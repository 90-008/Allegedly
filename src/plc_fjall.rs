use crate::{
    Dt, InvalidOp, Op as CommonOp,
    crypto::{AssuranceResults, DidKey, Signature, assure_valid_sig},
};
use anyhow::Context;
use data_encoding::BASE32_NOPAD;
use fjall::{Database, Keyspace, KeyspaceCreateOptions, PersistMode, config::BlockSizePolicy};
use ordered_varint::Variable;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Notify, futures::Notified, mpsc, oneshot};

const SEP: u8 = 0;

fn seq_key(seq: u64) -> Vec<u8> {
    seq.to_variable_vec().expect("that seq number encodes")
}

fn decode_seq_key(key: &[u8]) -> anyhow::Result<u64> {
    u64::decode_variable(key).context("failed to decode seq key")
}

type IpldCid = cid::CidGeneric<64>;

// 24 bytes -> 15 bytes
fn encode_did(buf: &mut Vec<u8>, did: &str) -> anyhow::Result<usize> {
    let input = did.trim_start_matches("did:plc:").to_uppercase();
    let len = BASE32_NOPAD
        .decode_len(input.len())
        .map_err(|_| anyhow::anyhow!("failed to calculate decode len for {did}"))?;

    let start = buf.len();
    buf.resize(start + len, 0);

    BASE32_NOPAD
        .decode_mut(input.as_bytes(), &mut buf[start..])
        .map_err(|_| anyhow::anyhow!("failed to encode did {did}"))
}

// 59 bytes -> 36 bytes
fn decode_cid_str(s: &str) -> anyhow::Result<Vec<u8>> {
    let cid = IpldCid::try_from(s)?;
    let mut buf = Vec::new();
    cid.write_bytes(&mut buf)
        .map_err(|e| anyhow::anyhow!("failed to encode cid {s}: {e}"))?;
    Ok(buf)
}

fn decode_cid(bytes: &[u8]) -> anyhow::Result<String> {
    IpldCid::try_from(bytes)
        .map_err(|e| anyhow::anyhow!("failed to decode cid: {e}"))
        .map(|cid| cid.to_string())
}

fn decode_did(bytes: &[u8]) -> String {
    let decoded = BASE32_NOPAD.encode(bytes).to_lowercase();
    format!("did:plc:{decoded}")
}

fn by_did_prefix(did: &str) -> anyhow::Result<Vec<u8>> {
    let mut p = Vec::with_capacity(BASE32_NOPAD.decode_len(did.len())? + 1);
    encode_did(&mut p, did)?;
    p.push(SEP);
    Ok(p)
}

/// by_did key: [15 bytes encoded did][SEP][seq varint]
fn by_did_key(did: &str, seq: u64) -> anyhow::Result<Vec<u8>> {
    let mut key = by_did_prefix(did)?;
    seq.encode_variable(&mut key)?;
    Ok(key)
}

/// CID string → binary CID bytes
// STABILITY: never reorder variants, only append.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, bitcode::Encode, bitcode::Decode)]
struct PlcCid(#[serde(with = "serde_bytes")] Vec<u8>);

impl PlcCid {
    fn from_cid_str(s: &str) -> anyhow::Result<Self> {
        let cid = IpldCid::try_from(s)?;
        let mut buf = Vec::new();
        cid.write_bytes(&mut buf)
            .map_err(|e| anyhow::anyhow!("failed to encode cid {s}: {e}"))?;
        Ok(Self(buf))
    }
}

impl fmt::Display for PlcCid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cid = IpldCid::try_from(self.0.as_slice()).map_err(|_| fmt::Error)?;
        write!(f, "{cid}")
    }
}

// STABILITY: never reorder variants, only append.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, bitcode::Encode, bitcode::Decode)]
enum Aka {
    Other(String),   // 0
    Bluesky(String), // 1
    Atproto(String), // 2
}

impl Aka {
    fn from_str(s: &str) -> Self {
        if let Some(stripped) = s.strip_prefix("at://") {
            if let Some(handle) = stripped.strip_suffix(".bsky.social") {
                Self::Bluesky(handle.to_string())
            } else {
                Self::Atproto(stripped.to_string())
            }
        } else {
            Self::Other(s.to_string())
        }
    }
}

impl fmt::Display for Aka {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bluesky(h) => write!(f, "at://{h}.bsky.social"),
            Self::Atproto(h) => write!(f, "at://{h}"),
            Self::Other(s) => f.write_str(s),
        }
    }
}

// STABILITY: never reorder variants, only append.
#[derive(Debug, Clone, Serialize, Deserialize, bitcode::Encode, bitcode::Decode)]
#[serde(rename_all = "snake_case")]
enum OpType {
    Other(String), // 0
    PlcOperation,  // 1
    Create,        // 2
    PlcTombstone,  // 3
}

impl OpType {
    fn from_str(s: &str) -> Self {
        match s {
            "plc_operation" => Self::PlcOperation,
            "create" => Self::Create,
            "plc_tombstone" => Self::PlcTombstone,
            other => Self::Other(other.to_string()),
        }
    }

    fn as_str(&self) -> &str {
        match self {
            Self::PlcOperation => "plc_operation",
            Self::Create => "create",
            Self::PlcTombstone => "plc_tombstone",
            Self::Other(s) => s,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoredOpField {
    Type,
    Sig,
    Prev,
    RotationKeys,
    VerificationMethods,
    AlsoKnownAs,
    Services,
    SigningKey,
    RecoveryKey,
    Handle,
    Service,
}

impl StoredOpField {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Type => "type",
            Self::Sig => "sig",
            Self::Prev => "prev",
            Self::RotationKeys => "rotationKeys",
            Self::VerificationMethods => "verificationMethods",
            Self::AlsoKnownAs => "alsoKnownAs",
            Self::Services => "services",
            Self::SigningKey => "signingKey",
            Self::RecoveryKey => "recoveryKey",
            Self::Handle => "handle",
            Self::Service => "service",
        }
    }
}

impl AsRef<str> for StoredOpField {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl std::ops::Deref for StoredOpField {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl fmt::Display for StoredOpField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, thiserror::Error)]
enum StoredOpError {
    #[error("operation is not an object")]
    NotAnObject,
    #[error("missing required field: {0}")]
    MissingField(StoredOpField),
    #[error("invalid field {0}: {1}")]
    InvalidField(StoredOpField, #[source] anyhow::Error),
    #[error("type mismatch for field {0}: expected {1}")]
    TypeMismatch(StoredOpField, &'static str),
}

// STABILITY: never reorder variants, only append.
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    bitcode::Encode,
    bitcode::Decode,
)]
enum VerificationMethodKey {
    Other(String), // 0
    Atproto,       // 1
}

impl VerificationMethodKey {
    fn from_str(s: &str) -> Self {
        match s {
            "atproto" => Self::Atproto,
            _ => Self::Other(s.to_string()),
        }
    }

    fn as_str(&self) -> &str {
        match self {
            Self::Atproto => "atproto",
            Self::Other(s) => s,
        }
    }
}

impl fmt::Display for VerificationMethodKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// STABILITY: never reorder variants, only append.
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    bitcode::Encode,
    bitcode::Decode,
)]
enum ServiceKey {
    Other(String), // 0
    AtprotoPds,    // 1
}

impl ServiceKey {
    fn from_str(s: &str) -> Self {
        match s {
            "atproto_pds" => Self::AtprotoPds,
            _ => Self::Other(s.to_string()),
        }
    }

    fn as_str(&self) -> &str {
        match self {
            Self::AtprotoPds => "atproto_pds",
            Self::Other(s) => s,
        }
    }
}

impl fmt::Display for ServiceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// STABILITY: never reorder variants, only append.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, bitcode::Encode, bitcode::Decode)]
enum ServiceType {
    Other(String),             // 0
    AtprotoPersonalDataServer, // 1
}

impl ServiceType {
    fn from_str(s: &str) -> Self {
        match s {
            "AtprotoPersonalDataServer" => Self::AtprotoPersonalDataServer,
            _ => Self::Other(s.to_string()),
        }
    }

    fn as_str(&self) -> &str {
        match self {
            Self::AtprotoPersonalDataServer => "AtprotoPersonalDataServer",
            Self::Other(s) => s,
        }
    }
}

// STABILITY: never reorder variants, only append.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, bitcode::Encode, bitcode::Decode)]
enum ServiceEndpoint {
    Other(String),      // 0
    BlueskyPds(String), // 1
    BlueskySocial,      // 2
}

impl ServiceEndpoint {
    fn from_str(s: &str) -> Self {
        if let Some(host) = s
            .strip_prefix("https://")
            .and_then(|h| h.strip_suffix(".host.bsky.network"))
        {
            Self::BlueskyPds(host.to_string())
        } else if s == "https://bsky.social" {
            Self::BlueskySocial
        } else {
            Self::Other(s.to_string())
        }
    }

    fn as_string(&self) -> String {
        match self {
            Self::BlueskyPds(h) => format!("https://{h}.host.bsky.network"),
            Self::BlueskySocial => "https://bsky.social".to_string(),
            Self::Other(s) => s.clone(),
        }
    }
}

// STABILITY: never reorder variants, only append.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, bitcode::Encode, bitcode::Decode)]
enum Handle {
    Other(String),    // 0
    BskySocial(String), // 1
}

impl Handle {
    fn from_str(s: &str) -> Self {
        if let Some(handle) = s.strip_suffix(".bsky.social") {
            Self::BskySocial(handle.to_string())
        } else {
            Self::Other(s.to_string())
        }
    }

    fn as_string(&self) -> String {
        match self {
            Self::BskySocial(h) => format!("{h}.bsky.social"),
            Self::Other(s) => s.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, bitcode::Encode, bitcode::Decode)]
struct StoredService {
    r#type: ServiceType,
    endpoint: ServiceEndpoint,
}

#[derive(Debug, Clone, Serialize, Deserialize, bitcode::Encode, bitcode::Decode)]
struct StoredOp {
    op_type: OpType,
    sig: Signature,
    prev: Option<PlcCid>,

    rotation_keys: Option<Vec<DidKey>>,
    verification_methods: Option<BTreeMap<VerificationMethodKey, DidKey>>,
    also_known_as: Option<Vec<Aka>>,
    services: Option<BTreeMap<ServiceKey, StoredService>>,

    // legacy create fields
    signing_key: Option<DidKey>,
    recovery_key: Option<DidKey>,
    handle: Option<Handle>,
    service: Option<ServiceEndpoint>,

    // msgpack-encoded BTreeMap<String, serde_json::Value>.
    // Vec<u8> is used because bitcode cannot handle serde_json::Value directly.
    // empty vec when there are no unknown fields (the common case).
    #[serde(skip)]
    unknown_packed: Vec<u8>,
}

impl StoredOp {
    fn get_keys(&self) -> Vec<&DidKey> {
        let mut keys = Vec::with_capacity(self.rotation_keys.as_ref().map_or(2, |keys| keys.len()));
        if let Some(rot_keys) = self.rotation_keys.as_ref() {
            keys.extend(rot_keys.iter());
        } else {
            // legacy genesis op
            if let Some(recovery_key) = self.recovery_key.as_ref() {
                keys.push(recovery_key);
            }
            if let Some(signing_key) = self.signing_key.as_ref() {
                keys.push(signing_key);
            }
        }
        keys
    }

    fn unknown(&self) -> BTreeMap<String, serde_json::Value> {
        if self.unknown_packed.is_empty() {
            return BTreeMap::new();
        }
        rmp_serde::from_slice(&self.unknown_packed).unwrap_or_default()
    }

    fn pack_unknown(unknown: BTreeMap<String, serde_json::Value>) -> Vec<u8> {
        if unknown.is_empty() {
            return Vec::new();
        }
        rmp_serde::to_vec(&unknown).expect("unknown fields are serializable")
    }
    fn from_json_value(v: serde_json::Value) -> (Option<Self>, Vec<StoredOpError>) {
        let serde_json::Value::Object(mut obj) = v else {
            return (None, vec![StoredOpError::NotAnObject]);
        };

        let mut errors = Vec::new();
        let mut unknown = BTreeMap::new();

        let op_type = match obj.remove(&*StoredOpField::Type) {
            Some(serde_json::Value::String(s)) => OpType::from_str(&s),
            Some(v) => {
                errors.push(StoredOpError::TypeMismatch(StoredOpField::Type, "string"));
                unknown.insert(StoredOpField::Type.to_string(), v);
                OpType::Other(String::new())
            }
            Option::None => {
                errors.push(StoredOpError::MissingField(StoredOpField::Type));
                OpType::Other(String::new())
            }
        };

        let sig = match obj.remove(&*StoredOpField::Sig) {
            Some(serde_json::Value::String(s)) => match Signature::from_base64url(&s) {
                Ok(sig) => sig,
                Err(e) => {
                    errors.push(StoredOpError::InvalidField(StoredOpField::Sig, e));
                    unknown.insert(StoredOpField::Sig.to_string(), serde_json::Value::String(s));
                    Signature(Vec::new())
                }
            },
            Some(v) => {
                errors.push(StoredOpError::TypeMismatch(StoredOpField::Sig, "string"));
                unknown.insert(StoredOpField::Sig.to_string(), v);
                Signature(Vec::new())
            }
            Option::None => {
                errors.push(StoredOpError::MissingField(StoredOpField::Sig));
                Signature(Vec::new())
            }
        };

        let prev = match obj.remove(&*StoredOpField::Prev) {
            Some(serde_json::Value::Null) | Option::None => Option::None,
            Some(serde_json::Value::String(s)) => match PlcCid::from_cid_str(&s) {
                Ok(p) => Some(p),
                Err(e) => {
                    errors.push(StoredOpError::InvalidField(StoredOpField::Prev, e));
                    unknown.insert(
                        StoredOpField::Prev.to_string(),
                        serde_json::Value::String(s),
                    );
                    Option::None
                }
            },
            Some(v) => {
                errors.push(StoredOpError::TypeMismatch(StoredOpField::Prev, "string"));
                unknown.insert(StoredOpField::Prev.to_string(), v);
                Option::None
            }
        };

        let rotation_keys = match obj.remove(&*StoredOpField::RotationKeys) {
            Some(serde_json::Value::Array(arr)) => {
                let mut keys = Vec::with_capacity(arr.len());
                let mut failed = false;
                for v in &arr {
                    match v {
                        serde_json::Value::String(s) => match DidKey::from_did_key(s) {
                            Ok(k) => keys.push(k),
                            Err(e) => {
                                errors.push(StoredOpError::InvalidField(
                                    StoredOpField::RotationKeys,
                                    e,
                                ));
                                failed = true;
                                break;
                            }
                        },
                        _ => {
                            errors.push(StoredOpError::TypeMismatch(
                                StoredOpField::RotationKeys,
                                "string inside array",
                            ));
                            failed = true;
                            break;
                        }
                    }
                }
                if failed {
                    unknown.insert(
                        StoredOpField::RotationKeys.to_string(),
                        serde_json::Value::Array(arr),
                    );
                    Option::None
                } else {
                    Some(keys)
                }
            }
            Some(v) => {
                errors.push(StoredOpError::TypeMismatch(
                    StoredOpField::RotationKeys,
                    "array",
                ));
                unknown.insert(StoredOpField::RotationKeys.to_string(), v);
                Option::None
            }
            Option::None => Option::None,
        };

        let verification_methods = match obj.remove(&*StoredOpField::VerificationMethods) {
            Some(serde_json::Value::Object(map)) => {
                let mut methods = BTreeMap::new();
                let mut failed = false;
                for (k, v) in &map {
                    match v {
                        serde_json::Value::String(s) => match DidKey::from_did_key(s) {
                            Ok(key) => {
                                methods.insert(VerificationMethodKey::from_str(k), key);
                            }
                            Err(e) => {
                                errors.push(StoredOpError::InvalidField(
                                    StoredOpField::VerificationMethods,
                                    e,
                                ));
                                failed = true;
                                break;
                            }
                        },
                        _ => {
                            errors.push(StoredOpError::TypeMismatch(
                                StoredOpField::VerificationMethods,
                                "string value in object",
                            ));
                            failed = true;
                            break;
                        }
                    }
                }
                if failed {
                    unknown.insert(
                        StoredOpField::VerificationMethods.to_string(),
                        serde_json::Value::Object(map),
                    );
                    Option::None
                } else {
                    Some(methods)
                }
            }
            Some(v) => {
                errors.push(StoredOpError::TypeMismatch(
                    StoredOpField::VerificationMethods,
                    "object",
                ));
                unknown.insert(StoredOpField::VerificationMethods.to_string(), v);
                Option::None
            }
            Option::None => Option::None,
        };

        let also_known_as = match obj.remove(&*StoredOpField::AlsoKnownAs) {
            Some(serde_json::Value::Array(arr)) => {
                let mut akas = Vec::with_capacity(arr.len());
                let mut failed = false;
                for v in &arr {
                    match v {
                        serde_json::Value::String(s) => akas.push(Aka::from_str(s)),
                        _ => {
                            errors.push(StoredOpError::TypeMismatch(
                                StoredOpField::AlsoKnownAs,
                                "string inside array",
                            ));
                            failed = true;
                            break;
                        }
                    }
                }
                if failed {
                    unknown.insert(
                        StoredOpField::AlsoKnownAs.to_string(),
                        serde_json::Value::Array(arr),
                    );
                    Option::None
                } else {
                    Some(akas)
                }
            }
            Some(v) => {
                errors.push(StoredOpError::TypeMismatch(
                    StoredOpField::AlsoKnownAs,
                    "array",
                ));
                unknown.insert(StoredOpField::AlsoKnownAs.to_string(), v);
                Option::None
            }
            Option::None => Option::None,
        };

        let services = match obj.remove(&*StoredOpField::Services) {
            Some(serde_json::Value::Object(map)) => {
                let mut svcs = BTreeMap::new();
                let mut failed = false;
                for (k, v) in &map {
                    if let (Some(r#type), Some(endpoint)) = (
                        v.get("type").and_then(|t| t.as_str()),
                        v.get("endpoint").and_then(|e| e.as_str()),
                    ) {
                        let svc = StoredService {
                            r#type: ServiceType::from_str(r#type),
                            endpoint: ServiceEndpoint::from_str(endpoint),
                        };
                        svcs.insert(ServiceKey::from_str(k), svc);
                    } else {
                        errors.push(StoredOpError::TypeMismatch(
                            StoredOpField::Services,
                            "missing or invalid type/endpoint in service object",
                        ));
                        failed = true;
                        break;
                    }
                }
                if failed {
                    unknown.insert(
                        StoredOpField::Services.to_string(),
                        serde_json::Value::Object(map),
                    );
                    Option::None
                } else {
                    Some(svcs)
                }
            }
            Some(v) => {
                errors.push(StoredOpError::TypeMismatch(
                    StoredOpField::Services,
                    "object",
                ));
                unknown.insert(StoredOpField::Services.to_string(), v);
                Option::None
            }
            Option::None => Option::None,
        };

        let signing_key = match obj.remove(&*StoredOpField::SigningKey) {
            Some(serde_json::Value::String(s)) => match DidKey::from_did_key(&s) {
                Ok(key) => Some(key),
                Err(e) => {
                    errors.push(StoredOpError::InvalidField(StoredOpField::SigningKey, e));
                    unknown.insert(
                        StoredOpField::SigningKey.to_string(),
                        serde_json::Value::String(s),
                    );
                    Option::None
                }
            },
            Some(v) => {
                errors.push(StoredOpError::TypeMismatch(
                    StoredOpField::SigningKey,
                    "string",
                ));
                unknown.insert(StoredOpField::SigningKey.to_string(), v);
                Option::None
            }
            Option::None => Option::None,
        };

        let recovery_key = match obj.remove(&*StoredOpField::RecoveryKey) {
            Some(serde_json::Value::String(s)) => match DidKey::from_did_key(&s) {
                Ok(key) => Some(key),
                Err(e) => {
                    errors.push(StoredOpError::InvalidField(StoredOpField::RecoveryKey, e));
                    unknown.insert(
                        StoredOpField::RecoveryKey.to_string(),
                        serde_json::Value::String(s),
                    );
                    Option::None
                }
            },
            Some(v) => {
                errors.push(StoredOpError::TypeMismatch(
                    StoredOpField::RecoveryKey,
                    "string",
                ));
                unknown.insert(StoredOpField::RecoveryKey.to_string(), v);
                Option::None
            }
            Option::None => Option::None,
        };

        let handle = match obj.remove(&*StoredOpField::Handle) {
            Some(serde_json::Value::String(s)) => Some(Handle::from_str(&s)),
            Some(v) => {
                errors.push(StoredOpError::TypeMismatch(StoredOpField::Handle, "string"));
                unknown.insert(StoredOpField::Handle.to_string(), v);
                Option::None
            }
            Option::None => Option::None,
        };

        let service = match obj.remove(&*StoredOpField::Service) {
            Some(serde_json::Value::String(s)) => Some(ServiceEndpoint::from_str(&s)),
            Some(v) => {
                errors.push(StoredOpError::TypeMismatch(
                    StoredOpField::Service,
                    "string",
                ));
                unknown.insert(StoredOpField::Service.to_string(), v);
                Option::None
            }
            Option::None => Option::None,
        };

        for (k, v) in obj {
            unknown.insert(k, v);
        }

        (
            Some(Self {
                op_type,
                sig,
                prev,
                rotation_keys,
                verification_methods,
                also_known_as,
                services,
                signing_key,
                recovery_key,
                handle,
                service,
                unknown_packed: Self::pack_unknown(unknown),
            }),
            errors,
        )
    }

    fn to_json_value(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();

        map.insert((*StoredOpField::Type).into(), self.op_type.as_str().into());
        map.insert((*StoredOpField::Sig).into(), self.sig.to_string().into());
        map.insert(
            (*StoredOpField::Prev).into(),
            self.prev
                .as_ref()
                .map(|c| serde_json::Value::String(c.to_string()))
                .unwrap_or(serde_json::Value::Null),
        );

        if let Some(keys) = &self.rotation_keys {
            map.insert(
                (*StoredOpField::RotationKeys).into(),
                keys.iter()
                    .map(|k| serde_json::Value::String(k.to_string()))
                    .collect::<Vec<_>>()
                    .into(),
            );
        }

        if let Some(methods) = &self.verification_methods {
            let obj: serde_json::Map<String, serde_json::Value> = methods
                .iter()
                .map(|(k, v)| {
                    (
                        k.as_str().to_string(),
                        serde_json::Value::String(v.to_string()),
                    )
                })
                .collect();
            map.insert((*StoredOpField::VerificationMethods).into(), obj.into());
        }

        if let Some(aka) = &self.also_known_as {
            map.insert(
                (*StoredOpField::AlsoKnownAs).into(),
                aka.iter()
                    .map(|h| serde_json::Value::String(h.to_string()))
                    .collect::<Vec<_>>()
                    .into(),
            );
        }

        if let Some(services) = &self.services {
            let obj: serde_json::Map<String, serde_json::Value> = services
                .iter()
                .map(|(k, svc)| {
                    (
                        k.as_str().to_string(),
                        serde_json::json!({
                            "type": svc.r#type.as_str(),
                            "endpoint": svc.endpoint.as_string(),
                        }),
                    )
                })
                .collect();
            map.insert((*StoredOpField::Services).into(), obj.into());
        }

        // legacy create fields
        if let Some(key) = &self.signing_key {
            map.insert((*StoredOpField::SigningKey).into(), key.to_string().into());
        }
        if let Some(key) = &self.recovery_key {
            map.insert((*StoredOpField::RecoveryKey).into(), key.to_string().into());
        }
        if let Some(handle) = &self.handle {
            map.insert((*StoredOpField::Handle).into(), handle.as_string().into());
        }
        if let Some(service) = &self.service {
            map.insert((*StoredOpField::Service).into(), service.as_string().into());
        }

        for (k, v) in self.unknown() {
            map.insert(k, v);
        }

        serde_json::Value::Object(map)
    }
}

fn verify_op_sig(op: &StoredOp, prev: Option<&StoredOp>) -> anyhow::Result<AssuranceResults> {
    let keys: Vec<&DidKey> = match &op.prev {
        None => op.get_keys(),
        Some(_) => match prev {
            None => anyhow::bail!("prev cid exists but the op for that cid is missing"),
            Some(p) => p.get_keys(),
        },
    };

    if keys.is_empty() {
        anyhow::bail!("no keys found for genesis op or prev op");
    }

    let data = {
        let serde_json::Value::Object(mut data) = op.to_json_value() else {
            unreachable!("we know op is valid, because it comes from StoredOp")
        };
        data.remove("sig");
        serde_json::Value::Object(data)
    };

    let results = assure_valid_sig(keys, &op.sig, &data)
        .expect("that our op is an object and we removed sig field");
    Ok(results)
}

// stored alongside the seq key in the ops keyspace
// cid and created_at are in the value (not the key) in the new layout
#[derive(Debug, Deserialize, Serialize, bitcode::Encode, bitcode::Decode)]
#[serde(rename_all = "camelCase")]
struct DbOp {
    #[serde(with = "serde_bytes")]
    pub did: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub cid: Vec<u8>,
    pub created_at: u64,
    pub nullified: bool,
    pub operation: StoredOp,
}

// we have our own Op struct for fjall since we dont want to have to convert Value back to RawValue
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Op {
    pub seq: u64,
    pub did: String,
    pub cid: String,
    #[serde(rename = "createdAt")]
    pub created_at: Dt,
    pub nullified: bool,
    pub operation: serde_json::Value,
}

impl Op {
    // todo: we should probably just have this in Op tbh as a `r#type: SequencedOpType` or something
    /// adds the `type` field to the op
    pub fn to_sequenced_json(&self) -> serde_json::Value {
        let mut val = serde_json::to_value(self).expect("Op is serializable");
        if let serde_json::Value::Object(ref mut map) = val {
            map.insert("type".to_string(), "sequenced_op".into());
        }
        val
    }
}

#[derive(Clone)]
pub struct FjallDb {
    inner: Arc<FjallInner>,
}

struct FjallInner {
    db: Database,
    /// primary keyspace: seq (varint) -> DbOp
    ops: Keyspace,
    /// secondary index: [encoded_did][SEP][seq_varint] -> []
    by_did: Keyspace,
    notify_stream: Notify,
}

impl FjallDb {
    pub fn open(path: impl AsRef<Path>) -> fjall::Result<Self> {
        const fn kb(kb: u32) -> u32 {
            kb * 1_024
        }
        const fn mb(mb: u32) -> u64 {
            kb(mb) as u64 * 1_024
        }

        let db = Database::builder(path)
            // 32mb is too low we can afford more
            // this should be configurable though!
            .cache_size(mb(256))
            .manual_journal_persist(true)
            .open()?;
        let opts = KeyspaceCreateOptions::default;
        let ops = db.keyspace("ops", || {
            opts()
                // this is mainly for when backfilling
                .max_memtable_size(mb(192))
                // this wont compress terribly well since its a bunch of CIDs and signatures and did:keys
                // and we want to keep reads fast since we'll be reading a lot...
                .data_block_size_policy(BlockSizePolicy::new([kb(4), kb(8), kb(32)]))
                // this has no downsides, since the only point reads that might miss we do is on by_did
                .expect_point_read_hits(true)
        })?;
        let by_did = db.keyspace("by_did", || {
            opts()
                .max_memtable_size(mb(64))
                // this isn't gonna compress well anyway, since its just keys (did + seq)
                // and dids dont have many operations in the first place, so we can use small blocks
                .data_block_size_policy(BlockSizePolicy::all(kb(2)))
        })?;
        Ok(Self {
            inner: Arc::new(FjallInner {
                db,
                ops,
                by_did,
                notify_stream: Notify::new(),
            }),
        })
    }

    pub fn clear(&self) -> fjall::Result<()> {
        self.inner.ops.clear()?;
        self.inner.by_did.clear()?;
        Ok(())
    }

    pub fn persist(&self, mode: PersistMode) -> fjall::Result<()> {
        self.inner.db.persist(mode)
    }

    pub fn compact(&self) -> fjall::Result<()> {
        self.inner.ops.major_compact()?;
        self.inner.by_did.major_compact()?;
        Ok(())
    }

    pub fn subscribe(&self) -> Notified<'_> {
        self.inner.notify_stream.notified()
    }

    /// Returns `(seq, created_at)` for the last stored op, or `None` if empty.
    pub fn get_latest(&self) -> anyhow::Result<Option<(u64, Dt)>> {
        let Some(guard) = self.inner.ops.last_key_value() else {
            return Ok(None);
        };
        let (key, value) = guard
            .into_inner()
            .map_err(|e| anyhow::anyhow!("fjall read error: {e}"))?;
        let seq = decode_seq_key(&key)?;
        let db_op: DbOp = bitcode::decode::<DbOp>(&value)?;
        let dt = Dt::from_timestamp_micros(db_op.created_at as i64)
            .ok_or_else(|| anyhow::anyhow!("invalid created_at in last op"))?;
        Ok(Some((seq, dt)))
    }

    pub fn insert_op<const VERIFY: bool>(&self, op: &CommonOp, seq: u64) -> anyhow::Result<usize> {
        let cid_bytes = decode_cid_str(&op.cid)?;

        let op_json: serde_json::Value = serde_json::from_str(op.operation.get())?;
        let (stored, mut errors) = StoredOp::from_json_value(op_json);

        let Some(operation) = stored else {
            return Err(errors.remove(0)).context("fatal operation parse error");
        };

        for err in &errors {
            log::warn!("failed to parse operation {} {}: {err}", op.did, op.cid);
        }
        if !errors.is_empty() {
            // if parse failed but not fatal, we just dont store it
            return Ok(0);
        }

        if VERIFY {
            let prev_op = operation
                .prev
                .as_ref()
                .map(|prev_cid| {
                    // TODO: we should have a cid -> seq lookup eventually maybe?
                    // this is probably fine though we will only iter over like 2 ops at most
                    // or so, its there to handle nullified...
                    // but a cid lookup would also help us avoid duplicate ops!
                    self._ops_for_did(&op.did)
                        .map(|ops| {
                            ops.rev()
                                .find(|r| r.as_ref().map_or(true, |(_, _, cid, _)| cid == prev_cid))
                                .transpose()
                        })
                        .flatten()
                })
                .transpose()?
                .flatten();

            let prev_stored = prev_op.as_ref().map(|(_, _, _, p)| &p.operation);

            match verify_op_sig(&operation, prev_stored) {
                Ok(results) => {
                    if !results.valid {
                        let msg = results
                            .errors
                            .iter()
                            .map(|e| e.to_string())
                            .collect::<Vec<_>>()
                            .join("\n");
                        log::warn!("invalid op {} {}:\n{msg}", op.did, op.cid);
                        return Ok(0);
                    }
                }
                Err(e) => {
                    log::warn!("invalid op {} {}: {e}", op.did, op.cid);
                    return Ok(0);
                }
            }
            log::debug!("verified op {} {}", op.did, op.cid);
        }

        let db_op = DbOp {
            did: {
                let mut encoded_did = Vec::with_capacity(15);
                encode_did(&mut encoded_did, &op.did)?;
                encoded_did
            },
            cid: cid_bytes,
            created_at: op.created_at.timestamp_micros() as u64,
            nullified: op.nullified,
            operation,
        };

        let seq_val = bitcode::encode(&db_op);
        let seq_key_bytes = seq_key(seq);
        let by_did_key_bytes = by_did_key(&op.did, seq)?;

        let mut batch = self.inner.db.batch();
        batch.insert(&self.inner.ops, seq_key_bytes, seq_val);
        batch.insert(&self.inner.by_did, by_did_key_bytes, &[]);
        batch.commit()?;

        self.inner.notify_stream.notify_waiters();

        Ok(1)
    }

    pub(crate) fn get_op_at_or_after(&self, seq: u64) -> anyhow::Result<Option<Op>> {
        self.inner
            .ops
            .range(seq_key(seq)..)
            .next()
            .map(|v| {
                bitcode::decode::<DbOp>(&v.value()?)
                    .context("failed to decode op")
                    .map(|op| {
                        Ok(Op {
                            seq,
                            did: decode_did(&op.did),
                            cid: decode_cid(&op.cid)?,
                            created_at: Dt::from_timestamp_micros(op.created_at as i64)
                                .ok_or_else(|| anyhow::anyhow!("invalid created_at in op"))?,
                            nullified: op.nullified,
                            operation: op.operation.to_json_value(),
                        })
                    })
                    .flatten()
            })
            .transpose()
    }

    /// Decode a `by_did` entry: extract the seq from the key suffix, then
    /// look up the full `DbOp` in the `ops` keyspace.
    fn decode_by_did_entry(
        &self,
        by_did_key_bytes: &[u8],
        prefix_len: usize,
    ) -> anyhow::Result<(u64, Dt, PlcCid, DbOp)> {
        let key_suffix = by_did_key_bytes
            .get(prefix_len..)
            .ok_or_else(|| anyhow::anyhow!("invalid by_did key {by_did_key_bytes:?}"))?;

        let seq =
            u64::decode_variable(key_suffix).context("failed to decode seq from by_did key")?;

        let value = self
            .inner
            .ops
            .get(seq_key(seq))?
            .ok_or_else(|| anyhow::anyhow!("op not found for seq {seq}"))?;

        let op: DbOp = bitcode::decode::<DbOp>(&value)?;
        let ts = Dt::from_timestamp_micros(op.created_at as i64)
            .ok_or_else(|| anyhow::anyhow!("invalid created_at_micros {}", op.created_at))?;
        let cid = PlcCid(op.cid.clone());

        Ok((seq, ts, cid, op))
    }

    fn _ops_for_did(
        &self,
        did: &str,
    ) -> anyhow::Result<impl DoubleEndedIterator<Item = anyhow::Result<(u64, Dt, PlcCid, DbOp)>> + '_>
    {
        let prefix = by_did_prefix(did)?;

        Ok(self.inner.by_did.prefix(&prefix).map(move |guard| {
            let (by_did_key, _) = guard
                .into_inner()
                .map_err(|e| anyhow::anyhow!("fjall read error: {e}"))?;
            self.decode_by_did_entry(&by_did_key, prefix.len())
        }))
    }

    pub fn ops_for_did(
        &self,
        did: &str,
    ) -> anyhow::Result<impl DoubleEndedIterator<Item = anyhow::Result<Op>> + '_> {
        Ok(self._ops_for_did(did)?.map(|res| {
            let (seq, ts, cid, op) = res?;
            let cid = decode_cid(&cid.0)?;
            let did = decode_did(&op.did);
            Ok(Op {
                seq,
                did,
                cid,
                created_at: ts,
                nullified: op.nullified,
                operation: op.operation.to_json_value(),
            })
        }))
    }

    pub fn export_ops(
        &self,
        range: impl std::ops::RangeBounds<u64>,
    ) -> anyhow::Result<impl Iterator<Item = anyhow::Result<Op>> + '_> {
        use std::ops::Bound;
        let map_bound = |b: Bound<&u64>| -> Bound<Vec<u8>> {
            match b {
                Bound::Included(seq) => Bound::Included(seq_key(*seq)),
                Bound::Excluded(seq) => Bound::Excluded(seq_key(*seq)),
                Bound::Unbounded => Bound::Unbounded,
            }
        };
        let range = (map_bound(range.start_bound()), map_bound(range.end_bound()));

        Ok(self
            .inner
            .ops
            .range(range)
            .map(|item| -> anyhow::Result<Op> {
                let (key, value) = item
                    .into_inner()
                    .map_err(|e: fjall::Error| anyhow::anyhow!("fjall read error: {e}"))?;
                let seq = decode_seq_key(&key)?;
                let db_op: DbOp = bitcode::decode::<DbOp>(&value)?;
                let created_at =
                    Dt::from_timestamp_micros(db_op.created_at as i64).ok_or_else(|| {
                        anyhow::anyhow!("invalid created_at_micros {}", db_op.created_at)
                    })?;
                let cid = decode_cid(&db_op.cid)?;
                let did = decode_did(&db_op.did);
                Ok(Op {
                    seq,
                    did,
                    cid,
                    created_at,
                    nullified: db_op.nullified,
                    operation: db_op.operation.to_json_value(),
                })
            }))
    }

    pub fn drop_op(&self, did_str: &str, _created_at: &Dt, _cid: &str) -> anyhow::Result<()> {
        // scan the by_did index for this DID and find the op that matches
        // (in practice drop_op is rare so a scan is fine)
        let prefix = by_did_prefix(did_str)?;
        let mut found_seq: Option<u64> = None;
        let mut found_by_did_key: Option<Vec<u8>> = None;

        for guard in self.inner.by_did.prefix(&prefix) {
            let (key, _) = guard
                .into_inner()
                .map_err(|e| anyhow::anyhow!("fjall read error: {e}"))?;
            let suffix = &key[prefix.len()..];
            let seq = u64::decode_variable(suffix).context("decode seq in drop_op")?;
            found_seq = Some(seq);
            found_by_did_key = Some(key.to_vec());
            // if there were multiple ops for this DID we'd need to match by cid,
            // but for now take the last matched (they're in seq order)
        }

        let (seq, by_did_key_bytes) = match (found_seq, found_by_did_key) {
            (Some(s), Some(k)) => (s, k),
            _ => {
                log::warn!("drop_op: by_did entry not found for {did_str}");
                return Ok(());
            }
        };

        let mut batch = self.inner.db.batch();
        batch.remove(&self.inner.ops, seq_key(seq));
        batch.remove(&self.inner.by_did, by_did_key_bytes);
        batch.commit()?;

        Ok(())
    }

    pub fn audit(&self, invalid_ops_tx: mpsc::Sender<InvalidOp>) -> anyhow::Result<(usize, usize)> {
        use std::sync::mpsc;

        let ops = self.inner.by_did.len()?;

        let workers = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);

        type Batch = (Vec<u8>, Vec<(Dt, PlcCid, DbOp)>);
        let (result_tx, result_rx) = mpsc::sync_channel::<anyhow::Result<(usize, usize)>>(workers);

        let channels: Vec<_> = (0..workers)
            .map(|_| mpsc::sync_channel::<Batch>(512))
            .collect();
        let senders: Vec<_> = channels.iter().map(|(tx, _)| tx.clone()).collect();

        std::thread::scope(|s| {
            for (_, rx) in channels {
                let result_tx = result_tx.clone();
                let invalid_ops_tx = invalid_ops_tx.clone();
                s.spawn(move || {
                    let mut checked: usize = 0;
                    let mut failed: usize = 0;
                    while let Ok((did_prefix, ops)) = rx.recv() {
                        let did = decode_did(&did_prefix[..did_prefix.len() - 1]);
                        for (ts, cid, op) in &ops {
                            let send_invalid = || {
                                let _ = invalid_ops_tx.blocking_send(InvalidOp {
                                    did: did.clone(),
                                    at: ts.clone(),
                                    cid: cid.to_string(),
                                });
                            };
                            checked += 1;
                            let prev_op = op.operation.prev.as_ref().and_then(|expected| {
                                ops.iter().find(|(_, c, _)| c == expected)
                            });
                            let prev_cid_ok = op.operation.prev.is_none() || prev_op.is_some();
                            if !prev_cid_ok {
                                log::error!("audit: op {did} {cid} prev cid mismatch or missing predecessor, is db corrupted?");
                                failed += 1;
                                send_invalid();
                                continue;
                            }
                            let prev_stored = prev_op.map(|(_, _, p)| &p.operation);
                            match verify_op_sig(&op.operation, prev_stored) {
                                Ok(results) => {
                                    if !results.valid {
                                        let msg = results
                                            .errors
                                            .iter()
                                            .map(|e| e.to_string())
                                            .collect::<Vec<_>>()
                                            .join("\n    ");
                                        log::warn!("audit: invalid op {} {}:\n    {msg}", did, cid);
                                        failed += 1;
                                        send_invalid();
                                    }
                                }
                                Err(e) => {
                                    log::warn!("audit: invalid op {} {}: {e}", did, cid);
                                    failed += 1;
                                    send_invalid();
                                }
                            }
                        }
                    }
                    let _ = result_tx.send(Ok((checked, failed)));
                });
            }
            drop(result_tx);

            // todo: probably dont use a macro...
            macro_rules! spawn_scan_thread {
                ($iter_method:ident, $start_idx:expr, $reverse:expr, $limit:expr) => {{
                    let senders = senders.clone();
                    let mut iter = self.inner.by_did.iter();

                    s.spawn(move || -> anyhow::Result<()> {
                        let mut current_prefix: Option<[u8; 16]> = None;
                        let mut did_ops: Vec<(Dt, PlcCid, DbOp)> = Vec::new();
                        let mut idx = $start_idx;
                        let mut processed_ops: usize = 0;

                        while let Some(guard) = iter.$iter_method() {
                            let (by_did_key, _) = guard
                                .into_inner()
                                .map_err(|e| anyhow::anyhow!("fjall read error: {e}"))?;

                            let mut prefix_array = [0u8; 16];
                            prefix_array.copy_from_slice(by_did_key.get(..16).ok_or_else(
                                || anyhow::anyhow!("by_did key too short: {by_did_key:?}"),
                            )?);

                            let op = self.decode_by_did_entry(&by_did_key, 16)?;

                            if current_prefix.map_or(true, |cp| cp != prefix_array) {
                                // new did, push the ops
                                if let Some(prefix) = current_prefix.take() {
                                    if $reverse {
                                        did_ops.reverse();
                                    }
                                    senders[idx % workers]
                                        .send((prefix.to_vec(), std::mem::take(&mut did_ops)))
                                        .ok();
                                    idx += 1;

                                    if processed_ops >= $limit {
                                        break;
                                    }
                                }
                                current_prefix = Some(prefix_array);
                            }

                            did_ops.push((op.1, op.2, op.3));
                            processed_ops += 1;
                        }

                        if let Some(prefix) = current_prefix {
                            if $reverse {
                                did_ops.reverse();
                            }
                            senders[idx % workers].send((prefix.to_vec(), did_ops)).ok();
                        }

                        Ok(())
                    })
                }};
            }

            // we can start two threads, one for forward iteration and one for reverse iteration
            // this way we have two scans in parallel which should be faster!
            let f_count = ops / 2;
            let f_handle = spawn_scan_thread!(next, 0, false, f_count);
            let b_count = ops - f_count;
            let b_handle = spawn_scan_thread!(next_back, workers / 2, true, b_count);

            f_handle.join().unwrap()?;
            b_handle.join().unwrap()?;

            drop(senders);

            let mut total_checked: usize = 0;
            let mut total_failed: usize = 0;
            for res in result_rx {
                let (c, f) = res?;
                total_checked += c;
                total_failed += f;
            }

            Ok((total_checked, total_failed))
        })
    }
}

pub async fn backfill_to_fjall(
    db: FjallDb,
    reset: bool,
    mut pages: mpsc::Receiver<crate::SeqPage>,
    notify_last_at: Option<oneshot::Sender<Option<Dt>>>,
) -> anyhow::Result<&'static str> {
    let t0 = Instant::now();

    if reset {
        let db = db.clone();
        tokio::task::spawn_blocking(move || db.clear()).await??;
        log::warn!("fjall reset: cleared all data");
    }

    let mut last_at = None;
    let mut ops_inserted: usize = 0;
    let mut insert_tasks: tokio::task::JoinSet<anyhow::Result<usize>> = tokio::task::JoinSet::new();

    loop {
        let pages_finished = pages.is_closed();
        // we can stop if we have no more pages and all the insert tasks are finished
        if pages_finished && insert_tasks.is_empty() {
            break;
        }
        tokio::select! {
            page = pages.recv(), if !pages_finished => {
                let Some(page) = page else { continue; };
                if notify_last_at.is_some() {
                    // SeqPage ops are always in order, so we can just grab the last one
                    if let Some(last_op) = page.ops.last() {
                        last_at = last_at.filter(|&l| l >= last_op.created_at).or(Some(last_op.created_at));
                    }
                }

                let db = db.clone();

                // we don't have to wait for inserts to finish, because insert_op
                // without verification does not read anything from the db
                insert_tasks.spawn_blocking(move || {
                    let mut count: usize = 0;
                    for seq_op in &page.ops {
                        let op = CommonOp {
                            did: seq_op.did.clone(),
                            cid: seq_op.cid.clone(),
                            created_at: seq_op.created_at,
                            nullified: seq_op.nullified,
                            operation: seq_op.operation.clone(),
                        };
                        // we don't verify sigs for bulk, since pages might be out of order (and we trust for backfills)
                        count += db.insert_op::<false>(&op, seq_op.seq)?;
                    }
                    db.persist(PersistMode::Buffer)?;
                    Ok(count)
                });
            }
            Some(res) = insert_tasks.join_next() => {
                match res? {
                    Ok(count) => ops_inserted += count,
                    Err(e) => {
                        insert_tasks.abort_all();
                        return Err(e);
                    }
                }
            }
        }
    }
    log::debug!("finished receiving bulk pages");

    if let Some(notify) = notify_last_at {
        log::trace!("notifying last_at: {last_at:?}");
        if notify.send(last_at).is_err() {
            log::error!("receiver for last_at dropped, can't notify");
        };
    }

    tokio::task::spawn_blocking(move || db.persist(PersistMode::SyncAll)).await??;

    log::info!(
        "backfill_to_fjall: inserted {ops_inserted} ops in {:?}",
        t0.elapsed()
    );
    Ok("backfill_to_fjall")
}

/// Write sequenced ops (with PLC seq numbers) into fjall.
pub async fn seq_pages_to_fjall(
    db: FjallDb,
    mut pages: mpsc::Receiver<crate::SeqPage>,
) -> anyhow::Result<&'static str> {
    log::info!("starting seq_pages_to_fjall writer...");

    let t0 = Instant::now();
    let mut ops_inserted: usize = 0;

    while let Some(page) = pages.recv().await {
        log::trace!("writing seq page with {} ops", page.ops.len());
        let db = db.clone();
        let count = tokio::task::spawn_blocking(move || -> anyhow::Result<usize> {
            let mut count: usize = 0;
            for seq_op in &page.ops {
                let common_op = CommonOp {
                    did: seq_op.did.clone(),
                    cid: seq_op.cid.clone(),
                    created_at: seq_op.created_at,
                    nullified: seq_op.nullified,
                    operation: seq_op.operation.clone(),
                };
                count += db.insert_op::<true>(&common_op, seq_op.seq)?;
            }
            db.persist(PersistMode::Buffer)?;
            Ok(count)
        })
        .await??;
        ops_inserted += count;
    }

    log::info!(
        "no more seq pages. inserted {ops_inserted} ops in {:?}",
        t0.elapsed()
    );
    Ok("seq_pages_to_fjall")
}

pub async fn audit(
    db: FjallDb,
    invalid_ops_tx: mpsc::Sender<InvalidOp>,
) -> anyhow::Result<&'static str> {
    log::info!("starting fjall audit...");
    let t0 = std::time::Instant::now();
    let (checked, failed) = tokio::task::spawn_blocking(move || db.audit(invalid_ops_tx)).await??;
    log::info!(
        "fjall audit complete in {:?}, {checked} ops checked",
        t0.elapsed()
    );
    if failed > 0 {
        log::error!("audit found {failed} invalid operations");
    }
    Ok("audit_fjall")
}

pub async fn fix_ops(
    db: FjallDb,
    upstream: reqwest::Url,
    only_drop: bool,
    mut invalid_ops_rx: mpsc::Receiver<InvalidOp>,
) -> anyhow::Result<&'static str> {
    log::info!("starting fjall fix ops...");
    let mut fixed_dids = std::collections::HashSet::new();
    let mut count = 0;

    let latest_at = db
        .get_latest()?
        .ok_or_else(|| anyhow::anyhow!("db not backfilled? expected at least one op"))
        .map(|(_, dt)| dt)?;

    // local seq counter for newly fetched ops
    let mut next_seq = db.get_latest()?.map(|(s, _)| s).unwrap_or(0) + 1;

    while let Some(op) = invalid_ops_rx.recv().await {
        let InvalidOp { did, at, cid, .. } = op;

        if only_drop {
            db.drop_op(&did, &at, &cid)?;
            db.persist(PersistMode::Buffer)?;
            count += 1;
            continue;
        }

        if fixed_dids.contains(&did) {
            continue;
        }

        log::trace!("fetching upstream ops to fix did: {did}");
        let mut url = upstream.clone();
        url.set_path(&format!("/{did}/log/audit"));

        let resp = crate::CLIENT.get(url).send().await?;

        use reqwest::StatusCode;
        let ops: Vec<CommonOp> = match resp.status() {
            StatusCode::OK => match resp.json().await {
                Ok(ops) => ops,
                Err(e) => {
                    log::warn!("failed to parse upstream ops for {did}: {e}");
                    continue;
                }
            },
            StatusCode::NOT_FOUND => {
                log::trace!("did not found upstream: {did}");
                Vec::new() // this essentially means drop the whole did
            }
            s => {
                log::warn!("failed to fetch upstream for {did}: {s}");
                continue;
            }
        };

        log::trace!("fetched {} ops for {did}", ops.len());

        // we drop all ops first just to be safe
        let existing = db.ops_for_did(&did)?;
        for op in existing {
            let op = op?;
            db.drop_op(&did, &op.created_at, &op.cid)?;
        }

        // then insert the fresh ops
        for op in ops {
            // skip newer ops, since we will fill them in later anyway
            // if we don't skip these we might miss some ops in between
            // the latest_at we started with vs the one we ended up with
            if op.created_at > latest_at {
                log::trace!(
                    "skipping op {} for {did} because it is newer than latest_at {latest_at}",
                    op.cid
                );
                continue;
            }

            let seq = next_seq;
            next_seq += 1;
            count += db.insert_op::<true>(&op, seq)?;
        }

        db.persist(PersistMode::Buffer)?;
        fixed_dids.insert(did);
    }

    log::info!("fixed {count} ops");

    Ok("fix_ops_fjall")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plc_cid_roundtrip() {
        let original = "bafyreigp6shzy6dlcxuowwoxz7u5nemdrkad2my5zwzpwilcnhih7bw6zm";
        let cid = PlcCid::from_cid_str(original).unwrap();
        assert_eq!(cid.to_string(), original);
    }

    #[test]
    fn bsky_aka_roundtrip() {
        let h = Aka::from_str("at://alice.bsky.social");
        assert_eq!(h, Aka::Bluesky("alice".to_string()));
        assert_eq!(h.to_string(), "at://alice.bsky.social");
    }

    #[test]
    fn atproto_aka_roundtrip() {
        let h = Aka::from_str("at://alice.example.com");
        assert_eq!(h, Aka::Atproto("alice.example.com".to_string()));
        assert_eq!(h.to_string(), "at://alice.example.com");
    }

    #[test]
    fn other_aka_roundtrip() {
        let h = Aka::from_str("https://something.else");
        assert_eq!(h, Aka::Other("https://something.else".to_string()));
        assert_eq!(h.to_string(), "https://something.else");
    }

    #[test]
    fn handle_bsky_social_roundtrip() {
        let h = Handle::from_str("alice.bsky.social");
        assert_eq!(h, Handle::BskySocial("alice".to_string()));
        assert_eq!(h.as_string(), "alice.bsky.social");
    }

    #[test]
    fn handle_other_roundtrip() {
        let h = Handle::from_str("user.example.com");
        assert_eq!(h, Handle::Other("user.example.com".to_string()));
        assert_eq!(h.as_string(), "user.example.com");
    }

    #[test]
    fn verification_method_key_roundtrip() {
        let k1 = VerificationMethodKey::from_str("atproto");
        assert_eq!(k1, VerificationMethodKey::Atproto);
        assert_eq!(k1.to_string(), "atproto");

        let k2 = VerificationMethodKey::from_str("other_key");
        assert_eq!(k2, VerificationMethodKey::Other("other_key".to_string()));
        assert_eq!(k2.to_string(), "other_key");
    }

    #[test]
    fn service_key_roundtrip() {
        let k1 = ServiceKey::from_str("atproto_pds");
        assert_eq!(k1, ServiceKey::AtprotoPds);
        assert_eq!(k1.to_string(), "atproto_pds");

        let k2 = ServiceKey::from_str("other_svc");
        assert_eq!(k2, ServiceKey::Other("other_svc".to_string()));
        assert_eq!(k2.to_string(), "other_svc");
    }

    #[test]
    fn service_type_roundtrip() {
        let t1 = ServiceType::from_str("AtprotoPersonalDataServer");
        assert_eq!(t1, ServiceType::AtprotoPersonalDataServer);
        assert_eq!(t1.as_str(), "AtprotoPersonalDataServer");

        let t2 = ServiceType::from_str("OtherType");
        assert_eq!(t2, ServiceType::Other("OtherType".to_string()));
        assert_eq!(t2.as_str(), "OtherType");
    }

    #[test]
    fn service_endpoint_roundtrip() {
        let e1 = ServiceEndpoint::from_str("https://example.host.bsky.network");
        assert_eq!(e1, ServiceEndpoint::BlueskyPds("example".to_string()));
        assert_eq!(e1.as_string(), "https://example.host.bsky.network");

        let e2 = ServiceEndpoint::from_str("https://bsky.social");
        assert_eq!(e2, ServiceEndpoint::BlueskySocial);
        assert_eq!(e2.as_string(), "https://bsky.social");

        let e3 = ServiceEndpoint::from_str("https://other.endpoint.com");
        assert_eq!(
            e3,
            ServiceEndpoint::Other("https://other.endpoint.com".to_string())
        );
        assert_eq!(e3.as_string(), "https://other.endpoint.com");
    }

    #[test]
    fn op_type_roundtrip() {
        assert_eq!(OpType::from_str("plc_operation").as_str(), "plc_operation");
        assert_eq!(OpType::from_str("create").as_str(), "create");
        assert_eq!(OpType::from_str("plc_tombstone").as_str(), "plc_tombstone");
        assert_eq!(OpType::from_str("weird_thing").as_str(), "weird_thing");
    }

    #[test]
    fn stored_op_fixture_roundtrip() {
        let fixtures = [
            "tests/fixtures/log_bskyapp.json",
            "tests/fixtures/log_legacy_dholms.json",
            "tests/fixtures/log_nullification.json",
            "tests/fixtures/log_tombstone.json",
        ];

        let mut total_json_size = 0;
        let mut total_packed_size = 0;

        for path in fixtures {
            let data = std::fs::read_to_string(path).unwrap();
            let entries: Vec<serde_json::Value> = serde_json::from_str(&data).unwrap();

            for entry in &entries {
                let op = &entry["operation"];
                let (stored, errors) = StoredOp::from_json_value(op.clone());
                if !errors.is_empty() {
                    let mut msg = format!("failed to parse op in {path}:\n");
                    for e in errors {
                        msg.push_str(&format!("  - {e:?}\n"));
                    }
                    msg.push_str(&format!("op: {op}\n"));
                    panic!("{msg}");
                }
                let stored = stored.unwrap();

                let packed = bitcode::encode(&stored);
                let unpacked: StoredOp = bitcode::decode::<StoredOp>(&packed).unwrap();

                let reconstructed = unpacked.to_json_value();
                assert_eq!(*op, reconstructed, "roundtrip mismatch in {path}");

                total_json_size += serde_json::to_vec(op).unwrap().len();
                total_packed_size += packed.len();
            }
        }

        println!(
            "json size: {} bytes, bitcode size: {} bytes, saved: {} bytes",
            total_json_size,
            total_packed_size,
            total_json_size as isize - total_packed_size as isize
        );
    }
}
