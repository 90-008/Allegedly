use crate::{Dt, ExportPage, Op as CommonOp, PageBoundaryState};
use anyhow::Context;
use data_encoding::{BASE32_NOPAD, BASE64URL_NOPAD};
use fjall::{
    Database, Keyspace, KeyspaceCreateOptions, OwnedWriteBatch, PersistMode,
    config::BlockSizePolicy,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, oneshot};

const SEP: u8 = 0;

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

fn op_key(created_at: &Dt, cid_suffix: &[u8]) -> Vec<u8> {
    let micros = created_at.timestamp_micros() as u64;
    let mut key = Vec::with_capacity(8 + 1 + cid_suffix.len());
    key.extend_from_slice(&micros.to_be_bytes());
    key.push(SEP);
    key.extend_from_slice(cid_suffix);
    key
}

fn by_did_prefix(did: &str) -> anyhow::Result<Vec<u8>> {
    let mut p = Vec::with_capacity(BASE32_NOPAD.decode_len(did.len())? + 1);
    encode_did(&mut p, did)?;
    p.push(SEP);
    Ok(p)
}

fn by_did_key(did: &str, created_at: &Dt, cid_suffix: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut key = by_did_prefix(did)?;
    let micros = created_at.timestamp_micros() as u64;
    key.extend_from_slice(&micros.to_be_bytes());
    key.push(SEP);
    key.extend_from_slice(cid_suffix);
    Ok(key)
}

fn decode_timestamp(key: &[u8]) -> anyhow::Result<Dt> {
    let micros = u64::from_be_bytes(
        key.try_into()
            .map_err(|e| anyhow::anyhow!("invalid timestamp key {key:?}: {e}"))?,
    );
    Dt::from_timestamp_micros(micros as i64)
        .ok_or_else(|| anyhow::anyhow!("invalid timestamp {micros}"))
}

/// base64url-encoded ECDSA signature → raw bytes
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Signature(#[serde(with = "serde_bytes")] Vec<u8>);

impl Signature {
    fn from_base64url(s: &str) -> anyhow::Result<Self> {
        BASE64URL_NOPAD
            .decode(s.as_bytes())
            .map(Self)
            .map_err(|e| anyhow::anyhow!("invalid base64url sig {s}: {e}"))
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&BASE64URL_NOPAD.encode(&self.0))
    }
}

/// did:key:z... → raw multicodec public key bytes
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DidKey(#[serde(with = "serde_bytes")] Vec<u8>);

impl DidKey {
    fn from_did_key(s: &str) -> anyhow::Result<Self> {
        let multibase_str = s
            .strip_prefix("did:key:")
            .ok_or_else(|| anyhow::anyhow!("missing did:key: prefix in {s}"))?;
        let (_base, bytes) = multibase::decode(multibase_str)
            .map_err(|e| anyhow::anyhow!("invalid multibase in did:key {s}: {e}"))?;
        Ok(Self(bytes))
    }
}

impl fmt::Display for DidKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "did:key:{}",
            multibase::encode(multibase::Base::Base58Btc, &self.0)
        )
    }
}

/// CID string → binary CID bytes
#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
enum Aka {
    Bluesky(String),
    Atproto(String),
    Other(String),
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OpType {
    PlcOperation,
    Create,
    PlcTombstone,
    Other(String),
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
enum VerificationMethodKey {
    Atproto,
    Other(String),
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
enum ServiceKey {
    AtprotoPds,
    Other(String),
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
enum ServiceType {
    AtprotoPersonalDataServer,
    Other(String),
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
enum ServiceEndpoint {
    BlueskyPds(String),
    Other(String),
}

impl ServiceEndpoint {
    fn from_str(s: &str) -> Self {
        if let Some(host) = s
            .strip_prefix("https://")
            .and_then(|h| h.strip_suffix(".host.bsky.network"))
        {
            Self::BlueskyPds(host.to_string())
        } else {
            Self::Other(s.to_string())
        }
    }

    fn as_string(&self) -> String {
        match self {
            Self::BlueskyPds(h) => format!("https://{h}.host.bsky.network"),
            Self::Other(s) => s.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredService {
    r#type: ServiceType,
    endpoint: ServiceEndpoint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    handle: Option<String>,
    service: Option<String>,

    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    unknown: BTreeMap<String, serde_json::Value>,
}

impl StoredOp {
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
            Some(serde_json::Value::String(s)) => Some(s),
            Some(v) => {
                errors.push(StoredOpError::TypeMismatch(StoredOpField::Handle, "string"));
                unknown.insert(StoredOpField::Handle.to_string(), v);
                Option::None
            }
            Option::None => Option::None,
        };

        let service = match obj.remove(&*StoredOpField::Service) {
            Some(serde_json::Value::String(s)) => Some(s),
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
                unknown,
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
            map.insert((*StoredOpField::Handle).into(), handle.clone().into());
        }
        if let Some(service) = &self.service {
            map.insert((*StoredOpField::Service).into(), service.clone().into());
        }

        for (k, v) in &self.unknown {
            map.insert(k.clone(), v.clone());
        }

        serde_json::Value::Object(map)
    }
}

// this is basically Op, but without the cid and created_at fields
// since we have them in the key already
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct DbOp {
    #[serde(with = "serde_bytes")]
    pub did: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub cid_prefix: Vec<u8>,
    pub nullified: bool,
    pub operation: StoredOp,
}

// we have our own Op struct for fjall since we dont want to have to convert Value back to RawValue
#[derive(Debug, Serialize)]
pub struct Op {
    pub did: String,
    pub cid: String,
    pub created_at: Dt,
    pub nullified: bool,
    pub operation: serde_json::Value,
}

#[derive(Clone)]
pub struct FjallDb {
    inner: Arc<FjallInner>,
}

struct FjallInner {
    db: Database,
    ops: Keyspace,
    by_did: Keyspace,
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
                // this isn't gonna compress well anyway, since its just keys (did + timestamp + cid)
                // and dids dont have many operations in the first place, so we can use small blocks
                .data_block_size_policy(BlockSizePolicy::all(kb(2)))
        })?;
        Ok(Self {
            inner: Arc::new(FjallInner { db, ops, by_did }),
        })
    }

    pub fn clear(&self) -> fjall::Result<()> {
        self.inner.ops.clear()?;
        self.inner.by_did.clear()?;
        Ok(())
    }

    pub fn persist(&self) -> fjall::Result<()> {
        self.inner.db.persist(PersistMode::SyncAll)
    }

    pub fn compact(&self) -> fjall::Result<()> {
        self.inner.ops.major_compact()?;
        self.inner.by_did.major_compact()?;
        Ok(())
    }

    pub fn get_latest(&self) -> anyhow::Result<Option<Dt>> {
        let Some(guard) = self.inner.ops.last_key_value() else {
            return Ok(None);
        };
        let key = guard
            .key()
            .map_err(|e| anyhow::anyhow!("fjall key error: {e}"))?;

        key.get(..8)
            .ok_or_else(|| anyhow::anyhow!("invalid timestamp key {key:?}"))
            .map(decode_timestamp)
            .flatten()
            .map(Some)
    }

    pub fn insert_op(&self, batch: &mut OwnedWriteBatch, op: &CommonOp) -> anyhow::Result<usize> {
        let cid_bytes = decode_cid_str(&op.cid)?;
        let cid_prefix = cid_bytes
            .get(..30)
            .ok_or_else(|| anyhow::anyhow!("invalid cid length (prefix): {}", op.cid))?
            .to_vec();
        let cid_suffix = cid_bytes
            .get(30..)
            .ok_or_else(|| anyhow::anyhow!("invalid cid length (suffix): {}", op.cid))?;

        let pk = by_did_key(&op.did, &op.created_at, cid_suffix)?;
        if self.inner.by_did.get(&pk)?.is_some() {
            return Ok(0);
        }
        let ts_key = op_key(&op.created_at, cid_suffix);

        let mut encoded_did = Vec::with_capacity(15);
        encode_did(&mut encoded_did, &op.did)?;

        let json_val: serde_json::Value = serde_json::from_str(op.operation.get())?;
        let (stored, mut errors) = StoredOp::from_json_value(json_val);

        let Some(operation) = stored else {
            return Err(errors.remove(0)).context("fatal operation parse error");
        };

        for e in &errors {
            log::warn!("failed to parse operation {} {}: {}", op.did, op.cid, e);
        }
        if !errors.is_empty() {
            // if parse failed but not fatal, we just dont store it
            return Ok(0);
        }

        let db_op = DbOp {
            did: encoded_did,
            cid_prefix,
            nullified: op.nullified,
            operation,
        };
        let value = rmp_serde::to_vec(&db_op)?;
        batch.insert(&self.inner.ops, &ts_key, &value);
        batch.insert(&self.inner.by_did, &pk, &[]);
        Ok(1)
    }

    pub fn ops_for_did(
        &self,
        did: &str,
    ) -> anyhow::Result<impl Iterator<Item = anyhow::Result<Op>> + '_> {
        let prefix = by_did_prefix(did)?;

        Ok(self.inner.by_did.prefix(&prefix).map(move |guard| {
            let (by_did_key, _) = guard
                .into_inner()
                .map_err(|e| anyhow::anyhow!("fjall read error: {e}"))?;

            let key_rest = by_did_key
                .get(prefix.len()..)
                .ok_or_else(|| anyhow::anyhow!("invalid by_did key {by_did_key:?}"))?;

            let ts_bytes = key_rest
                .get(..8)
                .ok_or_else(|| anyhow::anyhow!("invalid length: {key_rest:?}"))?;
            let cid_suffix = key_rest
                .get(9..)
                .ok_or_else(|| anyhow::anyhow!("invalid length: {key_rest:?}"))?;

            let op_key = [ts_bytes, &[SEP][..], cid_suffix].concat();
            let ts = decode_timestamp(ts_bytes)?;

            let value = self
                .inner
                .ops
                .get(&op_key)?
                .ok_or_else(|| anyhow::anyhow!("op not found: {op_key:?}"))?;

            let op: DbOp = rmp_serde::from_slice(&value)?;
            let mut full_cid_bytes = op.cid_prefix.clone();
            full_cid_bytes.extend_from_slice(cid_suffix);

            let cid = decode_cid(&full_cid_bytes)?;
            let did = decode_did(&op.did);

            Ok(Op {
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
        after: Option<Dt>,
        limit: usize,
    ) -> anyhow::Result<impl Iterator<Item = anyhow::Result<Op>> + '_> {
        let iter = if let Some(after) = after {
            let start = (after.timestamp_micros() as u64).to_be_bytes();
            self.inner.ops.range(start..)
        } else {
            self.inner.ops.iter()
        };

        Ok(iter.take(limit).map(|item| {
            let (key, value) = item
                .into_inner()
                .map_err(|e| anyhow::anyhow!("fjall read error: {e}"))?;
            let db_op: DbOp = rmp_serde::from_slice(&value)?;
            let created_at = decode_timestamp(
                key.get(..8)
                    .ok_or_else(|| anyhow::anyhow!("invalid op key {key:?}"))?,
            )?;
            let cid_suffix = key
                .get(9..)
                .ok_or_else(|| anyhow::anyhow!("invalid op key {key:?}"))?;

            let mut full_cid_bytes = db_op.cid_prefix.clone();
            full_cid_bytes.extend_from_slice(cid_suffix);

            let cid = decode_cid(&full_cid_bytes)?;
            let did = decode_did(&db_op.did);

            Ok(Op {
                did,
                cid,
                created_at,
                nullified: db_op.nullified,
                operation: db_op.operation.to_json_value(),
            })
        }))
    }
}

pub async fn backfill_to_fjall(
    db: FjallDb,
    reset: bool,
    mut pages: mpsc::Receiver<ExportPage>,
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

    while let Some(page) = pages.recv().await {
        let should_track = notify_last_at.is_some();
        if should_track {
            if let Some(s) = PageBoundaryState::new(&page) {
                last_at = last_at.filter(|&l| l >= s.last_at).or(Some(s.last_at));
            }
        }

        let db = db.clone();
        let count = tokio::task::spawn_blocking(move || -> anyhow::Result<usize> {
            let mut batch = db.inner.db.batch();
            let mut count: usize = 0;
            for op in &page.ops {
                count += db.insert_op(&mut batch, op)?;
            }
            batch.commit()?;
            Ok(count)
        })
        .await??;
        ops_inserted += count;
    }
    log::debug!("finished receiving bulk pages");

    if let Some(notify) = notify_last_at {
        log::trace!("notifying last_at: {last_at:?}");
        if notify.send(last_at).is_err() {
            log::error!("receiver for last_at dropped, can't notify");
        };
    }

    let db = db.clone();
    tokio::task::spawn_blocking(move || db.persist()).await??;

    log::info!(
        "backfill_to_fjall: inserted {ops_inserted} ops in {:?}",
        t0.elapsed()
    );
    Ok("backfill_to_fjall")
}

pub async fn pages_to_fjall(
    db: FjallDb,
    mut pages: mpsc::Receiver<ExportPage>,
) -> anyhow::Result<&'static str> {
    log::info!("starting pages_to_fjall writer...");

    let t0 = Instant::now();
    let mut ops_inserted: usize = 0;

    while let Some(page) = pages.recv().await {
        log::trace!("writing page with {} ops", page.ops.len());
        let db = db.clone();
        let count = tokio::task::spawn_blocking(move || -> anyhow::Result<usize> {
            let mut batch = db.inner.db.batch();
            let mut count: usize = 0;
            for op in &page.ops {
                count += db.insert_op(&mut batch, op)?;
            }
            batch.commit()?;
            Ok(count)
        })
        .await??;
        ops_inserted += count;
    }

    log::info!(
        "no more pages. inserted {ops_inserted} ops in {:?}",
        t0.elapsed()
    );
    Ok("pages_to_fjall")
}

pub async fn fjall_to_pages(
    db: FjallDb,
    dest: mpsc::Sender<ExportPage>,
    until: Option<Dt>,
) -> anyhow::Result<&'static str> {
    log::info!("starting fjall_to_pages backfill source...");

    let t0 = Instant::now();

    let dest_clone = dest.clone();
    let ops_sent = tokio::task::spawn_blocking(move || -> anyhow::Result<usize> {
        let iter = db.export_ops(None, usize::MAX)?;
        let mut current_page = Vec::with_capacity(1000);
        let mut count = 0;

        for op_res in iter {
            let op = op_res?;

            if let Some(u) = until {
                if op.created_at >= u {
                    break;
                }
            }

            let operation_str = serde_json::to_string(&op.operation)?;
            let common_op = crate::Op {
                did: op.did,
                cid: op.cid,
                created_at: op.created_at,
                nullified: op.nullified,
                operation: serde_json::value::RawValue::from_string(operation_str)?,
            };

            current_page.push(common_op);
            count += 1;

            if current_page.len() >= 1000 {
                let page = ExportPage {
                    ops: std::mem::take(&mut current_page),
                };
                if dest_clone.blocking_send(page).is_err() {
                    break;
                }
            }
        }

        if !current_page.is_empty() {
            let page = ExportPage { ops: current_page };
            let _ = dest_clone.blocking_send(page);
        }

        Ok(count)
    })
    .await??;

    log::info!(
        "finished sending {ops_sent} ops from fjall in {:?}",
        t0.elapsed()
    );
    Ok("fjall_to_pages")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_roundtrip() {
        let original = "9NuYV7AqwHVTc0YuWzNV3CJafsSZWH7qCxHRUIP2xWlB-YexXC1OaYAnUayiCXLVzRQ8WBXIqF-SvZdNalwcjA";
        let sig = Signature::from_base64url(original).unwrap();
        assert_eq!(sig.0.len(), 64);
        assert_eq!(sig.to_string(), original);
    }

    #[test]
    fn did_key_roundtrip() {
        let original = "did:key:zQ3shhCGUqDKjStzuDxPkTxN6ujddP4RkEKJJouJGRRkaLGbg";
        let key = DidKey::from_did_key(original).unwrap();
        assert_eq!(key.to_string(), original);
    }

    #[test]
    fn plc_cid_roundtrip() {
        let original = "bafyreigp6shzy6dlcxuowwoxz7u5nemdrkad2my5zwzpwilcnhih7bw6zm";
        let cid = PlcCid::from_cid_str(original).unwrap();
        assert_eq!(cid.to_string(), original);
    }

    #[test]
    fn bsky_handle_roundtrip() {
        let h = Aka::from_str("at://alice.bsky.social");
        assert_eq!(h, Aka::Bluesky("alice".to_string()));
        assert_eq!(h.to_string(), "at://alice.bsky.social");
    }

    #[test]
    fn atproto_handle_roundtrip() {
        let h = Aka::from_str("at://alice.example.com");
        assert_eq!(h, Aka::Atproto("alice.example.com".to_string()));
        assert_eq!(h.to_string(), "at://alice.example.com");
    }

    #[test]
    fn other_handle_roundtrip() {
        let h = Aka::from_str("https://something.else");
        assert_eq!(h, Aka::Other("https://something.else".to_string()));
        assert_eq!(h.to_string(), "https://something.else");
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

        let e2 = ServiceEndpoint::from_str("https://other.endpoint.com");
        assert_eq!(
            e2,
            ServiceEndpoint::Other("https://other.endpoint.com".to_string())
        );
        assert_eq!(e2.as_string(), "https://other.endpoint.com");
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

                // msgpack verification
                let packed = rmp_serde::to_vec(&stored).unwrap();
                let unpacked: StoredOp = rmp_serde::from_slice(&packed).unwrap();

                let reconstructed = unpacked.to_json_value();
                assert_eq!(*op, reconstructed, "roundtrip mismatch in {path}");

                total_json_size += serde_json::to_vec(op).unwrap().len();
                total_packed_size += packed.len();
            }
        }

        println!(
            "json size: {} bytes, msgpack size: {} bytes, saved: {} bytes",
            total_json_size,
            total_packed_size,
            total_json_size as isize - total_packed_size as isize
        );
    }
}
