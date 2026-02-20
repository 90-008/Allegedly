use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::borrow::Cow;
use std::collections::BTreeMap;

pub type CowStr<'a> = Cow<'a, str>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service<'a> {
    pub r#type: CowStr<'a>,
    pub endpoint: CowStr<'a>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DocumentData<'a> {
    pub did: CowStr<'a>,
    pub rotation_keys: Vec<CowStr<'a>>,
    pub verification_methods: BTreeMap<CowStr<'a>, CowStr<'a>>,
    pub also_known_as: Vec<CowStr<'a>>,
    pub services: BTreeMap<CowStr<'a>, Service<'a>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DidDocument<'a> {
    #[serde(rename = "@context")]
    pub context: Vec<CowStr<'a>>,
    pub id: CowStr<'a>,
    pub also_known_as: Vec<CowStr<'a>>,
    pub verification_method: Vec<VerificationMethod<'a>>,
    pub service: Vec<DocService<'a>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethod<'a> {
    pub id: CowStr<'a>,
    pub r#type: CowStr<'a>,
    pub controller: CowStr<'a>,
    pub public_key_multibase: CowStr<'a>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DocService<'a> {
    pub id: CowStr<'a>,
    pub r#type: CowStr<'a>,
    pub service_endpoint: CowStr<'a>,
}

const P256_PREFIX: &str = "zDn";
const SECP256K1_PREFIX: &str = "zQ3";

fn key_context(multibase: &str) -> Option<&'static str> {
    if multibase.starts_with(P256_PREFIX) {
        Some("https://w3id.org/security/suites/ecdsa-2019/v1")
    } else if multibase.starts_with(SECP256K1_PREFIX) {
        Some("https://w3id.org/security/suites/secp256k1-2019/v1")
    } else {
        None
    }
}

pub fn format_did_doc<'a>(data: &'a DocumentData<'a>) -> DidDocument<'a> {
    let mut context = vec![
        "https://www.w3.org/ns/did/v1".into(),
        "https://w3id.org/security/multikey/v1".into(),
    ];

    let verification_method = data
        .verification_methods
        .iter()
        .map(|(keyid, did_key)| {
            let multibase: CowStr = did_key.strip_prefix("did:key:").unwrap_or(did_key).into();

            if let Some(ctx) = key_context(&multibase) {
                if !context.iter().any(|c| c == ctx) {
                    context.push(ctx.into());
                }
            }
            VerificationMethod {
                id: format!("{}#{keyid}", data.did).into(),
                r#type: "Multikey".into(),
                controller: data.did.clone(),
                public_key_multibase: multibase,
            }
        })
        .collect();

    let service = data
        .services
        .iter()
        .map(|(service_id, svc)| DocService {
            id: format!("#{service_id}").into(),
            r#type: svc.r#type.clone(),
            service_endpoint: svc.endpoint.clone(),
        })
        .collect();

    DidDocument {
        context,
        id: data.did.clone(),
        also_known_as: data.also_known_as.clone(),
        verification_method,
        service,
    }
}

fn ensure_atproto_prefix(s: &str) -> CowStr<'_> {
    if s.starts_with("at://") {
        return s.into();
    }
    let stripped = s
        .strip_prefix("http://")
        .or_else(|| s.strip_prefix("https://"))
        .unwrap_or(s);
    format!("at://{stripped}").into()
}

fn ensure_http_prefix(s: &str) -> CowStr<'_> {
    if s.starts_with("http://") || s.starts_with("https://") {
        return s.into();
    }
    format!("https://{s}").into()
}

/// extract DocumentData from a single operation json blob.
/// returns None for tombstones.
pub fn op_to_doc_data<'a>(did: &'a str, op: &'a Value) -> Option<DocumentData<'a>> {
    // TODO: this shouldnt just short circuit to None, we should provide better information about whats missing in an error
    let obj = op.as_object()?;
    let op_type = obj.get("type")?.as_str()?;

    match op_type {
        "plc_tombstone" => None,
        "create" => {
            let signing_key = obj.get("signingKey")?.as_str()?;
            let recovery_key = obj.get("recoveryKey")?.as_str()?;
            let handle = obj.get("handle")?.as_str()?;
            let service = obj.get("service")?.as_str()?;

            let mut verification_methods = BTreeMap::new();
            verification_methods.insert("atproto".into(), signing_key.into());

            let mut services = BTreeMap::new();
            services.insert(
                "atproto_pds".into(),
                Service {
                    r#type: "AtprotoPersonalDataServer".into(),
                    endpoint: ensure_http_prefix(service),
                },
            );

            Some(DocumentData {
                did: Cow::Borrowed(did),
                rotation_keys: vec![Cow::Borrowed(recovery_key), Cow::Borrowed(signing_key)],
                verification_methods,
                also_known_as: vec![ensure_atproto_prefix(handle)],
                services,
            })
        }
        "plc_operation" => {
            let rotation_keys = obj
                .get("rotationKeys")?
                .as_array()?
                .iter()
                .filter_map(|v| v.as_str().map(Cow::Borrowed))
                .collect();

            let verification_methods = obj
                .get("verificationMethods")?
                .as_object()?
                .iter()
                .filter_map(|(k, v)| Some((k.as_str().into(), v.as_str()?.into())))
                .collect();

            let also_known_as = obj
                .get("alsoKnownAs")?
                .as_array()?
                .iter()
                .filter_map(|v| v.as_str().map(Cow::Borrowed))
                .collect();

            let services = obj
                .get("services")?
                .as_object()?
                .iter()
                .filter_map(|(k, v)| {
                    let svc: Service = Service::deserialize(v).ok()?;
                    Some((k.as_str().into(), svc))
                })
                .collect();

            Some(DocumentData {
                did: did.into(),
                rotation_keys,
                verification_methods,
                also_known_as,
                services,
            })
        }
        _ => None,
    }
}

/// apply a sequence of operation JSON blobs and return the current document data.
/// returns None if the DID is tombstoned (last op is a tombstone).
pub fn apply_op_log<'a>(
    did: &'a str,
    ops: impl IntoIterator<Item = &'a Value>,
) -> Option<DocumentData<'a>> {
    // TODO: we don't verify signature chain, we should do that...
    ops.into_iter()
        .last()
        .and_then(|op| op_to_doc_data(did, op))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_legacy_create() {
        let op = serde_json::json!({
            "type": "create",
            "signingKey": "did:key:zDnaeSigningKey",
            "recoveryKey": "did:key:zQ3shRecoveryKey",
            "handle": "alice.bsky.social",
            "service": "pds.example.com",
            "prev": null,
            "sig": "abc"
        });

        let data = op_to_doc_data("did:plc:test", &op).unwrap();
        assert_eq!(data.rotation_keys.len(), 2);
        assert_eq!(data.rotation_keys[0], "did:key:zQ3shRecoveryKey");
        assert_eq!(data.rotation_keys[1], "did:key:zDnaeSigningKey");
        assert_eq!(
            data.verification_methods.get("atproto").unwrap(),
            "did:key:zDnaeSigningKey"
        );
        assert_eq!(data.also_known_as, vec!["at://alice.bsky.social"]);
        let pds = data.services.get("atproto_pds").unwrap();
        assert_eq!(pds.endpoint, "https://pds.example.com");
    }

    #[test]
    fn format_doc_p256_context() {
        let data = DocumentData {
            did: "did:plc:test123".into(),
            rotation_keys: vec!["did:key:zDnaeXYZ".into()],
            verification_methods: {
                let mut m = BTreeMap::new();
                m.insert("atproto".into(), "did:key:zDnaeXYZ".into());
                m
            },
            also_known_as: vec!["at://alice.test".into()],
            services: {
                let mut m = BTreeMap::new();
                m.insert(
                    "atproto_pds".into(),
                    Service {
                        r#type: "AtprotoPersonalDataServer".into(),
                        endpoint: "https://pds.test".into(),
                    },
                );
                m
            },
        };

        let doc = format_did_doc(&data);
        assert_eq!(doc.context.len(), 3);
        assert!(
            doc.context
                .iter()
                .any(|c| c == "https://w3id.org/security/suites/ecdsa-2019/v1")
        );
        assert_eq!(doc.verification_method[0].public_key_multibase, "zDnaeXYZ");
        assert_eq!(doc.verification_method[0].id, "did:plc:test123#atproto");
    }

    #[test]
    fn tombstone_returns_none() {
        let op = serde_json::json!({
            "type": "plc_tombstone",
            "prev": "bafyabc",
            "sig": "xyz"
        });
        assert!(op_to_doc_data("did:plc:test", &op).is_none());
    }

    #[test]
    fn apply_log_with_tombstone() {
        let create = serde_json::json!({
            "type": "plc_operation",
            "rotationKeys": ["did:key:zQ3shKey1"],
            "verificationMethods": {"atproto": "did:key:zDnaeKey1"},
            "alsoKnownAs": ["at://alice.test"],
            "services": {
                "atproto_pds": {"type": "AtprotoPersonalDataServer", "service_endpoint": "https://pds.test"}
            },
            "prev": null,
            "sig": "abc"
        });
        let tombstone = serde_json::json!({
            "type": "plc_tombstone",
            "prev": "bafyabc",
            "sig": "xyz"
        });

        let ops = vec![create.clone()];
        let result = apply_op_log("did:plc:test", &ops);
        assert!(result.is_some());

        let ops = vec![create, tombstone];
        let result = apply_op_log("did:plc:test", &ops);
        assert!(result.is_none());
    }

    fn load_fixture(name: &str) -> (String, Vec<Value>) {
        let path = format!("tests/fixtures/{name}");
        let data = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
        let entries: Vec<Value> = serde_json::from_str(&data).unwrap();
        let did = entries[0]["did"].as_str().unwrap().to_string();
        let ops: Vec<Value> = entries
            .iter()
            .filter(|e| !e["nullified"].as_bool().unwrap_or(false))
            .map(|e| e["operation"].clone())
            .collect();
        (did, ops)
    }

    #[test]
    fn interop_legacy_dholms() {
        let (did, ops) = load_fixture("log_legacy_dholms.json");
        assert_eq!(did, "did:plc:yk4dd2qkboz2yv6tpubpc6co");

        let data = apply_op_log(&did, &ops).expect("should reconstruct");
        assert_eq!(data.did, did);
        assert_eq!(data.also_known_as, vec!["at://dholms.xyz"]);
        assert_eq!(
            data.services.get("atproto_pds").unwrap().endpoint,
            "https://bsky.social"
        );
        assert_eq!(
            data.verification_methods.get("atproto").unwrap(),
            "did:key:zQ3shXjHeiBuRCKmM36cuYnm7YEMzhGnCmCyW92sRJ9pribSF"
        );

        let doc = format_did_doc(&data);
        assert_eq!(doc.id, did);
        assert!(
            doc.context
                .iter()
                .any(|c| c == "https://w3id.org/security/suites/secp256k1-2019/v1")
        );
    }

    #[test]
    fn interop_bskyapp() {
        let (did, ops) = load_fixture("log_bskyapp.json");
        assert_eq!(did, "did:plc:z72i7hdynmk6r22z27h6tvur");

        let data = apply_op_log(&did, &ops).expect("should reconstruct");
        println!("{:?}", data);
        assert_eq!(data.also_known_as, vec!["at://bsky.app"]);
        assert_eq!(
            data.verification_methods.get("atproto").unwrap(),
            "did:key:zQ3shXjHeiBuRCKmM36cuYnm7YEMzhGnCmCyW92sRJ9pribSF"
        );
        assert_eq!(
            data.services.get("atproto_pds").unwrap().endpoint,
            "https://bsky.social"
        );
    }

    #[test]
    fn interop_tombstone() {
        let path = "tests/fixtures/log_tombstone.json";
        let data = std::fs::read_to_string(path).unwrap();
        let entries: Vec<Value> = serde_json::from_str(&data).unwrap();
        let did = entries[0]["did"].as_str().unwrap();
        let ops: Vec<Value> = entries.iter().map(|e| e["operation"].clone()).collect();

        assert_eq!(did, "did:plc:6adr3q2labdllanslzhqkqd3");
        let result = apply_op_log(did, &ops);
        assert!(result.is_none(), "tombstoned DID should return None");
    }

    #[test]
    fn interop_nullification() {
        let (did, ops) = load_fixture("log_nullification.json");
        assert_eq!(did, "did:plc:2s2mvm52ttz6r4hocmrq7x27");

        let data = apply_op_log(&did, &ops).expect("should reconstruct");
        assert_eq!(data.did, did);
        assert_eq!(data.rotation_keys.len(), 2);
        assert_eq!(
            data.rotation_keys[0],
            "did:key:zQ3shwPdax6jKMbhtzbueGwSjc7RnjsmPcNB1vQUpbKUCN1t1"
        );
    }
}
