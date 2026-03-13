use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};
use std::fmt;

/// base64url-encoded ECDSA signature → raw bytes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl Signature {
    pub fn from_base64url(s: &str) -> anyhow::Result<Self> {
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
pub struct DidKey(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl DidKey {
    pub fn from_did_key(s: &str) -> anyhow::Result<Self> {
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

const P256_PREFIX: [u8; 2] = [0x80, 0x24];
const K256_PREFIX: [u8; 2] = [0xe7, 0x01];

/// verifies a plc op signature
///
/// - `key` : did:key:z... public key
/// - `data`: dag-cbor encoded op without the `sig` field (sha256 is applied internally)
/// - `sig` : signature bytes decoded from the base64url `sig` field of the op
pub fn verify_plc_sig(key: &DidKey, data: &[u8], sig: &Signature) -> anyhow::Result<()> {
    use ecdsa::signature::Verifier as _;

    let prefix: [u8; 2] = key
        .0
        .get(..2)
        .ok_or_else(|| anyhow::anyhow!("key bytes too short: {key}"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("key bytes too short: {key}"))?;
    let pubkey = key
        .0
        .get(2..)
        .ok_or_else(|| anyhow::anyhow!("key bytes too short: {key}"))?;

    match prefix {
        P256_PREFIX => {
            use p256::ecdsa::{Signature, VerifyingKey};

            let key = VerifyingKey::from_sec1_bytes(pubkey)
                .map_err(|e| anyhow::anyhow!("bad p256 key {pubkey:?}: {e}"))?;
            let sig = Signature::from_slice(&sig.0)
                .map_err(|e| anyhow::anyhow!("bad p256 sig {sig}: {e}"))?;
            if sig.normalize_s().is_some() {
                anyhow::bail!("high-S signature is not allowed for plc");
            }
            key.verify(data, &sig)
                .map_err(|e| anyhow::anyhow!("invalid p256 signature {sig}: {e}"))
        }
        K256_PREFIX => {
            use k256::ecdsa::{Signature, VerifyingKey};

            let key = VerifyingKey::from_sec1_bytes(pubkey)
                .map_err(|e| anyhow::anyhow!("bad k256 key {pubkey:?}: {e}"))?;
            let sig = Signature::from_slice(&sig.0)
                .map_err(|e| anyhow::anyhow!("bad k256 sig {sig}: {e}"))?;
            if sig.normalize_s().is_some() {
                anyhow::bail!("high-S signature is not allowed for plc");
            }
            key.verify(data, &sig)
                .map_err(|e| anyhow::anyhow!("invalid k256 signature {sig}: {e}"))
        }
        _ => anyhow::bail!("unsupported key prefix: {:02x?}", prefix),
    }
}

pub struct AssuranceResults {
    pub valid: bool,
    pub errors: Vec<anyhow::Error>,
}

/// assures that an op has a valid signature
///
/// - `keys`: the rotation keys from the previous operation (or it's own keys if genesis op)
/// - `sig` : the signature to check.
/// - `data`: the operation to check, without the sig field.
pub fn assure_valid_sig<'key>(
    keys: impl IntoIterator<Item = &'key DidKey>,
    sig: &Signature,
    data: &serde_json::Value,
) -> anyhow::Result<AssuranceResults> {
    let serde_json::Value::Object(data) = data else {
        anyhow::bail!("invalid op, not an object");
    };
    if data.contains_key("sig") {
        anyhow::bail!("data should not include the sig");
    }
    let data = serde_ipld_dagcbor::to_vec(&data)?;
    let mut results = AssuranceResults {
        valid: false,
        errors: Vec::new(),
    };
    for key in keys {
        match verify_plc_sig(key, &data, sig) {
            Ok(_) => {
                results.valid = true;
                break;
            }
            Err(e) => results.errors.push(e),
        }
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

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
    fn test_fixture_signatures() {
        let fixtures = [
            "tests/fixtures/log_bskyapp.json",
            "tests/fixtures/log_legacy_dholms.json",
            "tests/fixtures/log_nullification.json",
            "tests/fixtures/log_tombstone.json",
        ];

        for path in fixtures {
            let data = std::fs::read_to_string(path).unwrap();
            let entries: Vec<serde_json::Value> = serde_json::from_str(&data).unwrap();

            let mut ops_by_cid: HashMap<String, serde_json::Value> = HashMap::new();

            for entry in entries {
                let mut data = entry["operation"].clone();
                let cid = entry["cid"].as_str().unwrap().to_string();

                let sig_str = data["sig"].as_str().unwrap();
                let sig = Signature::from_base64url(sig_str).unwrap();

                data.as_object_mut().unwrap().remove("sig");

                let prev_cid = data["prev"].as_str().unwrap_or("");
                let op = ops_by_cid.get(prev_cid).unwrap_or(&data);

                let mut valid_keys = Vec::new();
                if let Some(arr) = op["rotationKeys"].as_array() {
                    for k in arr {
                        valid_keys.push(DidKey::from_did_key(k.as_str().unwrap()).unwrap());
                    }
                }
                if let Some(rk) = op["recoveryKey"].as_str() {
                    valid_keys.push(DidKey::from_did_key(rk).unwrap());
                }
                if let Some(sk) = op["signingKey"].as_str() {
                    valid_keys.push(DidKey::from_did_key(sk).unwrap());
                }

                assert!(
                    !valid_keys.is_empty(),
                    "{path}/{cid}: no keys to verify against"
                );

                let results = assure_valid_sig(&valid_keys, &sig, &data)
                    .expect("that we used the function correctly");
                for err in results.errors {
                    println!("{path}/{cid}: {err}");
                }
                if !results.valid {
                    panic!("signature verification failed in {path}/{cid}");
                }

                ops_by_cid.insert(cid, data);
            }
        }
    }
}
