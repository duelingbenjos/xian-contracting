//! Independent local conformance verifier. Not linked into any Xian node crate.

use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signature as EdSignature, VerifyingKey as EdKey};
use ml_dsa::{EncodedVerifyingKey, MlDsa65, Signature as PqSignature, VerifyingKey as PqKey};
use serde_json::Value;

type Check<T> = Result<T, &'static str>;

struct Record {
    chain: String,
    account: String,
    epoch: u64,
    ed: [u8; 32],
    pq: Option<Vec<u8>>,
}

struct State {
    active: Record,
    recovery: Option<Record>,
    raw: Vec<u8>,
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

fn valid_point(key: &[u8; 32]) -> bool {
    CompressedEdwardsY(*key).decompress().is_some_and(|point| {
        point.compress().to_bytes() == *key && !point.is_small_order() && point.is_torsion_free()
    })
}

impl<'a> Reader<'a> {
    fn take(&mut self, size: usize) -> Check<&'a [u8]> {
        let end = self.offset.checked_add(size).ok_or("length overflow")?;
        let result = self.bytes.get(self.offset..end).ok_or("truncated state")?;
        self.offset = end;
        Ok(result)
    }

    fn text(&mut self, limit: usize) -> Check<String> {
        let size = u16::from_be_bytes(self.take(2)?.try_into().map_err(|_| "length")?) as usize;
        if size == 0 || size > limit {
            return Err("string bound");
        }
        let bytes = self.take(size)?;
        if !bytes.is_ascii() {
            return Err("non-ASCII identity");
        }
        String::from_utf8(bytes.to_vec()).map_err(|_| "invalid text")
    }

    fn record(&mut self, pq: bool) -> Check<Record> {
        let chain = self.text(64)?;
        let account = self.text(72)?;
        let is_start = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
        if !is_start(chain.as_bytes()[0])
            || !chain.bytes().all(|b| is_start(b) || b"._-".contains(&b))
        {
            return Err("invalid chain");
        }
        if account.len() != 72
            || !account.starts_with("account:")
            || !account[8..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid account");
        }
        let epoch = u64::from_be_bytes(self.take(8)?.try_into().map_err(|_| "epoch")?);
        let ed: [u8; 32] = self.take(32)?.try_into().map_err(|_| "key")?;
        if !valid_point(&ed) {
            return Err("invalid Ed25519 key");
        }
        let pq = if pq {
            Some(self.take(1952)?.to_vec())
        } else {
            None
        };
        Ok(Record {
            chain,
            account,
            epoch,
            ed,
            pq,
        })
    }
}

fn decode_state(bytes: Vec<u8>) -> Check<State> {
    if bytes.is_empty() || bytes.len() > 4265 {
        return Err("state bound");
    }
    let mut reader = Reader {
        bytes: &bytes,
        offset: 0,
    };
    let tag = reader.take(1)?[0];
    if tag > 1 {
        return Err("unsupported state");
    }
    let active = reader.record(tag == 1)?;
    let recovery = if tag == 1 {
        let recovery = reader.record(true)?;
        if active.chain != recovery.chain
            || active.account != recovery.account
            || active.epoch != recovery.epoch
            || active.ed == recovery.ed
            || active.pq == recovery.pq
        {
            return Err("invalid role separation");
        }
        Some(recovery)
    } else {
        None
    };
    if reader.offset != bytes.len() {
        return Err("trailing state");
    }
    Ok(State {
        active,
        recovery,
        raw: bytes,
    })
}

fn ed_verify(key: &[u8; 32], message: &[u8], signature: &[u8]) -> bool {
    let Ok(key) = EdKey::from_bytes(key) else {
        return false;
    };
    let Ok(signature) = EdSignature::from_slice(signature) else {
        return false;
    };
    key.verify_strict(message, &signature).is_ok()
}

fn hybrid_verify(record: &Record, message: &[u8], auth: &[u8]) -> bool {
    let mut header = b"XIAN-HYBRID-AUTH\0\x01\x01".to_vec();
    header.extend(record.epoch.to_be_bytes());
    if auth.len() != 3400 || auth[..27] != header || !ed_verify(&record.ed, message, &auth[27..91])
    {
        return false;
    }
    let Some(pq) = &record.pq else {
        return false;
    };
    let Ok(key_bytes) = EncodedVerifyingKey::<MlDsa65>::try_from(pq.as_slice()) else {
        return false;
    };
    let Ok(signature) = PqSignature::<MlDsa65>::try_from(&auth[91..]) else {
        return false;
    };
    PqKey::<MlDsa65>::decode(&key_bytes).verify_with_context(message, &[], &signature)
}

fn lp16(destination: &mut Vec<u8>, value: &str) {
    destination.extend((value.len() as u16).to_be_bytes());
    destination.extend(value.as_bytes());
}

fn tx_message(record: &Record, payload: &[u8]) -> Check<Vec<u8>> {
    if payload.is_empty() || payload.len() > 131072 {
        return Err("payload bound");
    }
    let mut message = b"XIAN-HYBRID-TX\0\x01\x01".to_vec();
    lp16(&mut message, &record.chain);
    lp16(&mut message, &record.account);
    message.extend(record.epoch.to_be_bytes());
    message.extend(record.ed);
    message.extend(record.pq.as_ref().ok_or("hybrid key required")?);
    message.extend((payload.len() as u32).to_be_bytes());
    message.extend(payload);
    Ok(message)
}

fn transition_messages(current: &State, candidate: &State, operation: u8) -> Vec<Vec<u8>> {
    (1..=3)
        .map(|role| {
            let mut message = b"XIAN-HYBRID-LIFECYCLE\0".to_vec();
            message.extend([1, 1, operation, role]);
            for state in [current, candidate] {
                message.extend((state.raw.len() as u32).to_be_bytes());
                message.extend(&state.raw);
            }
            message
        })
        .collect()
}

/// Verify one shared conformance case and return its reconstructed signed messages.
pub fn verify_case(case: &Value, blobs: &Value) -> Check<Vec<Vec<u8>>> {
    let blob = |field: &str| -> Check<Vec<u8>> {
        let name = case[field].as_str().ok_or("blob reference")?;
        let value = blobs[name].as_str().ok_or("blob value")?;
        if !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("noncanonical hex");
        }
        hex::decode(value).map_err(|_| "invalid hex")
    };
    let state = decode_state(blob("state")?)?;
    if case["kind"] == "decode" {
        return Ok(vec![]);
    }
    if case["kind"] == "tx" {
        if state.recovery.is_none() {
            return Err("hybrid state required");
        }
        let message = tx_message(&state.active, &blob("payload")?)?;
        return if hybrid_verify(&state.active, &message, &blob("auth")?) {
            Ok(vec![message])
        } else {
            Err("invalid signatures")
        };
    }
    if case["kind"] != "transition" {
        return Err("unsupported case");
    }
    let operation = case["operation"].as_u64().ok_or("operation")?;
    if !(1..=3).contains(&operation) {
        return Err("unsupported operation");
    }
    let gate = case["enrollment_open"].as_bool().ok_or("policy")?;
    let candidate = decode_state(blob("candidate")?)?;
    let next_recovery = candidate
        .recovery
        .as_ref()
        .ok_or("hybrid candidate required")?;
    if state.active.chain != candidate.active.chain
        || state.active.account != candidate.active.account
    {
        return Err("identity mismatch");
    }
    if state.recovery.is_none() {
        if operation != 1 || !gate || candidate.active.epoch != 0 {
            return Err("invalid enrollment");
        }
    } else if operation == 1 || state.active.epoch.checked_add(1) != Some(candidate.active.epoch) {
        return Err("stale or overflowing epoch");
    }
    for next in [&candidate.active, next_recovery] {
        for old in std::iter::once(&state.active).chain(state.recovery.iter()) {
            if old.ed == next.ed || (old.pq.is_some() && old.pq == next.pq) {
                return Err("reused key");
            }
        }
    }
    let authority = blob("authority_proof")?;
    let active = blob("active_proof")?;
    let recovery = blob("recovery_proof")?;
    if authority.len() != if operation == 1 { 64 } else { 3400 }
        || active.len() != 3400
        || recovery.len() != 3400
    {
        return Err("proof size");
    }
    let messages = transition_messages(&state, &candidate, operation as u8);
    let authority_valid = match operation {
        1 => ed_verify(&state.active.ed, &messages[0], &authority),
        2 => hybrid_verify(&state.active, &messages[0], &authority),
        _ => hybrid_verify(
            state.recovery.as_ref().ok_or("recovery required")?,
            &messages[0],
            &authority,
        ),
    };
    if !authority_valid
        || !hybrid_verify(&candidate.active, &messages[1], &active)
        || !hybrid_verify(next_recovery, &messages[2], &recovery)
    {
        return Err("invalid transition proof");
    }
    Ok(messages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn shared_verdicts_and_transcript_hashes() {
        let vectors: Value =
            serde_json::from_str(include_str!("../../parity_vectors.json")).unwrap();
        assert_eq!(vectors["schema"], "xian-hybrid-parity-v1");
        for case in vectors["cases"].as_array().unwrap() {
            let result = verify_case(case, &vectors["blobs"]);
            assert_eq!(
                result.is_ok(),
                case["expected"].as_bool().unwrap(),
                "{}: {:?}",
                case["name"],
                result.as_ref().err()
            );
            if let Some(hashes) = case["transcripts_sha256"].as_array() {
                let actual: Vec<String> = result
                    .unwrap()
                    .iter()
                    .map(|message| hex::encode(Sha256::digest(message)))
                    .collect();
                let expected: Vec<&str> =
                    hashes.iter().map(|hash| hash.as_str().unwrap()).collect();
                assert_eq!(actual, expected, "{}", case["name"]);
            }
        }
    }

    #[test]
    fn payload_bounds() {
        let vectors: Value =
            serde_json::from_str(include_str!("../../parity_vectors.json")).unwrap();
        let state = decode_state(hex::decode(vectors["blobs"]["first"].as_str().unwrap()).unwrap())
            .unwrap();
        assert!(tx_message(&state.active, &[]).is_err());
        assert!(tx_message(&state.active, &vec![0; 131073]).is_err());
        assert!(tx_message(&state.active, &vec![0; 131072]).is_ok());
    }
}
