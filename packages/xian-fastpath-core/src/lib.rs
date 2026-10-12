use ed25519_dalek::{Signature, VerifyingKey};
use pyo3::create_exception;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use pyo3::IntoPyObjectExt;
use serde_json::{Map, Value};
use std::collections::HashSet;

create_exception!(
    xian_fastpath_core,
    NativeFastpathValidationError,
    PyValueError
);

const PAYLOAD_MARKER: &str = "\"payload\":";
const TX_METADATA_KEYS: [&str; 1] = ["signature"];
const TX_PAYLOAD_KEYS: [&str; 7] = [
    "chain_id",
    "contract",
    "function",
    "kwargs",
    "nonce",
    "sender",
    "chi_supplied",
];
const MAX_CANONICAL_JSON_DEPTH: usize = 128;

#[pyfunction]
fn extract_payload_string(json_str: &str) -> PyResult<String> {
    extract_payload_string_impl(json_str)
}

#[pyfunction]
fn decode_and_validate_transaction_static(
    py: Python<'_>,
    raw: &[u8],
    chain_id: &str,
) -> PyResult<Py<PyAny>> {
    let (tx_value, _) = decode_transaction_bytes_impl(raw)?;
    validate_transaction_static_impl(&tx_value, chain_id)?;
    value_to_pyobject(py, &tx_value)
}

#[pymodule]
fn _native(py: Python<'_>, module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add(
        "NativeFastpathValidationError",
        py.get_type::<NativeFastpathValidationError>(),
    )?;
    module.add_function(wrap_pyfunction!(extract_payload_string, module)?)?;
    module.add_function(wrap_pyfunction!(
        decode_and_validate_transaction_static,
        module
    )?)?;
    Ok(())
}

fn extract_payload_string_impl(json_str: &str) -> PyResult<String> {
    let start_index = json_str
        .find(PAYLOAD_MARKER)
        .ok_or_else(|| PyValueError::new_err("No 'payload' found in the provided JSON string."))?;
    let start_brace_index = json_str[start_index..]
        .find('{')
        .map(|offset| start_index + offset)
        .ok_or_else(|| PyValueError::new_err("Malformed JSON: No opening brace for 'payload'."))?;

    let bytes = json_str.as_bytes();
    let mut brace_count = 0usize;
    let mut in_string = false;

    for index in start_brace_index..bytes.len() {
        let byte = bytes[index];

        if byte == b'"' && !is_escaped(bytes, index) {
            in_string = !in_string;
        }

        if !in_string {
            if byte == b'{' {
                brace_count += 1;
            } else if byte == b'}' {
                if brace_count == 0 {
                    break;
                }
                brace_count -= 1;
            }
        }

        if brace_count == 0 {
            return Ok(json_str[start_brace_index..=index].to_string());
        }
    }

    Err(PyValueError::new_err(
        "Malformed JSON: No matching closing brace for 'payload'.",
    ))
}

fn is_escaped(bytes: &[u8], index: usize) -> bool {
    if index == 0 {
        return false;
    }

    let mut slash_count = 0usize;
    let mut cursor = index;
    while cursor > 0 && bytes[cursor - 1] == b'\\' {
        slash_count += 1;
        cursor -= 1;
    }
    slash_count % 2 == 1
}

fn json_parse_error(error: serde_json::Error) -> PyErr {
    let message = error.to_string();
    if message.contains("recursion limit exceeded") {
        PyValueError::new_err("recursion limit exceeded")
    } else {
        PyValueError::new_err(message)
    }
}

fn decode_transaction_bytes_impl(raw: &[u8]) -> PyResult<(Value, String)> {
    let tx_hex = std::str::from_utf8(raw).map_err(|err| PyValueError::new_err(err.to_string()))?;
    let decoded_bytes =
        hex::decode(tx_hex).map_err(|err| PyValueError::new_err(err.to_string()))?;
    let tx_str = std::str::from_utf8(&decoded_bytes)
        .map_err(|err| PyValueError::new_err(err.to_string()))?;
    let tx_value: Value = serde_json::from_str(tx_str).map_err(json_parse_error)?;
    validate_json_depth(&tx_value, 0)?;
    let canonical_tx = canonical_json(&tx_value)?;
    if tx_str != canonical_tx {
        return Err(PyValueError::new_err("Transaction bytes are not canonical"));
    }
    let parsed_payload = tx_value
        .get("payload")
        .ok_or_else(|| PyValueError::new_err("Invalid payload"))?;
    let payload_str = canonical_json(parsed_payload)?;

    Ok((tx_value, payload_str))
}

fn validate_transaction_static_impl(tx_value: &Value, chain_id: &str) -> PyResult<()> {
    let tx = expect_object(tx_value, "Transaction has wrongly formatted dictionary")?;
    let metadata = tx
        .get("metadata")
        .ok_or_else(|| validation_error("Metadata is missing"))?;
    let metadata = expect_object(metadata, "Metadata is missing")?;
    if metadata.len() != 1 {
        return Err(validation_error("Wrong number of metadata entries"));
    }
    ensure_exact_keys(metadata, &TX_METADATA_KEYS)?;

    let payload = tx
        .get("payload")
        .ok_or_else(|| validation_error("Payload is missing"))?;
    let payload = expect_object(payload, "Payload is missing")?;

    ensure_non_empty_string(payload.get("sender"), "Payload key 'sender' is missing")?;
    ensure_non_empty_string(payload.get("contract"), "Payload key 'contract' is missing")?;
    ensure_non_empty_string(payload.get("function"), "Payload key 'function' is missing")?;
    ensure_truthy(
        payload.get("chi_supplied"),
        "Payload key 'chi_supplied' is missing",
    )?;
    ensure_exact_keys(payload, &TX_PAYLOAD_KEYS)?;

    let sender = expect_string(
        payload.get("sender"),
        "Transaction has wrongly formatted dictionary",
    )?;
    let signature = expect_string(
        metadata.get("signature"),
        "Transaction has wrongly formatted dictionary",
    )?;
    let contract = expect_string(
        payload.get("contract"),
        "Transaction has wrongly formatted dictionary",
    )?;
    let function = expect_string(
        payload.get("function"),
        "Transaction has wrongly formatted dictionary",
    )?;
    let tx_chain_id = expect_string(
        payload.get("chain_id"),
        "Transaction has wrongly formatted dictionary",
    )?;
    let kwargs = payload
        .get("kwargs")
        .ok_or_else(|| validation_error("Transaction has wrongly formatted dictionary"))?;
    let kwargs = expect_object(kwargs, "Transaction has wrongly formatted dictionary")?;

    if !is_hex_of_len(sender, 64)
        || !is_hex_of_len(signature, 128)
        || !is_identifier(contract)
        || !is_identifier(function)
        || !kwargs.keys().all(|key| is_identifier(key))
        || !is_non_negative_integer(payload.get("nonce"))
        || !is_non_negative_integer(payload.get("chi_supplied"))
    {
        return Err(validation_error(
            "Transaction has wrongly formatted dictionary",
        ));
    }

    let signing_payload = build_signing_payload(payload);
    if contains_non_integer_number(&signing_payload) {
        return Err(validation_error(
            "Transaction has wrongly formatted dictionary",
        ));
    }
    let signing_message = canonical_json(&signing_payload)?;
    if !verify_signature(sender, signature, &signing_message) {
        return Err(validation_error("Bad signature"));
    }

    if tx_chain_id != chain_id {
        return Err(validation_error("Wrong chain_id"));
    }

    if contract == "submission" && function == "submit_contract" {
        let name = kwargs.get("name");
        if !is_valid_submission_name(name) {
            return Err(validation_error("Transaction contract name is invalid"));
        }
    }

    Ok(())
}

fn build_signing_payload(payload: &Map<String, Value>) -> Value {
    let mut signing_payload = Map::new();
    for key in [
        "chain_id",
        "contract",
        "function",
        "kwargs",
        "nonce",
        "sender",
        "chi_supplied",
    ] {
        if let Some(value) = payload.get(key) {
            signing_payload.insert(key.to_string(), value.clone());
        }
    }
    Value::Object(signing_payload)
}

fn verify_signature(public_key_hex: &str, signature_hex: &str, message: &str) -> bool {
    let public_key = match hex::decode(public_key_hex) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let signature = match hex::decode(signature_hex) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let public_key_bytes: [u8; 32] = match public_key.try_into() {
        Ok(value) => value,
        Err(_) => return false,
    };
    let signature_bytes: [u8; 64] = match signature.try_into() {
        Ok(value) => value,
        Err(_) => return false,
    };

    let verifying_key = match VerifyingKey::from_bytes(&public_key_bytes) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify_strict(message.as_bytes(), &signature)
        .is_ok()
}

fn ensure_exact_keys(map: &Map<String, Value>, expected: &[&str]) -> PyResult<()> {
    let expected_keys: HashSet<&str> = expected.iter().copied().collect();
    let actual_keys: HashSet<&str> = map.keys().map(|key| key.as_str()).collect();
    if expected_keys != actual_keys {
        return Err(validation_error(
            "Transaction has unexpected or missing keys",
        ));
    }
    Ok(())
}

fn ensure_non_empty_string(value: Option<&Value>, message: &str) -> PyResult<()> {
    match value.and_then(Value::as_str) {
        Some(raw) if !raw.is_empty() => Ok(()),
        _ => Err(validation_error(message)),
    }
}

fn ensure_truthy(value: Option<&Value>, message: &str) -> PyResult<()> {
    match value {
        Some(Value::Bool(raw)) if *raw => Ok(()),
        Some(Value::Number(raw)) if !raw.is_i64() || raw.as_i64().unwrap_or_default() != 0 => {
            Ok(())
        }
        Some(Value::String(raw)) if !raw.is_empty() => Ok(()),
        Some(Value::Array(raw)) if !raw.is_empty() => Ok(()),
        Some(Value::Object(raw)) if !raw.is_empty() => Ok(()),
        _ => Err(validation_error(message)),
    }
}

fn is_valid_submission_name(value: Option<&Value>) -> bool {
    let Some(Value::String(name)) = value else {
        return false;
    };
    contract_name_is_formatted(name)
}

fn contract_name_is_formatted(value: &str) -> bool {
    // Match contracting.names plus the submission contract's public prefix.
    value.len() <= 64
        && value.starts_with("con_")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphabetic() {
        return false;
    }
    chars.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

fn is_hex_of_len(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_non_negative_integer(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Number(number)) if number.as_u64().is_some())
}

fn contains_non_integer_number(value: &Value) -> bool {
    match value {
        Value::Number(number) => number.as_i64().is_none() && number.as_u64().is_none(),
        Value::Array(items) => items.iter().any(contains_non_integer_number),
        Value::Object(items) => items.values().any(contains_non_integer_number),
        _ => false,
    }
}

fn canonical_json(value: &Value) -> PyResult<String> {
    let mut output = String::new();
    write_canonical_json(value, &mut output, 0)?;
    Ok(output)
}

fn validate_json_depth(value: &Value, depth: usize) -> PyResult<()> {
    if depth > MAX_CANONICAL_JSON_DEPTH {
        return Err(PyValueError::new_err("recursion limit exceeded"));
    }
    match value {
        Value::Array(items) => {
            for item in items {
                validate_json_depth(item, depth + 1)?;
            }
        }
        Value::Object(items) => {
            for item in items.values() {
                validate_json_depth(item, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn write_canonical_json(value: &Value, output: &mut String, depth: usize) -> PyResult<()> {
    if depth > MAX_CANONICAL_JSON_DEPTH {
        return Err(PyValueError::new_err("recursion limit exceeded"));
    }
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(raw) => output.push_str(if *raw { "true" } else { "false" }),
        Value::Number(number) => output.push_str(&number.to_string()),
        Value::String(raw) => output.push_str(
            &serde_json::to_string(raw).map_err(|err| PyValueError::new_err(err.to_string()))?,
        ),
        Value::Array(items) => {
            output.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_canonical_json(item, output, depth + 1)?;
            }
            output.push(']');
        }
        Value::Object(items) => {
            output.push('{');
            let mut keys: Vec<&String> = items.keys().collect();
            keys.sort();
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output.push_str(
                    &serde_json::to_string(key)
                        .map_err(|err| PyValueError::new_err(err.to_string()))?,
                );
                output.push(':');
                write_canonical_json(items.get(*key).expect("key exists"), output, depth + 1)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

fn expect_object<'a>(value: &'a Value, message: &str) -> PyResult<&'a Map<String, Value>> {
    value.as_object().ok_or_else(|| validation_error(message))
}

fn expect_string<'a>(value: Option<&'a Value>, message: &str) -> PyResult<&'a str> {
    value
        .and_then(Value::as_str)
        .ok_or_else(|| validation_error(message))
}

fn validation_error(message: &str) -> PyErr {
    NativeFastpathValidationError::new_err(message.to_string())
}

fn value_to_pyobject(py: Python<'_>, value: &Value) -> PyResult<Py<PyAny>> {
    match value {
        Value::Null => Ok(py.None()),
        Value::Bool(raw) => Ok(raw.into_py_any(py)?),
        Value::Number(raw) => {
            if let Some(value) = raw.as_i64() {
                Ok(value.into_py_any(py)?)
            } else if let Some(value) = raw.as_u64() {
                Ok(value.into_py_any(py)?)
            } else if let Some(value) = raw.as_f64() {
                Ok(value.into_py_any(py)?)
            } else {
                Err(PyValueError::new_err("Unsupported JSON number"))
            }
        }
        Value::String(raw) => Ok(raw.into_py_any(py)?),
        Value::Array(items) => {
            let py_list = PyList::empty(py);
            for item in items {
                py_list.append(value_to_pyobject(py, item)?)?;
            }
            Ok(py_list.into_any().unbind())
        }
        Value::Object(items) => {
            let py_dict = PyDict::new(py);
            for (key, item) in items {
                py_dict.set_item(key, value_to_pyobject(py, item)?)?;
            }
            Ok(py_dict.into_any().unbind())
        }
    }
}
