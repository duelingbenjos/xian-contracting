use super::*;

pub(super) fn builtin_name_value(name: &str) -> Option<VmValue> {
    match name {
        "len" | "range" | "str" | "bool" | "int" | "float" | "bytes" | "bytearray" | "dict"
        | "list" | "tuple" | "set" | "frozenset" | "isinstance" | "issubclass" | "sorted"
        | "sum" | "min" | "max" | "all" | "any" | "map" | "filter" | "reversed" | "zip" | "pow"
        | "format" | "ord" | "abs" | "ascii" | "bin" | "hex" | "oct" | "chr" | "divmod"
        | "round" | "Exception" => Some(VmValue::Builtin(name.to_owned())),
        "Any" | "decimal" => Some(VmValue::TypeMarker(name.to_owned())),
        _ => None,
    }
}

pub(super) fn coerce_type_marker(value: VmValue) -> VmValue {
    match value {
        VmValue::Builtin(name)
            if matches!(
                name.as_str(),
                "str"
                    | "int"
                    | "float"
                    | "bool"
                    | "bytes"
                    | "bytearray"
                    | "list"
                    | "dict"
                    | "tuple"
                    | "set"
                    | "frozenset"
            ) =>
        {
            VmValue::TypeMarker(name)
        }
        other => other,
    }
}

pub(super) fn bytes_like_data(value: &VmValue) -> Option<&[u8]> {
    match value {
        VmValue::Bytes(bytes) | VmValue::ByteArray(bytes) => Some(bytes.as_slice()),
        _ => None,
    }
}

pub(super) fn clone_as_bytes_like(value: &VmValue) -> Result<Vec<u8>, VmExecutionError> {
    match value {
        VmValue::Bytes(bytes) | VmValue::ByteArray(bytes) => Ok(bytes.clone()),
        VmValue::String(value) => Ok(value.as_bytes().to_vec()),
        VmValue::List(values) | VmValue::Tuple(values) => values
            .iter()
            .map(byte_from_value)
            .collect::<Result<Vec<_>, _>>(),
        other => Err(VmExecutionError::new(format!(
            "{} is not bytes-like",
            other.type_name()
        ))),
    }
}

fn byte_from_value(value: &VmValue) -> Result<u8, VmExecutionError> {
    let bigint = match value {
        VmValue::Int(value) => value.clone(),
        VmValue::Bool(value) => {
            if *value {
                BigInt::from(1u8)
            } else {
                BigInt::from(0u8)
            }
        }
        other => {
            return Err(VmExecutionError::new(format!(
                "a bytes-like object is required, not '{}'",
                other.type_name()
            )))
        }
    };
    if bigint.sign() == Sign::Minus || bigint > BigInt::from(255u16) {
        return Err(VmExecutionError::new("byte must be in range(0, 256)"));
    }
    bigint_to_u32(&bigint, "byte value").map(|value| value as u8)
}

fn bytes_like_index_value(bytes: &[u8], index: &VmValue) -> Result<VmValue, VmExecutionError> {
    let idx = normalize_sequence_index(index, bytes.len())?;
    Ok(vm_int(bytes[idx]))
}

fn slice_bytes_like(
    bytes: Vec<u8>,
    lower: Option<BigInt>,
    upper: Option<BigInt>,
    step: Option<BigInt>,
    mutable: bool,
) -> Result<VmValue, VmExecutionError> {
    let sliced = slice_positions(bytes.len(), lower, upper, step)?
        .into_iter()
        .map(|index| bytes[index])
        .collect::<Vec<_>>();
    if mutable {
        Ok(VmValue::ByteArray(sliced))
    } else {
        Ok(VmValue::Bytes(sliced))
    }
}

fn repeat_bytes_like(bytes: &[u8], count: &BigInt) -> Result<Vec<u8>, VmExecutionError> {
    if count.sign() == Sign::Minus {
        return Ok(Vec::new());
    }
    let count = bigint_to_usize(count, "repeat count")?;
    let total_len = bytes.len().saturating_mul(count);
    if total_len > MAX_BINARY_ALLOCATION_BYTES {
        return Err(VmExecutionError::new(
            "binary repetition exceeds the maximum allowed allocation size",
        ));
    }
    let mut repeated = Vec::with_capacity(bytes.len().saturating_mul(count));
    for _ in 0..count {
        repeated.extend_from_slice(bytes);
    }
    Ok(repeated)
}

pub(super) fn integer_limit_error(kind: &str) -> VmExecutionError {
    VmExecutionError::new(format!(
        "{kind} exceeds the maximum allowed integer size of {MAX_INTEGER_BITS} bits"
    ))
}

pub(super) fn ensure_bigint_bits(value: &BigInt, kind: &str) -> Result<(), VmExecutionError> {
    if value.bits() > MAX_INTEGER_BITS {
        return Err(integer_limit_error(kind));
    }
    Ok(())
}

pub(super) fn checked_int_value(value: BigInt, kind: &str) -> Result<VmValue, VmExecutionError> {
    ensure_bigint_bits(&value, kind)?;
    Ok(VmValue::Int(value))
}

pub(super) fn ensure_int_input_size(value: &str) -> Result<(), VmExecutionError> {
    if value.len() > MAX_INT_STRING_CHARS {
        return Err(VmExecutionError::new(format!(
            "int() input exceeds the maximum allowed length of {MAX_INT_STRING_CHARS} characters"
        )));
    }
    Ok(())
}

pub(super) fn ensure_int_bytes_input_size(value: &[u8]) -> Result<(), VmExecutionError> {
    if value.len() > MAX_INT_STRING_CHARS {
        return Err(VmExecutionError::new(format!(
            "int() input exceeds the maximum allowed length of {MAX_INT_STRING_CHARS} characters"
        )));
    }
    Ok(())
}

fn estimated_mul_bits(left: &BigInt, right: &BigInt) -> u64 {
    if left.is_zero() || right.is_zero() {
        return 0;
    }
    left.bits().saturating_add(right.bits())
}

fn is_power_of_two_bigint(value: &BigInt) -> bool {
    if value.sign() == Sign::Minus || value.is_zero() {
        return false;
    }
    let one = BigInt::from(1u8);
    (value.clone() & (value - &one)).is_zero()
}

fn estimated_pow_bits(base: &BigInt, exponent: &BigInt) -> Result<u64, VmExecutionError> {
    if exponent.sign() == Sign::Minus || base.is_zero() || base.abs() == BigInt::from(1u8) {
        return Ok(1);
    }
    let exponent = exponent
        .to_u64()
        .ok_or_else(|| integer_limit_error("integer exponentiation"))?;
    let absolute = base.abs();
    let base_bits = if is_power_of_two_bigint(&absolute) {
        absolute.bits().saturating_sub(1)
    } else {
        absolute.bits()
    };
    base_bits
        .checked_mul(exponent)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| integer_limit_error("integer exponentiation"))
}

fn checked_bigint_mul(left: BigInt, right: BigInt) -> Result<VmValue, VmExecutionError> {
    if estimated_mul_bits(&left, &right) > MAX_INTEGER_BITS + 1 {
        return Err(integer_limit_error("integer multiplication"));
    }
    checked_int_value(left * right, "integer multiplication")
}

pub(super) fn checked_bigint_pow(
    base: &BigInt,
    exponent: &BigInt,
    kind: &str,
) -> Result<VmValue, VmExecutionError> {
    if estimated_pow_bits(base, exponent)? > MAX_INTEGER_BITS {
        return Err(integer_limit_error(kind));
    }
    checked_int_value(base.pow(bigint_to_u32(exponent, "pow exponent")?), kind)
}

fn checked_left_shift(left: BigInt, right: BigInt) -> Result<VmValue, VmExecutionError> {
    if right.sign() == Sign::Minus {
        return Err(VmExecutionError::new("negative shift count"));
    }
    let shift = bigint_to_usize(&right, "shift count")?;
    let shift_bits = u64::try_from(shift).unwrap_or(u64::MAX);
    if !left.is_zero() && left.bits().saturating_add(shift_bits) > MAX_INTEGER_BITS {
        return Err(integer_limit_error("left shift"));
    }
    checked_int_value(left << shift, "left shift")
}

fn checked_right_shift(left: BigInt, right: BigInt) -> Result<VmValue, VmExecutionError> {
    if right.sign() == Sign::Minus {
        return Err(VmExecutionError::new("negative shift count"));
    }
    if right > BigInt::from(MAX_INTEGER_BITS) {
        return Err(integer_limit_error("right shift count"));
    }
    let shift = bigint_to_usize(&right, "shift count")?;
    Ok(VmValue::Int(left >> shift))
}

fn compare_bytes_like(left: &[u8], right: &[u8]) -> std::cmp::Ordering {
    left.cmp(right)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum VmSetKey {
    None,
    Bool(bool),
    Int(BigInt),
    Decimal(BigInt),
    Float(String),
    DateTime((i64, i64, i64, i64, i64, i64, i64)),
    TimeDelta(i64),
    String(String),
    Bytes(Vec<u8>),
    Tuple(Vec<VmSetKey>),
    FrozenSet(Vec<VmSetKey>),
}

pub(super) fn set_like_values(value: &VmValue) -> Option<&[VmValue]> {
    match value {
        VmValue::Set(values) | VmValue::FrozenSet(values) => Some(values.as_slice()),
        _ => None,
    }
}

pub(super) fn normalize_set_items(values: Vec<VmValue>) -> Result<Vec<VmValue>, VmExecutionError> {
    let mut normalized: Vec<(VmValue, VmSetKey)> = Vec::new();
    for value in values {
        let key = vm_set_key(&value)?;
        let mut matched_index = None;
        for (index, (existing, _)) in normalized.iter().enumerate() {
            if vm_values_equal(existing, &value)? {
                matched_index = Some(index);
                break;
            }
        }
        if let Some(index) = matched_index {
            if key < normalized[index].1 {
                normalized[index] = (value, key);
            }
        } else {
            normalized.push((value, key));
        }
    }
    normalized.sort_by(|left, right| left.1.cmp(&right.1));
    Ok(normalized.into_iter().map(|(value, _)| value).collect())
}

fn vm_set_key(value: &VmValue) -> Result<VmSetKey, VmExecutionError> {
    match value {
        VmValue::None => Ok(VmSetKey::None),
        VmValue::Bool(value) => Ok(VmSetKey::Bool(*value)),
        VmValue::Int(value) => Ok(VmSetKey::Int(value.clone())),
        VmValue::Decimal(value) => Ok(VmSetKey::Decimal(value.scaled.clone())),
        VmValue::Float(value) => Ok(VmSetKey::Float(format!("{value:?}"))),
        VmValue::DateTime(value) => Ok(VmSetKey::DateTime((
            value.year(),
            value.month(),
            value.day(),
            value.hour(),
            value.minute(),
            value.second(),
            value.microsecond(),
        ))),
        VmValue::TimeDelta(value) => Ok(VmSetKey::TimeDelta(value.seconds())),
        VmValue::String(value) => Ok(VmSetKey::String(value.clone())),
        VmValue::Bytes(value) => Ok(VmSetKey::Bytes(value.clone())),
        VmValue::Tuple(values) => Ok(VmSetKey::Tuple(
            values
                .iter()
                .map(vm_set_key)
                .collect::<Result<Vec<_>, _>>()?,
        )),
        VmValue::FrozenSet(values) => Ok(VmSetKey::FrozenSet(
            values
                .iter()
                .map(vm_set_key)
                .collect::<Result<Vec<_>, _>>()?,
        )),
        other => Err(VmExecutionError::new(format!(
            "unhashable type: '{}'",
            other.type_name()
        ))),
    }
}

fn set_contains_value(values: &[VmValue], needle: &VmValue) -> Result<bool, VmExecutionError> {
    for value in values {
        if vm_values_equal(value, needle)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn set_values_equal(left: &[VmValue], right: &[VmValue]) -> Result<bool, VmExecutionError> {
    if left.len() != right.len() {
        return Ok(false);
    }
    for value in left {
        if !set_contains_value(right, value)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn set_is_subset(left: &[VmValue], right: &[VmValue]) -> Result<bool, VmExecutionError> {
    for value in left {
        if !set_contains_value(right, value)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn set_union_values(left: &[VmValue], right: &[VmValue]) -> Vec<VmValue> {
    let mut values = left.to_vec();
    values.extend(right.iter().cloned());
    values
}

fn set_intersection_values(
    left: &[VmValue],
    right: &[VmValue],
) -> Result<Vec<VmValue>, VmExecutionError> {
    let mut values = Vec::new();
    for value in left {
        if set_contains_value(right, value)? {
            values.push(value.clone());
        }
    }
    Ok(values)
}

fn set_difference_values(
    left: &[VmValue],
    right: &[VmValue],
) -> Result<Vec<VmValue>, VmExecutionError> {
    let mut values = Vec::new();
    for value in left {
        if !set_contains_value(right, value)? {
            values.push(value.clone());
        }
    }
    Ok(values)
}

fn set_symmetric_difference_values(
    left: &[VmValue],
    right: &[VmValue],
) -> Result<Vec<VmValue>, VmExecutionError> {
    let mut values = set_difference_values(left, right)?;
    for value in right {
        if !set_contains_value(left, value)? {
            values.push(value.clone());
        }
    }
    Ok(values)
}

pub(super) fn apply_binary_operator(
    operator: &str,
    left: VmValue,
    right: VmValue,
) -> Result<VmValue, VmExecutionError> {
    let coerce_decimal = |value: &VmValue, side: &str| -> Result<VmDecimal, VmExecutionError> {
        VmDecimal::from_vm_value(value).map_err(|err| {
            VmExecutionError::new(format!(
                "binary operator '{operator}' could not coerce {side} operand {} ({}) to decimal: {err}",
                value.python_repr(),
                value.type_name()
            ))
        })
    };
    match operator {
        "add" => match (left, right) {
            (VmValue::DateTime(left), VmValue::TimeDelta(right)) => {
                Ok(VmValue::DateTime(left.add_timedelta(&right)?))
            }
            (VmValue::TimeDelta(left), VmValue::DateTime(right)) => {
                Ok(VmValue::DateTime(right.add_timedelta(&left)?))
            }
            (VmValue::TimeDelta(left), VmValue::TimeDelta(right)) => {
                Ok(VmValue::TimeDelta(left.add(&right)?))
            }
            (VmValue::Decimal(left), VmValue::Decimal(right)) => {
                Ok(VmValue::Decimal(left.add(&right)?))
            }
            (VmValue::Decimal(left), right) => Ok(VmValue::Decimal(
                left.add(&coerce_decimal(&right, "right")?)?,
            )),
            (left, VmValue::Decimal(right)) => Ok(VmValue::Decimal(
                coerce_decimal(&left, "left")?.add(&right)?,
            )),
            (VmValue::Int(left), VmValue::Int(right)) => Ok(VmValue::Int(left + right)),
            (VmValue::Float(left), VmValue::Float(right)) => Ok(VmValue::Float(left + right)),
            (VmValue::Int(left), VmValue::Float(right)) => Ok(VmValue::Float(
                bigint_to_f64(&left, "left int operand")? + right,
            )),
            (VmValue::Float(left), VmValue::Int(right)) => Ok(VmValue::Float(
                left + bigint_to_f64(&right, "right int operand")?,
            )),
            (VmValue::Bytes(mut left), VmValue::Bytes(right)) => {
                left.extend(right);
                Ok(VmValue::Bytes(left))
            }
            (VmValue::Bytes(mut left), VmValue::ByteArray(right)) => {
                left.extend(right);
                Ok(VmValue::Bytes(left))
            }
            (VmValue::ByteArray(mut left), VmValue::Bytes(right)) => {
                left.extend(right);
                Ok(VmValue::ByteArray(left))
            }
            (VmValue::ByteArray(mut left), VmValue::ByteArray(right)) => {
                left.extend(right);
                Ok(VmValue::ByteArray(left))
            }
            (VmValue::String(left), VmValue::String(right)) => Ok(VmValue::String(left + &right)),
            (VmValue::List(mut left), VmValue::List(right)) => {
                left.extend(right);
                Ok(VmValue::List(left))
            }
            (VmValue::Tuple(mut left), VmValue::Tuple(right)) => {
                left.extend(right);
                Ok(VmValue::Tuple(left))
            }
            (left, right) => Err(VmExecutionError::new(format!(
                "unsupported add operands {} and {}",
                left.type_name(),
                right.type_name()
            ))),
        },
        "sub" => match (left, right) {
            (VmValue::DateTime(left), VmValue::DateTime(right)) => {
                Ok(VmValue::TimeDelta(left.sub_datetime(&right)?))
            }
            (VmValue::TimeDelta(left), VmValue::TimeDelta(right)) => {
                Ok(VmValue::TimeDelta(left.sub(&right)?))
            }
            (VmValue::Decimal(left), VmValue::Decimal(right)) => {
                Ok(VmValue::Decimal(left.sub(&right)?))
            }
            (VmValue::Decimal(left), right) => Ok(VmValue::Decimal(
                left.sub(&coerce_decimal(&right, "right")?)?,
            )),
            (left, VmValue::Decimal(right)) => Ok(VmValue::Decimal(
                coerce_decimal(&left, "left")?.sub(&right)?,
            )),
            (VmValue::Int(left), VmValue::Int(right)) => Ok(VmValue::Int(left - right)),
            (VmValue::Float(left), VmValue::Float(right)) => Ok(VmValue::Float(left - right)),
            (VmValue::Int(left), VmValue::Float(right)) => Ok(VmValue::Float(
                bigint_to_f64(&left, "left int operand")? - right,
            )),
            (VmValue::Float(left), VmValue::Int(right)) => Ok(VmValue::Float(
                left - bigint_to_f64(&right, "right int operand")?,
            )),
            (VmValue::Set(values), right) if set_like_values(&right).is_some() => {
                let right = set_like_values(&right).expect("checked above");
                Ok(VmValue::Set(normalize_set_items(set_difference_values(
                    &values, right,
                )?)?))
            }
            (VmValue::FrozenSet(values), right) if set_like_values(&right).is_some() => {
                let right = set_like_values(&right).expect("checked above");
                Ok(VmValue::FrozenSet(normalize_set_items(
                    set_difference_values(&values, right)?,
                )?))
            }
            (left, right) => Err(VmExecutionError::new(format!(
                "unsupported sub operands {} and {}",
                left.type_name(),
                right.type_name()
            ))),
        },
        "mul" => match (left, right) {
            (VmValue::TimeDelta(left), VmValue::TimeDelta(right)) => {
                Ok(VmValue::TimeDelta(left.mul_timedelta(&right)?))
            }
            (VmValue::TimeDelta(left), VmValue::Int(right)) => Ok(VmValue::TimeDelta(
                left.mul_int(bigint_to_i64(&right, "timedelta multiplier")?)?,
            )),
            (VmValue::Int(left), VmValue::TimeDelta(right)) => Ok(VmValue::TimeDelta(
                right.mul_int(bigint_to_i64(&left, "timedelta multiplier")?)?,
            )),
            (VmValue::List(values), VmValue::Int(count)) => {
                Ok(VmValue::List(repeat_values(&values, &count)?))
            }
            (VmValue::Int(count), VmValue::List(values)) => {
                Ok(VmValue::List(repeat_values(&values, &count)?))
            }
            (VmValue::Tuple(values), VmValue::Int(count)) => {
                Ok(VmValue::Tuple(repeat_values(&values, &count)?))
            }
            (VmValue::Int(count), VmValue::Tuple(values)) => {
                Ok(VmValue::Tuple(repeat_values(&values, &count)?))
            }
            (VmValue::String(value), VmValue::Int(count)) => {
                Ok(VmValue::String(repeat_string(&value, &count)?))
            }
            (VmValue::Int(count), VmValue::String(value)) => {
                Ok(VmValue::String(repeat_string(&value, &count)?))
            }
            (VmValue::Bytes(bytes), VmValue::Int(count))
            | (VmValue::Int(count), VmValue::Bytes(bytes)) => {
                Ok(VmValue::Bytes(repeat_bytes_like(&bytes, &count)?))
            }
            (VmValue::ByteArray(bytes), VmValue::Int(count))
            | (VmValue::Int(count), VmValue::ByteArray(bytes)) => {
                Ok(VmValue::ByteArray(repeat_bytes_like(&bytes, &count)?))
            }
            (VmValue::Decimal(left), VmValue::Decimal(right)) => {
                Ok(VmValue::Decimal(left.mul(&right)?))
            }
            (VmValue::Decimal(left), right) => Ok(VmValue::Decimal(
                left.mul(&coerce_decimal(&right, "right")?)?,
            )),
            (left, VmValue::Decimal(right)) => Ok(VmValue::Decimal(
                coerce_decimal(&left, "left")?.mul(&right)?,
            )),
            (VmValue::Int(left), VmValue::Int(right)) => checked_bigint_mul(left, right),
            (VmValue::Float(left), VmValue::Float(right)) => Ok(VmValue::Float(left * right)),
            (VmValue::Int(left), VmValue::Float(right)) => Ok(VmValue::Float(
                bigint_to_f64(&left, "left int operand")? * right,
            )),
            (VmValue::Float(left), VmValue::Int(right)) => Ok(VmValue::Float(
                left * bigint_to_f64(&right, "right int operand")?,
            )),
            (left, right) => Err(VmExecutionError::new(format!(
                "unsupported mul operands {} and {}",
                left.type_name(),
                right.type_name()
            ))),
        },
        "div" => match (left, right) {
            (VmValue::Decimal(left), VmValue::Decimal(right)) => {
                Ok(VmValue::Decimal(left.div(&right)?))
            }
            (VmValue::Decimal(left), right) => Ok(VmValue::Decimal(
                left.div(&coerce_decimal(&right, "right")?)?,
            )),
            (left, VmValue::Decimal(right)) => Ok(VmValue::Decimal(
                coerce_decimal(&left, "left")?.div(&right)?,
            )),
            (VmValue::Int(left), VmValue::Int(right)) => {
                if right.is_zero() {
                    return Err(VmExecutionError::new("division by zero"));
                }
                Ok(VmValue::Float(
                    bigint_to_f64(&left, "left int operand")?
                        / bigint_to_f64(&right, "right int operand")?,
                ))
            }
            (VmValue::Float(left), VmValue::Float(right)) => Ok(VmValue::Float(left / right)),
            (VmValue::Int(left), VmValue::Float(right)) => Ok(VmValue::Float(
                bigint_to_f64(&left, "left int operand")? / right,
            )),
            (VmValue::Float(left), VmValue::Int(right)) => Ok(VmValue::Float(
                left / bigint_to_f64(&right, "right int operand")?,
            )),
            (left, right) => Err(VmExecutionError::new(format!(
                "unsupported div operands {} and {}",
                left.type_name(),
                right.type_name()
            ))),
        },
        "floordiv" => match (left, right) {
            (VmValue::Decimal(left), VmValue::Decimal(right)) => {
                Ok(VmValue::Decimal(left.floor_div(&right)?))
            }
            (VmValue::Decimal(left), right) => Ok(VmValue::Decimal(
                left.floor_div(&coerce_decimal(&right, "right")?)?,
            )),
            (left, VmValue::Decimal(right)) => Ok(VmValue::Decimal(
                coerce_decimal(&left, "left")?.floor_div(&right)?,
            )),
            (VmValue::Int(left), VmValue::Int(right)) => {
                Ok(VmValue::Int(bigint_floor_div(&left, &right)?))
            }
            (left, right) => Err(VmExecutionError::new(format!(
                "unsupported floordiv operands {} and {}",
                left.type_name(),
                right.type_name()
            ))),
        },
        "mod" => match (left, right) {
            (VmValue::Decimal(left), VmValue::Decimal(right)) => {
                Ok(VmValue::Decimal(left.modulo(&right)?))
            }
            (VmValue::Decimal(left), right) => Ok(VmValue::Decimal(
                left.modulo(&coerce_decimal(&right, "right")?)?,
            )),
            (left, VmValue::Decimal(right)) => Ok(VmValue::Decimal(
                coerce_decimal(&left, "left")?.modulo(&right)?,
            )),
            (VmValue::Int(left), VmValue::Int(right)) => {
                Ok(VmValue::Int(bigint_modulo(&left, &right)?))
            }
            (left, right) => Err(VmExecutionError::new(format!(
                "unsupported mod operands {} and {}",
                left.type_name(),
                right.type_name()
            ))),
        },
        "pow" => match (left, right) {
            (VmValue::Int(left), VmValue::Int(right)) => {
                checked_bigint_pow(&left, &right, "integer exponentiation")
            }
            (VmValue::Decimal(left), VmValue::Decimal(right)) => {
                Ok(VmValue::Decimal(left.pow(&right)?))
            }
            (VmValue::Decimal(left), right) => Ok(VmValue::Decimal(
                left.pow(&coerce_decimal(&right, "right")?)?,
            )),
            (left, VmValue::Decimal(right)) => Ok(VmValue::Decimal(
                coerce_decimal(&left, "left")?.pow(&right)?,
            )),
            (VmValue::Float(left), VmValue::Float(right)) => Ok(VmValue::Float(left.powf(right))),
            (VmValue::Float(left), VmValue::Int(right)) => Ok(VmValue::Float(
                left.powf(bigint_to_f64(&right, "pow exponent")?),
            )),
            (VmValue::Int(left), VmValue::Float(right)) => Ok(VmValue::Float(
                bigint_to_f64(&left, "pow base")?.powf(right),
            )),
            (left, right) => Err(VmExecutionError::new(format!(
                "unsupported pow operands {} and {}",
                left.type_name(),
                right.type_name()
            ))),
        },
        "bitand" => match (left, right) {
            (VmValue::Bool(left), VmValue::Bool(right)) => Ok(VmValue::Bool(left & right)),
            (VmValue::Set(values), right) if set_like_values(&right).is_some() => {
                let right = set_like_values(&right).expect("checked above");
                Ok(VmValue::Set(normalize_set_items(set_intersection_values(
                    &values, right,
                )?)?))
            }
            (VmValue::FrozenSet(values), right) if set_like_values(&right).is_some() => {
                let right = set_like_values(&right).expect("checked above");
                Ok(VmValue::FrozenSet(normalize_set_items(
                    set_intersection_values(&values, right)?,
                )?))
            }
            (left, right) => Ok(VmValue::Int(left.as_bigint()? & right.as_bigint()?)),
        },
        "bitor" => match (left, right) {
            (VmValue::Bool(left), VmValue::Bool(right)) => Ok(VmValue::Bool(left | right)),
            (VmValue::Set(values), right) if set_like_values(&right).is_some() => {
                let right = set_like_values(&right).expect("checked above");
                Ok(VmValue::Set(normalize_set_items(set_union_values(
                    &values, right,
                ))?))
            }
            (VmValue::FrozenSet(values), right) if set_like_values(&right).is_some() => {
                let right = set_like_values(&right).expect("checked above");
                Ok(VmValue::FrozenSet(normalize_set_items(set_union_values(
                    &values, right,
                ))?))
            }
            (left, right) => Ok(VmValue::Int(left.as_bigint()? | right.as_bigint()?)),
        },
        "bitxor" => match (left, right) {
            (VmValue::Bool(left), VmValue::Bool(right)) => Ok(VmValue::Bool(left ^ right)),
            (VmValue::Set(values), right) if set_like_values(&right).is_some() => {
                let right = set_like_values(&right).expect("checked above");
                Ok(VmValue::Set(normalize_set_items(
                    set_symmetric_difference_values(&values, right)?,
                )?))
            }
            (VmValue::FrozenSet(values), right) if set_like_values(&right).is_some() => {
                let right = set_like_values(&right).expect("checked above");
                Ok(VmValue::FrozenSet(normalize_set_items(
                    set_symmetric_difference_values(&values, right)?,
                )?))
            }
            (left, right) => Ok(VmValue::Int(left.as_bigint()? ^ right.as_bigint()?)),
        },
        "lshift" => {
            let left = left.as_bigint()?;
            let right = right.as_bigint()?;
            checked_left_shift(left, right)
        }
        "rshift" => {
            let left = left.as_bigint()?;
            let right = right.as_bigint()?;
            checked_right_shift(left, right)
        }
        other => Err(VmExecutionError::new(format!(
            "unsupported binary operator '{other}'"
        ))),
    }
}

pub(super) fn apply_unary_operator(
    operator: &str,
    operand: VmValue,
) -> Result<VmValue, VmExecutionError> {
    match operator {
        "not" => Ok(VmValue::Bool(!operand.truthy())),
        "neg" => match operand {
            VmValue::Int(value) => Ok(VmValue::Int(-value)),
            VmValue::Float(value) => Ok(VmValue::Float(-value)),
            VmValue::Decimal(value) => Ok(VmValue::Decimal(VmDecimal::from_scaled(-value.scaled)?)),
            other => Err(VmExecutionError::new(format!(
                "unsupported neg operand {}",
                other.type_name()
            ))),
        },
        "pos" => match operand {
            VmValue::Int(value) => Ok(VmValue::Int(value)),
            VmValue::Float(value) => Ok(VmValue::Float(value)),
            VmValue::Decimal(value) => Ok(VmValue::Decimal(value)),
            VmValue::TimeDelta(value) => Ok(VmValue::TimeDelta(value)),
            other => Err(VmExecutionError::new(format!(
                "unsupported pos operand {}",
                other.type_name()
            ))),
        },
        "invert" => Ok(VmValue::Int(!operand.as_bigint()?)),
        other => Err(VmExecutionError::new(format!(
            "unsupported unary operator '{other}'"
        ))),
    }
}

pub(super) fn apply_compare_operator(
    operator: &str,
    left: &VmValue,
    right: &VmValue,
) -> Result<bool, VmExecutionError> {
    match operator {
        "eq" => vm_values_equal(left, right),
        "not_eq" => Ok(!vm_values_equal(left, right)?),
        "gt" if set_like_values(left).is_some() && set_like_values(right).is_some() => {
            let left = set_like_values(left).expect("checked above");
            let right = set_like_values(right).expect("checked above");
            Ok(left.len() > right.len() && set_is_subset(right, left)?)
        }
        "gt_e" if set_like_values(left).is_some() && set_like_values(right).is_some() => {
            let left = set_like_values(left).expect("checked above");
            let right = set_like_values(right).expect("checked above");
            set_is_subset(right, left)
        }
        "lt" if set_like_values(left).is_some() && set_like_values(right).is_some() => {
            let left = set_like_values(left).expect("checked above");
            let right = set_like_values(right).expect("checked above");
            Ok(left.len() < right.len() && set_is_subset(left, right)?)
        }
        "lt_e" if set_like_values(left).is_some() && set_like_values(right).is_some() => {
            let left = set_like_values(left).expect("checked above");
            let right = set_like_values(right).expect("checked above");
            set_is_subset(left, right)
        }
        "gt" => compare_ord(left, right, |left, right| left > right),
        "gt_e" => compare_ord(left, right, |left, right| left >= right),
        "lt" => compare_ord(left, right, |left, right| left < right),
        "lt_e" => compare_ord(left, right, |left, right| left <= right),
        "in" => contains_value(right, left),
        "not_in" => contains_value(right, left).map(|value| !value),
        "is" => Ok(left == right),
        "is_not" => Ok(left != right),
        other => Err(VmExecutionError::new(format!(
            "unsupported compare operator '{other}'"
        ))),
    }
}

pub(super) fn compare_ord<F>(
    left: &VmValue,
    right: &VmValue,
    op: F,
) -> Result<bool, VmExecutionError>
where
    F: Fn(f64, f64) -> bool,
{
    let coerce_decimal = |value: &VmValue, side: &str| -> Result<VmDecimal, VmExecutionError> {
        VmDecimal::from_vm_value(value).map_err(|err| {
            VmExecutionError::new(format!(
                "comparison could not coerce {side} operand {} ({}) to decimal: {err}",
                value.python_repr(),
                value.type_name()
            ))
        })
    };
    match (left, right) {
        (VmValue::DateTime(left), VmValue::DateTime(right)) => Ok(op_datetime(left, right, &op)),
        (VmValue::TimeDelta(left), VmValue::TimeDelta(right)) => Ok(op_timedelta(left, right, &op)),
        (VmValue::Decimal(left), VmValue::Decimal(right)) => Ok(op_decimal(left, right, &op)),
        (VmValue::Decimal(left), right) => {
            Ok(op_decimal(left, &coerce_decimal(right, "right")?, &op))
        }
        (left, VmValue::Decimal(right)) => {
            Ok(op_decimal(&coerce_decimal(left, "left")?, right, &op))
        }
        (VmValue::Int(left), VmValue::Int(right)) => Ok(op_bigint(left, right, &op)),
        (VmValue::Float(left), VmValue::Float(right)) => Ok(op(*left, *right)),
        (VmValue::Int(left), VmValue::Float(right)) => {
            Ok(op(bigint_to_f64(left, "left int operand")?, *right))
        }
        (VmValue::Float(left), VmValue::Int(right)) => {
            Ok(op(*left, bigint_to_f64(right, "right int operand")?))
        }
        (VmValue::String(left), VmValue::String(right)) => Ok(op_string(left, right, &op)),
        (left, right) if bytes_like_data(left).is_some() && bytes_like_data(right).is_some() => {
            let left = bytes_like_data(left).expect("checked above");
            let right = bytes_like_data(right).expect("checked above");
            let score = match compare_bytes_like(left, right) {
                std::cmp::Ordering::Greater => 1.0,
                std::cmp::Ordering::Equal => 0.0,
                std::cmp::Ordering::Less => -1.0,
            };
            Ok(op(score, 0.0))
        }
        (left, right) => Err(VmExecutionError::new(format!(
            "values {} and {} are not order-comparable",
            left.type_name(),
            right.type_name()
        ))),
    }
}

pub(super) fn op_string<F>(left: &str, right: &str, op: &F) -> bool
where
    F: Fn(f64, f64) -> bool,
{
    let left_score = if left > right {
        1.0
    } else if left == right {
        0.0
    } else {
        -1.0
    };
    op(left_score, 0.0)
}

pub(super) fn op_decimal<F>(left: &VmDecimal, right: &VmDecimal, op: &F) -> bool
where
    F: Fn(f64, f64) -> bool,
{
    let left_score = match left.scaled.cmp(&right.scaled) {
        std::cmp::Ordering::Greater => 1.0,
        std::cmp::Ordering::Equal => 0.0,
        std::cmp::Ordering::Less => -1.0,
    };
    op(left_score, 0.0)
}

pub(super) fn op_bigint<F>(left: &BigInt, right: &BigInt, op: &F) -> bool
where
    F: Fn(f64, f64) -> bool,
{
    let score = match left.cmp(right) {
        std::cmp::Ordering::Greater => 1.0,
        std::cmp::Ordering::Equal => 0.0,
        std::cmp::Ordering::Less => -1.0,
    };
    op(score, 0.0)
}

pub(super) fn op_datetime<F>(left: &VmDateTime, right: &VmDateTime, op: &F) -> bool
where
    F: Fn(f64, f64) -> bool,
{
    let score = match left.value.cmp(&right.value) {
        std::cmp::Ordering::Greater => 1.0,
        std::cmp::Ordering::Equal => 0.0,
        std::cmp::Ordering::Less => -1.0,
    };
    op(score, 0.0)
}

pub(super) fn op_timedelta<F>(left: &VmTimeDelta, right: &VmTimeDelta, op: &F) -> bool
where
    F: Fn(f64, f64) -> bool,
{
    let score = match left.raw_seconds.cmp(&right.raw_seconds) {
        std::cmp::Ordering::Greater => 1.0,
        std::cmp::Ordering::Equal => 0.0,
        std::cmp::Ordering::Less => -1.0,
    };
    op(score, 0.0)
}

pub(super) fn native_attribute_value(
    value: &VmValue,
    attr: &str,
) -> Result<VmValue, VmExecutionError> {
    match value {
        VmValue::DateTime(value) => match attr {
            "year" => Ok(vm_int(value.year())),
            "month" => Ok(vm_int(value.month())),
            "day" => Ok(vm_int(value.day())),
            "hour" => Ok(vm_int(value.hour())),
            "minute" => Ok(vm_int(value.minute())),
            "second" => Ok(vm_int(value.second())),
            "microsecond" => Ok(vm_int(value.microsecond())),
            other => Err(VmExecutionError::new(format!(
                "datetime has no attribute '{other}'"
            ))),
        },
        VmValue::TimeDelta(value) => match attr {
            "seconds" => Ok(vm_int(value.seconds())),
            "minutes" => Ok(vm_int(value.minutes())),
            "hours" => Ok(vm_int(value.hours())),
            "days" => Ok(vm_int(value.days())),
            "weeks" => Ok(vm_int(value.weeks())),
            other => Err(VmExecutionError::new(format!(
                "timedelta has no attribute '{other}'"
            ))),
        },
        other => Err(VmExecutionError::new(format!(
            "value of type {} has no native attribute '{}'",
            other.type_name(),
            attr
        ))),
    }
}

pub(super) fn time_datetime_new(
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
) -> Result<VmValue, VmExecutionError> {
    let year = positional_or_keyword_i64(&args, &kwargs, 0, "year")?;
    let month = positional_or_keyword_i64(&args, &kwargs, 1, "month")?;
    let day = positional_or_keyword_i64(&args, &kwargs, 2, "day")?;
    let hour = optional_positional_or_keyword_i64(&args, &kwargs, 3, "hour")?.unwrap_or(0);
    let minute = optional_positional_or_keyword_i64(&args, &kwargs, 4, "minute")?.unwrap_or(0);
    let second = optional_positional_or_keyword_i64(&args, &kwargs, 5, "second")?.unwrap_or(0);
    let microsecond =
        optional_positional_or_keyword_i64(&args, &kwargs, 6, "microsecond")?.unwrap_or(0);
    Ok(VmValue::DateTime(VmDateTime::new(
        year,
        month,
        day,
        hour,
        minute,
        second,
        microsecond,
    )?))
}

pub(super) fn time_datetime_strptime(
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
) -> Result<VmValue, VmExecutionError> {
    if !kwargs.is_empty() || args.len() != 2 {
        return Err(VmExecutionError::new(
            "datetime.datetime.strptime() expects two positional arguments",
        ));
    }
    let date_string = args[0].as_string()?;
    let format = args[1].as_string()?;
    Ok(VmValue::DateTime(VmDateTime::parse(&date_string, &format)?))
}

pub(super) fn time_timedelta_new(
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
) -> Result<VmValue, VmExecutionError> {
    let weeks = optional_positional_or_keyword_i64(&args, &kwargs, 0, "weeks")?.unwrap_or(0);
    let days = optional_positional_or_keyword_i64(&args, &kwargs, 1, "days")?.unwrap_or(0);
    let hours = optional_positional_or_keyword_i64(&args, &kwargs, 2, "hours")?.unwrap_or(0);
    let minutes = optional_positional_or_keyword_i64(&args, &kwargs, 3, "minutes")?.unwrap_or(0);
    let seconds = optional_positional_or_keyword_i64(&args, &kwargs, 4, "seconds")?.unwrap_or(0);
    Ok(VmValue::TimeDelta(VmTimeDelta::new(
        weeks, days, hours, minutes, seconds,
    )?))
}

fn strict_hash_hex_bytes(value: &str) -> Result<Vec<u8>, VmExecutionError> {
    if value.len() % 2 != 0 {
        return Err(VmExecutionError::new(
            "hash hex input must contain whole bytes",
        ));
    }
    hex::decode(value)
        .map_err(|_| VmExecutionError::new("hash hex input must be unprefixed hexadecimal"))
}

pub(super) fn hash_sha3_256_text(
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
) -> Result<VmValue, VmExecutionError> {
    if !kwargs.is_empty() || args.len() != 1 {
        return Err(VmExecutionError::new(
            "hashlib.sha3_text() expects one argument",
        ));
    }
    let mut hasher = Sha3_256::new();
    hasher.update(args[0].as_string()?.as_bytes());
    Ok(VmValue::String(hex::encode(hasher.finalize())))
}

pub(super) fn hash_sha3_256_hex(
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
) -> Result<VmValue, VmExecutionError> {
    if !kwargs.is_empty() || args.len() != 1 {
        return Err(VmExecutionError::new(
            "hashlib.sha3_hex() expects one argument",
        ));
    }
    let mut hasher = Sha3_256::new();
    hasher.update(strict_hash_hex_bytes(&args[0].as_string()?)?);
    Ok(VmValue::String(hex::encode(hasher.finalize())))
}

pub(super) fn hash_sha256_text(
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
) -> Result<VmValue, VmExecutionError> {
    if !kwargs.is_empty() || args.len() != 1 {
        return Err(VmExecutionError::new(
            "hashlib.sha256_text() expects one argument",
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(args[0].as_string()?.as_bytes());
    Ok(VmValue::String(hex::encode(hasher.finalize())))
}

pub(super) fn hash_sha256_hex(
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
) -> Result<VmValue, VmExecutionError> {
    if !kwargs.is_empty() || args.len() != 1 {
        return Err(VmExecutionError::new(
            "hashlib.sha256_hex() expects one argument",
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(strict_hash_hex_bytes(&args[0].as_string()?)?);
    Ok(VmValue::String(hex::encode(hasher.finalize())))
}

pub(super) fn crypto_ed25519_verify(
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
) -> Result<VmValue, VmExecutionError> {
    if !kwargs.is_empty() || args.len() != 3 {
        return Err(VmExecutionError::new(
            "crypto.verify() expects three positional arguments",
        ));
    }
    let key_hex = args[0].as_string()?;
    let message = args[1].as_string()?;
    let signature_hex = args[2].as_string()?;

    let key_bytes = match hex::decode(key_hex) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(VmValue::Bool(false)),
    };
    let signature_bytes = match hex::decode(signature_hex) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(VmValue::Bool(false)),
    };
    let verifying_key = match VerifyingKey::from_bytes(
        &key_bytes
            .try_into()
            .map_err(|_| VmExecutionError::new("invalid verify key length"))?,
    ) {
        Ok(key) => key,
        Err(_) => return Ok(VmValue::Bool(false)),
    };
    let signature = match Signature::try_from(signature_bytes.as_slice()) {
        Ok(signature) => signature,
        Err(_) => return Ok(VmValue::Bool(false)),
    };
    Ok(VmValue::Bool(
        verifying_key
            .verify_strict(message.as_bytes(), &signature)
            .is_ok(),
    ))
}

pub(super) fn crypto_key_is_valid(
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
) -> Result<VmValue, VmExecutionError> {
    if !kwargs.is_empty() || args.len() != 1 {
        return Err(VmExecutionError::new(
            "crypto.key_is_valid() expects one argument",
        ));
    }
    let key = args[0].as_string()?;
    Ok(VmValue::Bool(
        key.len() == 64 && key.chars().all(|ch| ch.is_ascii_hexdigit()),
    ))
}

pub(super) fn positional_or_keyword_i64(
    args: &[VmValue],
    kwargs: &[(String, VmValue)],
    index: usize,
    name: &str,
) -> Result<i64, VmExecutionError> {
    optional_positional_or_keyword_i64(args, kwargs, index, name)?
        .ok_or_else(|| VmExecutionError::new(format!("missing required argument '{name}'")))
}

pub(super) fn optional_positional_or_keyword_i64(
    args: &[VmValue],
    kwargs: &[(String, VmValue)],
    index: usize,
    name: &str,
) -> Result<Option<i64>, VmExecutionError> {
    if let Some(value) = args.get(index) {
        return Ok(Some(value.as_i64()?));
    }
    if let Some((_, value)) = kwargs.iter().find(|(key, _)| key == name) {
        return Ok(Some(value.as_i64()?));
    }
    Ok(None)
}

pub(super) fn format_builtin_value(
    value: &VmValue,
    spec: &str,
) -> Result<String, VmExecutionError> {
    match value {
        VmValue::Int(value) => format_bigint(value, spec),
        VmValue::String(value) if spec.is_empty() => Ok(value.clone()),
        VmValue::Bool(_)
        | VmValue::Float(_)
        | VmValue::Decimal(_)
        | VmValue::Bytes(_)
        | VmValue::ByteArray(_)
            if spec.is_empty() =>
        {
            Ok(value.python_repr())
        }
        other => Err(VmExecutionError::new(format!(
            "format() does not support {} with spec '{}'",
            other.type_name(),
            spec
        ))),
    }
}

pub(super) fn format_bigint(value: &BigInt, spec: &str) -> Result<String, VmExecutionError> {
    if spec.is_empty() || spec == "d" {
        return Ok(value.to_string());
    }

    let (width_spec, format_type) = spec
        .chars()
        .last()
        .map(|format_type| (&spec[..spec.len() - format_type.len_utf8()], format_type))
        .ok_or_else(|| VmExecutionError::new("invalid format spec"))?;

    let zero_pad = width_spec.starts_with('0');
    let width = if width_spec.is_empty() {
        0
    } else {
        width_spec.parse::<usize>().map_err(|_| {
            VmExecutionError::new(format!("unsupported integer format spec '{spec}'"))
        })?
    };

    let rendered = match format_type {
        'b' => value.to_str_radix(2),
        'o' => value.to_str_radix(8),
        'x' => value.to_str_radix(16),
        'X' => value.to_str_radix(16).to_uppercase(),
        'd' => value.to_string(),
        _ => {
            return Err(VmExecutionError::new(format!(
                "unsupported integer format spec '{spec}'"
            )))
        }
    };

    if width == 0 || rendered.len() >= width {
        return Ok(rendered);
    }

    let pad_char = if zero_pad { '0' } else { ' ' };
    let (sign, digits) = if let Some(stripped) = rendered.strip_prefix('-') {
        ("-", stripped)
    } else {
        ("", rendered.as_str())
    };
    let padding = pad_char
        .to_string()
        .repeat(width.saturating_sub(sign.len() + digits.len()));
    if zero_pad && !sign.is_empty() {
        Ok(format!("{sign}{padding}{digits}"))
    } else {
        Ok(format!("{padding}{sign}{digits}"))
    }
}

pub(super) fn repeat_values(
    values: &[VmValue],
    count: &BigInt,
) -> Result<Vec<VmValue>, VmExecutionError> {
    if count.sign() == Sign::Minus {
        return Ok(Vec::new());
    }
    let count = bigint_to_usize(count, "sequence repeat count")?;
    let total_len = values.len().saturating_mul(count);
    if total_len > MAX_SEQUENCE_LENGTH {
        return Err(VmExecutionError::new(
            "sequence repetition exceeds the maximum allowed allocation size",
        ));
    }
    let mut repeated = Vec::with_capacity(values.len().saturating_mul(count));
    for _ in 0..count {
        repeated.extend(values.iter().cloned());
    }
    Ok(repeated)
}

pub(super) fn repeat_string(value: &str, count: &BigInt) -> Result<String, VmExecutionError> {
    if count.sign() == Sign::Minus {
        return Ok(String::new());
    }
    let count = bigint_to_usize(count, "string repeat count")?;
    let total_len = value.len().saturating_mul(count);
    if total_len > MAX_BINARY_ALLOCATION_BYTES {
        return Err(VmExecutionError::new(
            "string repetition exceeds the maximum allowed allocation size",
        ));
    }
    Ok(value.repeat(count))
}

pub(super) fn render_simple_format(
    template: &str,
    args: &[VmValue],
) -> Result<String, VmExecutionError> {
    let mut rendered = String::new();
    let mut chars = template.chars().peekable();
    let mut next_arg = 0usize;

    while let Some(ch) = chars.next() {
        match ch {
            '{' => {
                if chars.peek() == Some(&'{') {
                    chars.next();
                    rendered.push('{');
                    continue;
                }

                let mut token = String::new();
                loop {
                    let Some(inner) = chars.next() else {
                        return Err(VmExecutionError::new("str.format() missing closing '}'"));
                    };
                    if inner == '}' {
                        break;
                    }
                    token.push(inner);
                }

                let index = if token.is_empty() {
                    let index = next_arg;
                    next_arg += 1;
                    index
                } else {
                    token.parse::<usize>().map_err(|_| {
                        VmExecutionError::new(format!("unsupported str.format() field '{token}'"))
                    })?
                };
                let value = args.get(index).ok_or_else(|| {
                    VmExecutionError::new("str.format() placeholder index out of range")
                })?;
                rendered.push_str(&value.python_repr());
            }
            '}' => {
                if chars.peek() == Some(&'}') {
                    chars.next();
                    rendered.push('}');
                } else {
                    return Err(VmExecutionError::new("str.format() unmatched '}'"));
                }
            }
            other => rendered.push(other),
        }
    }

    Ok(rendered)
}

pub(super) fn call_native_method(
    receiver: VmValue,
    method: &str,
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
) -> Result<NativeMethodResult, VmExecutionError> {
    if !kwargs.is_empty() {
        return Err(VmExecutionError::new(format!(
            "native method '{}()' does not accept keyword arguments",
            method
        )));
    }

    match receiver {
        VmValue::List(mut values) => match method {
            "append" => {
                if args.len() != 1 {
                    return Err(VmExecutionError::new("list.append() expects one argument"));
                }
                values.push(args[0].clone());
                Ok(NativeMethodResult::Mutated {
                    receiver: VmValue::List(values),
                    value: VmValue::None,
                })
            }
            "remove" => {
                if args.len() != 1 {
                    return Err(VmExecutionError::new("list.remove() expects one argument"));
                }
                let index = values
                    .iter()
                    .position(|value| value == &args[0])
                    .ok_or_else(|| VmExecutionError::new("list.remove(x): x not in list"))?;
                values.remove(index);
                Ok(NativeMethodResult::Mutated {
                    receiver: VmValue::List(values),
                    value: VmValue::None,
                })
            }
            "extend" => {
                if args.len() != 1 {
                    return Err(VmExecutionError::new("list.extend() expects one argument"));
                }
                values.extend(iterate_value(&args[0])?);
                Ok(NativeMethodResult::Mutated {
                    receiver: VmValue::List(values),
                    value: VmValue::None,
                })
            }
            "insert" => {
                if args.len() != 2 {
                    return Err(VmExecutionError::new("list.insert() expects two arguments"));
                }
                let index = normalize_sequence_insert_index(&args[0], values.len())?;
                values.insert(index, args[1].clone());
                Ok(NativeMethodResult::Mutated {
                    receiver: VmValue::List(values),
                    value: VmValue::None,
                })
            }
            "pop" => {
                let index = match args.as_slice() {
                    [] => values
                        .len()
                        .checked_sub(1)
                        .ok_or_else(|| VmExecutionError::new("pop from empty list"))?,
                    [index] => normalize_sequence_index(index, values.len())?,
                    _ => {
                        return Err(VmExecutionError::new(
                            "list.pop() accepts at most one argument",
                        ))
                    }
                };
                let value = values.remove(index);
                Ok(NativeMethodResult::Mutated {
                    receiver: VmValue::List(values),
                    value,
                })
            }
            "count" => {
                if args.len() != 1 {
                    return Err(VmExecutionError::new("list.count() expects one argument"));
                }
                let mut count = 0usize;
                for value in &values {
                    if vm_values_equal(value, &args[0])? {
                        count += 1;
                    }
                }
                Ok(NativeMethodResult::Value(vm_int(count)))
            }
            "index" => match args.as_slice() {
                [needle] | [needle, ..] => {
                    let (start, end) =
                        normalize_search_bounds(values.len(), args.get(1), args.get(2))?;
                    for (offset, value) in values[start..end].iter().enumerate() {
                        if vm_values_equal(value, needle)? {
                            return Ok(NativeMethodResult::Value(vm_int(start + offset)));
                        }
                    }
                    Err(VmExecutionError::new("list.index(x): x not in list"))
                }
                _ => Err(VmExecutionError::new(
                    "list.index() expects between one and three arguments",
                )),
            },
            "clear" => {
                if !args.is_empty() {
                    return Err(VmExecutionError::new("list.clear() expects no arguments"));
                }
                values.clear();
                Ok(NativeMethodResult::Mutated {
                    receiver: VmValue::List(values),
                    value: VmValue::None,
                })
            }
            "copy" => {
                if !args.is_empty() {
                    return Err(VmExecutionError::new("list.copy() expects no arguments"));
                }
                Ok(NativeMethodResult::Value(VmValue::List(values.clone())))
            }
            other => Err(VmExecutionError::new(format!(
                "unsupported list method '{}()'",
                other
            ))),
        },
        VmValue::String(value) => match method {
            "upper" => match args.as_slice() {
                [] => Ok(NativeMethodResult::Value(VmValue::String(
                    value.to_uppercase(),
                ))),
                _ => Err(VmExecutionError::new("str.upper() expects no arguments")),
            },
            "lower" => match args.as_slice() {
                [] => Ok(NativeMethodResult::Value(VmValue::String(
                    value.to_lowercase(),
                ))),
                _ => Err(VmExecutionError::new("str.lower() expects no arguments")),
            },
            "isascii" => match args.as_slice() {
                [] => Ok(NativeMethodResult::Value(VmValue::Bool(value.is_ascii()))),
                _ => Err(VmExecutionError::new("str.isascii() expects no arguments")),
            },
            "isalpha" => match args.as_slice() {
                [] => Ok(NativeMethodResult::Value(VmValue::Bool(
                    !value.is_empty() && value.chars().all(char::is_alphabetic),
                ))),
                _ => Err(VmExecutionError::new("str.isalpha() expects no arguments")),
            },
            "isdigit" => match args.as_slice() {
                [] => Ok(NativeMethodResult::Value(VmValue::Bool(
                    !value.is_empty() && value.chars().all(char::is_numeric),
                ))),
                _ => Err(VmExecutionError::new("str.isdigit() expects no arguments")),
            },
            "islower" => match args.as_slice() {
                [] => {
                    let has_cased = value.chars().any(char::is_alphabetic);
                    Ok(NativeMethodResult::Value(VmValue::Bool(
                        has_cased
                            && value
                                .chars()
                                .all(|ch| !ch.is_alphabetic() || ch.is_lowercase()),
                    )))
                }
                _ => Err(VmExecutionError::new("str.islower() expects no arguments")),
            },
            "isalnum" => match args.as_slice() {
                [] => Ok(NativeMethodResult::Value(VmValue::Bool(
                    !value.is_empty() && value.chars().all(char::is_alphanumeric),
                ))),
                _ => Err(VmExecutionError::new("str.isalnum() expects no arguments")),
            },
            "startswith" => match args.as_slice() {
                [prefix] | [prefix, ..] => {
                    let (start, end) =
                        normalize_search_bounds(value.chars().count(), args.get(1), args.get(2))?;
                    let segment = substring_by_char_bounds(&value, start, end);
                    let prefixes = string_match_candidates(prefix)?;
                    Ok(NativeMethodResult::Value(VmValue::Bool(
                        prefixes.iter().any(|prefix| segment.starts_with(prefix)),
                    )))
                }
                _ => Err(VmExecutionError::new(
                    "str.startswith() expects between one and three arguments",
                )),
            },
            "endswith" => match args.as_slice() {
                [suffix] | [suffix, ..] => {
                    let (start, end) =
                        normalize_search_bounds(value.chars().count(), args.get(1), args.get(2))?;
                    let segment = substring_by_char_bounds(&value, start, end);
                    let suffixes = string_match_candidates(suffix)?;
                    Ok(NativeMethodResult::Value(VmValue::Bool(
                        suffixes.iter().any(|suffix| segment.ends_with(suffix)),
                    )))
                }
                _ => Err(VmExecutionError::new(
                    "str.endswith() expects between one and three arguments",
                )),
            },
            "find" => match args.as_slice() {
                [needle] | [needle, ..] => {
                    let needle = needle.as_string()?;
                    let (start, end) =
                        normalize_search_bounds(value.chars().count(), args.get(1), args.get(2))?;
                    let segment = substring_by_char_bounds(&value, start, end);
                    let found = segment
                        .find(&needle)
                        .map(|byte_index| start + segment[..byte_index].chars().count());
                    Ok(NativeMethodResult::Value(vm_int(
                        found.map_or(-1i64, |index| index as i64),
                    )))
                }
                _ => Err(VmExecutionError::new(
                    "str.find() expects between one and three arguments",
                )),
            },
            "strip" => match args.as_slice() {
                [] => Ok(NativeMethodResult::Value(VmValue::String(
                    value.trim().to_owned(),
                ))),
                [chars] => {
                    let chars = chars.as_string()?;
                    let stripped = if chars.is_empty() {
                        value.clone()
                    } else {
                        value.trim_matches(|ch| chars.contains(ch)).to_owned()
                    };
                    Ok(NativeMethodResult::Value(VmValue::String(stripped)))
                }
                _ => Err(VmExecutionError::new(
                    "str.strip() expects zero or one argument",
                )),
            },
            "replace" => match args.as_slice() {
                [old, new] => Ok(NativeMethodResult::Value(VmValue::String(
                    value.replace(&old.as_string()?, &new.as_string()?),
                ))),
                [old, new, count] => {
                    let count = count.as_bigint()?;
                    let replaced = if count < BigInt::zero() {
                        value.replace(&old.as_string()?, &new.as_string()?)
                    } else {
                        value.replacen(
                            &old.as_string()?,
                            &new.as_string()?,
                            bigint_to_usize(&count, "str.replace count")?,
                        )
                    };
                    Ok(NativeMethodResult::Value(VmValue::String(replaced)))
                }
                _ => Err(VmExecutionError::new(
                    "str.replace() expects two or three arguments",
                )),
            },
            "join" => match args.as_slice() {
                [items] => {
                    let rendered = iterate_value(items)?
                        .into_iter()
                        .map(|item| item.as_string())
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok(NativeMethodResult::Value(VmValue::String(
                        rendered.join(&value),
                    )))
                }
                _ => Err(VmExecutionError::new("str.join() expects one argument")),
            },
            "split" => match args.as_slice() {
                [] => Ok(NativeMethodResult::Value(VmValue::List(
                    split_string(value.as_str(), None, None)?
                        .into_iter()
                        .map(VmValue::String)
                        .collect(),
                ))),
                [separator] => {
                    let separator = if matches!(separator, VmValue::None) {
                        None
                    } else {
                        Some(separator.as_string()?)
                    };
                    Ok(NativeMethodResult::Value(VmValue::List(
                        split_string(value.as_str(), separator.as_deref(), None)?
                            .into_iter()
                            .map(VmValue::String)
                            .collect(),
                    )))
                }
                [separator, maxsplit] => {
                    let separator = if matches!(separator, VmValue::None) {
                        None
                    } else {
                        Some(separator.as_string()?)
                    };
                    let maxsplit = maxsplit.as_bigint()?;
                    let limit = if maxsplit.sign() == Sign::Minus {
                        None
                    } else {
                        Some(bigint_to_usize(&maxsplit, "str.split maxsplit")?)
                    };
                    Ok(NativeMethodResult::Value(VmValue::List(
                        split_string(value.as_str(), separator.as_deref(), limit)?
                            .into_iter()
                            .map(VmValue::String)
                            .collect(),
                    )))
                }
                _ => Err(VmExecutionError::new(
                    "str.split() expects between zero and two arguments",
                )),
            },
            "format" => Ok(NativeMethodResult::Value(VmValue::String(
                render_simple_format(&value, &args)?,
            ))),
            other => Err(VmExecutionError::new(format!(
                "unsupported str method '{}()'",
                other
            ))),
        },
        VmValue::Bytes(value) => match method {
            "hex" => match args.as_slice() {
                [] => Ok(NativeMethodResult::Value(VmValue::String(hex::encode(
                    value,
                )))),
                _ => Err(VmExecutionError::new("bytes.hex() expects no arguments")),
            },
            other => Err(VmExecutionError::new(format!(
                "unsupported bytes method '{}()'",
                other
            ))),
        },
        VmValue::ByteArray(mut value) => match method {
            "hex" => match args.as_slice() {
                [] => Ok(NativeMethodResult::Value(VmValue::String(hex::encode(
                    &value,
                )))),
                _ => Err(VmExecutionError::new(
                    "bytearray.hex() expects no arguments",
                )),
            },
            "append" => {
                if args.len() != 1 {
                    return Err(VmExecutionError::new(
                        "bytearray.append() expects one argument",
                    ));
                }
                value.push(byte_from_value(&args[0])?);
                Ok(NativeMethodResult::Mutated {
                    receiver: VmValue::ByteArray(value),
                    value: VmValue::None,
                })
            }
            "extend" => {
                if args.len() != 1 {
                    return Err(VmExecutionError::new(
                        "bytearray.extend() expects one argument",
                    ));
                }
                let bytes = iterate_value(&args[0])?
                    .iter()
                    .map(byte_from_value)
                    .collect::<Result<Vec<_>, _>>()?;
                value.extend(bytes);
                Ok(NativeMethodResult::Mutated {
                    receiver: VmValue::ByteArray(value),
                    value: VmValue::None,
                })
            }
            "pop" => {
                let index = match args.as_slice() {
                    [] => value
                        .len()
                        .checked_sub(1)
                        .ok_or_else(|| VmExecutionError::new("pop from empty bytearray"))?,
                    [index] => normalize_sequence_index(index, value.len())?,
                    _ => {
                        return Err(VmExecutionError::new(
                            "bytearray.pop() accepts at most one argument",
                        ))
                    }
                };
                let popped = value.remove(index);
                Ok(NativeMethodResult::Mutated {
                    receiver: VmValue::ByteArray(value),
                    value: vm_int(popped),
                })
            }
            "clear" => {
                if !args.is_empty() {
                    return Err(VmExecutionError::new(
                        "bytearray.clear() expects no arguments",
                    ));
                }
                value.clear();
                Ok(NativeMethodResult::Mutated {
                    receiver: VmValue::ByteArray(value),
                    value: VmValue::None,
                })
            }
            "copy" => {
                if !args.is_empty() {
                    return Err(VmExecutionError::new(
                        "bytearray.copy() expects no arguments",
                    ));
                }
                Ok(NativeMethodResult::Value(VmValue::ByteArray(value.clone())))
            }
            other => Err(VmExecutionError::new(format!(
                "unsupported bytearray method '{}()'",
                other
            ))),
        },
        VmValue::Set(mut values) => match method {
            "add" => {
                if args.len() != 1 {
                    return Err(VmExecutionError::new("set.add() expects one argument"));
                }
                values.push(args[0].clone());
                Ok(NativeMethodResult::Mutated {
                    receiver: VmValue::Set(normalize_set_items(values)?),
                    value: VmValue::None,
                })
            }
            "remove" => {
                if args.len() != 1 {
                    return Err(VmExecutionError::new("set.remove() expects one argument"));
                }
                let remaining = set_difference_values(&values, &args)?;
                if remaining.len() == values.len() {
                    return Err(VmExecutionError::new(args[0].python_repr()));
                }
                Ok(NativeMethodResult::Mutated {
                    receiver: VmValue::Set(remaining),
                    value: VmValue::None,
                })
            }
            "discard" => {
                if args.len() != 1 {
                    return Err(VmExecutionError::new("set.discard() expects one argument"));
                }
                Ok(NativeMethodResult::Mutated {
                    receiver: VmValue::Set(set_difference_values(&values, &args)?),
                    value: VmValue::None,
                })
            }
            "pop" => {
                if !args.is_empty() {
                    return Err(VmExecutionError::new("set.pop() expects no arguments"));
                }
                let value = values
                    .first()
                    .cloned()
                    .ok_or_else(|| VmExecutionError::new("pop from an empty set"))?;
                values.remove(0);
                Ok(NativeMethodResult::Mutated {
                    receiver: VmValue::Set(values),
                    value,
                })
            }
            "clear" => {
                if !args.is_empty() {
                    return Err(VmExecutionError::new("set.clear() expects no arguments"));
                }
                Ok(NativeMethodResult::Mutated {
                    receiver: VmValue::Set(Vec::new()),
                    value: VmValue::None,
                })
            }
            "copy" => {
                if !args.is_empty() {
                    return Err(VmExecutionError::new("set.copy() expects no arguments"));
                }
                Ok(NativeMethodResult::Value(VmValue::Set(values.clone())))
            }
            "issubset" => {
                if args.len() != 1 {
                    return Err(VmExecutionError::new("set.issubset() expects one argument"));
                }
                let other = normalize_set_items(iterate_value(&args[0])?)?;
                Ok(NativeMethodResult::Value(VmValue::Bool(set_is_subset(
                    &values, &other,
                )?)))
            }
            "issuperset" => {
                if args.len() != 1 {
                    return Err(VmExecutionError::new(
                        "set.issuperset() expects one argument",
                    ));
                }
                let other = normalize_set_items(iterate_value(&args[0])?)?;
                Ok(NativeMethodResult::Value(VmValue::Bool(set_is_subset(
                    &other, &values,
                )?)))
            }
            "isdisjoint" => {
                if args.len() != 1 {
                    return Err(VmExecutionError::new(
                        "set.isdisjoint() expects one argument",
                    ));
                }
                let other = normalize_set_items(iterate_value(&args[0])?)?;
                Ok(NativeMethodResult::Value(VmValue::Bool(
                    set_intersection_values(&values, &other)?.is_empty(),
                )))
            }
            "union" => {
                let mut merged = values.clone();
                for other in &args {
                    merged.extend(iterate_value(other)?);
                }
                Ok(NativeMethodResult::Value(VmValue::Set(
                    normalize_set_items(merged)?,
                )))
            }
            "intersection" => {
                let mut result = values.clone();
                for other in &args {
                    let other = normalize_set_items(iterate_value(other)?)?;
                    result = set_intersection_values(&result, &other)?;
                }
                Ok(NativeMethodResult::Value(VmValue::Set(result)))
            }
            "difference" => {
                let mut result = values.clone();
                for other in &args {
                    let other = normalize_set_items(iterate_value(other)?)?;
                    result = set_difference_values(&result, &other)?;
                }
                Ok(NativeMethodResult::Value(VmValue::Set(result)))
            }
            "symmetric_difference" => {
                if args.len() != 1 {
                    return Err(VmExecutionError::new(
                        "set.symmetric_difference() expects one argument",
                    ));
                }
                let other = normalize_set_items(iterate_value(&args[0])?)?;
                Ok(NativeMethodResult::Value(VmValue::Set(
                    normalize_set_items(set_symmetric_difference_values(&values, &other)?)?,
                )))
            }
            other => Err(VmExecutionError::new(format!(
                "unsupported set method '{}()'",
                other
            ))),
        },
        VmValue::FrozenSet(values) => match method {
            "copy" => {
                if !args.is_empty() {
                    return Err(VmExecutionError::new(
                        "frozenset.copy() expects no arguments",
                    ));
                }
                Ok(NativeMethodResult::Value(VmValue::FrozenSet(values)))
            }
            "issubset" => {
                if args.len() != 1 {
                    return Err(VmExecutionError::new(
                        "frozenset.issubset() expects one argument",
                    ));
                }
                let other = normalize_set_items(iterate_value(&args[0])?)?;
                Ok(NativeMethodResult::Value(VmValue::Bool(set_is_subset(
                    &values, &other,
                )?)))
            }
            "issuperset" => {
                if args.len() != 1 {
                    return Err(VmExecutionError::new(
                        "frozenset.issuperset() expects one argument",
                    ));
                }
                let other = normalize_set_items(iterate_value(&args[0])?)?;
                Ok(NativeMethodResult::Value(VmValue::Bool(set_is_subset(
                    &other, &values,
                )?)))
            }
            "isdisjoint" => {
                if args.len() != 1 {
                    return Err(VmExecutionError::new(
                        "frozenset.isdisjoint() expects one argument",
                    ));
                }
                let other = normalize_set_items(iterate_value(&args[0])?)?;
                Ok(NativeMethodResult::Value(VmValue::Bool(
                    set_intersection_values(&values, &other)?.is_empty(),
                )))
            }
            "union" => {
                let mut merged = values.clone();
                for other in &args {
                    merged.extend(iterate_value(other)?);
                }
                Ok(NativeMethodResult::Value(VmValue::FrozenSet(
                    normalize_set_items(merged)?,
                )))
            }
            "intersection" => {
                let mut result = values.clone();
                for other in &args {
                    let other = normalize_set_items(iterate_value(other)?)?;
                    result = set_intersection_values(&result, &other)?;
                }
                Ok(NativeMethodResult::Value(VmValue::FrozenSet(result)))
            }
            "difference" => {
                let mut result = values.clone();
                for other in &args {
                    let other = normalize_set_items(iterate_value(other)?)?;
                    result = set_difference_values(&result, &other)?;
                }
                Ok(NativeMethodResult::Value(VmValue::FrozenSet(result)))
            }
            "symmetric_difference" => {
                if args.len() != 1 {
                    return Err(VmExecutionError::new(
                        "frozenset.symmetric_difference() expects one argument",
                    ));
                }
                let other = normalize_set_items(iterate_value(&args[0])?)?;
                Ok(NativeMethodResult::Value(VmValue::FrozenSet(
                    normalize_set_items(set_symmetric_difference_values(&values, &other)?)?,
                )))
            }
            other => Err(VmExecutionError::new(format!(
                "unsupported frozenset method '{}()'",
                other
            ))),
        },
        VmValue::Dict(entries) => match method {
            "keys" => {
                if !args.is_empty() {
                    return Err(VmExecutionError::new("dict.keys() expects no arguments"));
                }
                Ok(NativeMethodResult::Value(VmValue::List(
                    entries.iter().map(|(key, _)| key.clone()).collect(),
                )))
            }
            "values" => {
                if !args.is_empty() {
                    return Err(VmExecutionError::new("dict.values() expects no arguments"));
                }
                Ok(NativeMethodResult::Value(VmValue::List(
                    entries.iter().map(|(_, value)| value.clone()).collect(),
                )))
            }
            "items" => {
                if !args.is_empty() {
                    return Err(VmExecutionError::new("dict.items() expects no arguments"));
                }
                Ok(NativeMethodResult::Value(VmValue::List(
                    entries
                        .iter()
                        .map(|(key, value)| VmValue::Tuple(vec![key.clone(), value.clone()]))
                        .collect(),
                )))
            }
            "get" => match args.as_slice() {
                [key] => Ok(NativeMethodResult::Value(
                    dict_get(&entries, key).unwrap_or(VmValue::None),
                )),
                [key, default] => Ok(NativeMethodResult::Value(
                    dict_get(&entries, key).unwrap_or_else(|| default.clone()),
                )),
                _ => Err(VmExecutionError::new(
                    "dict.get() expects one or two arguments",
                )),
            },
            "pop" => match args.as_slice() {
                [key] => {
                    let mut entries = entries;
                    let value = dict_pop(&mut entries, key).ok_or_else(|| {
                        VmExecutionError::new(format!("missing dict key {}", key.python_repr()))
                    })?;
                    Ok(NativeMethodResult::Mutated {
                        receiver: VmValue::Dict(entries),
                        value,
                    })
                }
                [key, default] => {
                    let mut entries = entries;
                    let value = dict_pop(&mut entries, key).unwrap_or_else(|| default.clone());
                    Ok(NativeMethodResult::Mutated {
                        receiver: VmValue::Dict(entries),
                        value,
                    })
                }
                _ => Err(VmExecutionError::new(
                    "dict.pop() expects one or two arguments",
                )),
            },
            "clear" => {
                if !args.is_empty() {
                    return Err(VmExecutionError::new("dict.clear() expects no arguments"));
                }
                Ok(NativeMethodResult::Mutated {
                    receiver: VmValue::Dict(Vec::new()),
                    value: VmValue::None,
                })
            }
            "copy" => {
                if !args.is_empty() {
                    return Err(VmExecutionError::new("dict.copy() expects no arguments"));
                }
                Ok(NativeMethodResult::Value(VmValue::Dict(entries.clone())))
            }
            other => Err(VmExecutionError::new(format!(
                "unsupported dict method '{}()'",
                other
            ))),
        },
        other => Err(VmExecutionError::new(format!(
            "value of type {} has no native method '{}()'",
            other.type_name(),
            method
        ))),
    }
}

pub(super) fn target_writes_module_scope(
    target: &Value,
    scope: &HashMap<String, VmValue>,
    globals: &HashMap<String, VmValue>,
) -> Result<bool, VmExecutionError> {
    let object = as_object(target, "target")?;
    match required_string(object, "node")? {
        "name" => {
            let id = required_string(object, "id")?;
            Ok(!scope.contains_key(id) && globals.contains_key(id))
        }
        "subscript" => target_writes_module_scope(required_value(object, "value")?, scope, globals),
        _ => Ok(false),
    }
}

pub(super) fn builtin_ordered_values(args: Vec<VmValue>) -> Result<Vec<VmValue>, VmExecutionError> {
    if args.len() == 1 {
        iterate_value(&args[0])
    } else {
        Ok(args)
    }
}

pub(super) fn sorted_values(values: Vec<VmValue>) -> Result<Vec<VmValue>, VmExecutionError> {
    let mut ordered = Vec::with_capacity(values.len());
    for value in values {
        let mut insert_at = ordered.len();
        for (index, existing) in ordered.iter().enumerate() {
            if compare_vm_values(&value, existing)? == std::cmp::Ordering::Less {
                insert_at = index;
                break;
            }
        }
        ordered.insert(insert_at, value);
    }
    Ok(ordered)
}

pub(super) fn compare_vm_values(
    left: &VmValue,
    right: &VmValue,
) -> Result<std::cmp::Ordering, VmExecutionError> {
    match (left, right) {
        (VmValue::DateTime(left), VmValue::DateTime(right)) => Ok(left.value.cmp(&right.value)),
        (VmValue::TimeDelta(left), VmValue::TimeDelta(right)) => {
            Ok(left.raw_seconds.cmp(&right.raw_seconds))
        }
        (VmValue::Bool(left), VmValue::Bool(right)) => Ok(left.cmp(right)),
        (VmValue::Decimal(left), VmValue::Decimal(right)) => Ok(left.scaled.cmp(&right.scaled)),
        (VmValue::Decimal(left), right) => {
            Ok(left.scaled.cmp(&VmDecimal::from_vm_value(right)?.scaled))
        }
        (left, VmValue::Decimal(right)) => {
            Ok(VmDecimal::from_vm_value(left)?.scaled.cmp(&right.scaled))
        }
        (VmValue::Bool(left), VmValue::Int(right)) => {
            Ok(BigInt::from(if *left { 1 } else { 0 }).cmp(right))
        }
        (VmValue::Int(left), VmValue::Bool(right)) => {
            Ok(left.cmp(&BigInt::from(if *right { 1 } else { 0 })))
        }
        (VmValue::Bool(left), VmValue::Float(right)) => (if *left { 1.0 } else { 0.0 })
            .partial_cmp(right)
            .ok_or_else(|| VmExecutionError::new("cannot compare NaN values")),
        (VmValue::Float(left), VmValue::Bool(right)) => left
            .partial_cmp(&(if *right { 1.0 } else { 0.0 }))
            .ok_or_else(|| VmExecutionError::new("cannot compare NaN values")),
        (VmValue::Int(left), VmValue::Int(right)) => Ok(left.cmp(right)),
        (VmValue::Float(left), VmValue::Float(right)) => left
            .partial_cmp(right)
            .ok_or_else(|| VmExecutionError::new("cannot compare NaN values")),
        (VmValue::Int(left), VmValue::Float(right)) => bigint_to_f64(left, "left int operand")?
            .partial_cmp(right)
            .ok_or_else(|| VmExecutionError::new("cannot compare NaN values")),
        (VmValue::Float(left), VmValue::Int(right)) => left
            .partial_cmp(&bigint_to_f64(right, "right int operand")?)
            .ok_or_else(|| VmExecutionError::new("cannot compare NaN values")),
        (VmValue::String(left), VmValue::String(right)) => Ok(left.cmp(right)),
        (left, right) if bytes_like_data(left).is_some() && bytes_like_data(right).is_some() => {
            Ok(compare_bytes_like(
                bytes_like_data(left).expect("checked above"),
                bytes_like_data(right).expect("checked above"),
            ))
        }
        (left, right) => Err(VmExecutionError::new(format!(
            "values {} and {} are not order-comparable",
            left.type_name(),
            right.type_name()
        ))),
    }
}

pub(super) fn compare_numeric_values(
    left: &VmValue,
    right: &VmValue,
) -> Result<Option<std::cmp::Ordering>, VmExecutionError> {
    let left_numeric = matches!(
        left,
        VmValue::Bool(_) | VmValue::Int(_) | VmValue::Float(_) | VmValue::Decimal(_)
    );
    let right_numeric = matches!(
        right,
        VmValue::Bool(_) | VmValue::Int(_) | VmValue::Float(_) | VmValue::Decimal(_)
    );
    if !left_numeric || !right_numeric {
        return Ok(None);
    }

    match (left, right) {
        (VmValue::Bool(left), VmValue::Bool(right)) => Ok(Some(left.cmp(right))),
        (VmValue::Bool(_), _)
        | (_, VmValue::Bool(_))
        | (VmValue::Decimal(_), _)
        | (_, VmValue::Decimal(_))
        | (VmValue::Int(_), VmValue::Int(_))
        | (VmValue::Float(_), VmValue::Float(_))
        | (VmValue::Int(_), VmValue::Float(_))
        | (VmValue::Float(_), VmValue::Int(_)) => Ok(Some(compare_vm_values(left, right)?)),
        _ => Ok(None),
    }
}

pub(super) fn vm_values_equal(left: &VmValue, right: &VmValue) -> Result<bool, VmExecutionError> {
    if let Some(ordering) = compare_numeric_values(left, right)? {
        return Ok(ordering == std::cmp::Ordering::Equal);
    }

    match (left, right) {
        (VmValue::Set(left), VmValue::Set(right))
        | (VmValue::Set(left), VmValue::FrozenSet(right))
        | (VmValue::FrozenSet(left), VmValue::Set(right))
        | (VmValue::FrozenSet(left), VmValue::FrozenSet(right)) => set_values_equal(left, right),
        (VmValue::List(left), VmValue::List(right))
        | (VmValue::Tuple(left), VmValue::Tuple(right)) => {
            if left.len() != right.len() {
                return Ok(false);
            }
            for (left_item, right_item) in left.iter().zip(right.iter()) {
                if !vm_values_equal(left_item, right_item)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        (VmValue::Dict(left), VmValue::Dict(right)) => {
            if left.len() != right.len() {
                return Ok(false);
            }
            for (left_key, left_value) in left {
                let Some((_, right_value)) = right
                    .iter()
                    .find(|(right_key, _)| vm_values_equal(left_key, right_key).unwrap_or(false))
                else {
                    return Ok(false);
                };
                if !vm_values_equal(left_value, right_value)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        (left, right) if bytes_like_data(left).is_some() && bytes_like_data(right).is_some() => {
            Ok(bytes_like_data(left) == bytes_like_data(right))
        }
        _ => Ok(left == right),
    }
}

pub(super) fn contains_value(
    container: &VmValue,
    needle: &VmValue,
) -> Result<bool, VmExecutionError> {
    match container {
        VmValue::String(value) => match needle {
            VmValue::String(needle) => Ok(value.contains(needle)),
            _ => Err(VmExecutionError::new(
                "string membership requires a string needle",
            )),
        },
        VmValue::Bytes(value) | VmValue::ByteArray(value) => match needle {
            VmValue::Int(_) | VmValue::Bool(_) => Ok(value.contains(&byte_from_value(needle)?)),
            VmValue::Bytes(needle) | VmValue::ByteArray(needle) => {
                if needle.is_empty() {
                    return Ok(true);
                }
                Ok(value.windows(needle.len()).any(|window| window == needle))
            }
            other => Err(VmExecutionError::new(format!(
                "a bytes-like object is required, not '{}'",
                other.type_name()
            ))),
        },
        VmValue::Set(values) | VmValue::FrozenSet(values) => set_contains_value(values, needle),
        VmValue::List(values) | VmValue::Tuple(values) => {
            for item in values {
                if vm_values_equal(item, needle)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        VmValue::Dict(entries) => {
            for (key, _) in entries {
                if vm_values_equal(key, needle)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        other => Err(VmExecutionError::new(format!(
            "membership is not supported for {}",
            other.type_name()
        ))),
    }
}

pub(super) fn iterate_value(value: &VmValue) -> Result<Vec<VmValue>, VmExecutionError> {
    match value {
        VmValue::List(values)
        | VmValue::Tuple(values)
        | VmValue::Set(values)
        | VmValue::FrozenSet(values) => Ok(values.clone()),
        VmValue::Dict(entries) => Ok(entries.iter().map(|(key, _)| key.clone()).collect()),
        VmValue::String(value) => Ok(value
            .chars()
            .map(|ch| VmValue::String(ch.to_string()))
            .collect()),
        VmValue::Bytes(value) | VmValue::ByteArray(value) => {
            Ok(value.iter().copied().map(vm_int).collect())
        }
        other => Err(VmExecutionError::new(format!(
            "value of type {} is not iterable",
            other.type_name()
        ))),
    }
}

pub(super) fn assign_subscript(
    container: VmValue,
    index: &VmValue,
    value: VmValue,
) -> Result<VmValue, VmExecutionError> {
    match container {
        VmValue::List(mut values) => {
            let idx = normalize_sequence_index(index, values.len())?;
            values[idx] = value;
            Ok(VmValue::List(values))
        }
        VmValue::Dict(mut entries) => {
            dict_set(&mut entries, index.clone(), value);
            Ok(VmValue::Dict(entries))
        }
        VmValue::ByteArray(mut bytes) => {
            let idx = normalize_sequence_index(index, bytes.len())?;
            bytes[idx] = byte_from_value(&value)?;
            Ok(VmValue::ByteArray(bytes))
        }
        other => Err(VmExecutionError::new(format!(
            "subscript assignment is not supported for {}",
            other.type_name()
        ))),
    }
}

pub(super) fn subscript_value(
    container: VmValue,
    index: &VmValue,
) -> Result<VmValue, VmExecutionError> {
    match container {
        VmValue::List(values) => {
            let idx = normalize_sequence_index(index, values.len())?;
            Ok(values[idx].clone())
        }
        VmValue::Tuple(values) => {
            let idx = normalize_sequence_index(index, values.len())?;
            Ok(values[idx].clone())
        }
        VmValue::Dict(entries) => dict_get(&entries, index).ok_or_else(|| {
            VmExecutionError::new(format!("missing dict key {}", index.python_repr()))
        }),
        VmValue::String(value) => {
            let chars = value.chars().map(|ch| ch.to_string()).collect::<Vec<_>>();
            let idx = normalize_sequence_index(index, chars.len())?;
            Ok(VmValue::String(chars[idx].clone()))
        }
        VmValue::Bytes(value) | VmValue::ByteArray(value) => bytes_like_index_value(&value, index),
        other => Err(VmExecutionError::new(format!(
            "subscript access is not supported for {}",
            other.type_name()
        ))),
    }
}

pub(super) fn subscript_slice_value(
    container: VmValue,
    lower: Option<BigInt>,
    upper: Option<BigInt>,
    step: Option<BigInt>,
) -> Result<VmValue, VmExecutionError> {
    match container {
        VmValue::List(values) => Ok(VmValue::List(
            slice_positions(values.len(), lower, upper, step)?
                .into_iter()
                .map(|index| values[index].clone())
                .collect(),
        )),
        VmValue::Tuple(values) => Ok(VmValue::Tuple(
            slice_positions(values.len(), lower, upper, step)?
                .into_iter()
                .map(|index| values[index].clone())
                .collect(),
        )),
        VmValue::String(value) => {
            let chars = value.chars().map(|ch| ch.to_string()).collect::<Vec<_>>();
            Ok(VmValue::String(
                slice_positions(chars.len(), lower, upper, step)?
                    .into_iter()
                    .map(|index| chars[index].clone())
                    .collect::<String>(),
            ))
        }
        VmValue::Bytes(value) => slice_bytes_like(value, lower, upper, step, false),
        VmValue::ByteArray(value) => slice_bytes_like(value, lower, upper, step, true),
        other => Err(VmExecutionError::new(format!(
            "slice access is not supported for {}",
            other.type_name()
        ))),
    }
}

pub(super) fn normalize_sequence_index(
    index: &VmValue,
    length: usize,
) -> Result<usize, VmExecutionError> {
    let raw = index.as_bigint()?;
    let length_value = BigInt::from(length);
    let adjusted = if raw.sign() == Sign::Minus {
        &length_value + &raw
    } else {
        raw
    };
    if adjusted.sign() == Sign::Minus || adjusted >= length_value {
        return Err(VmExecutionError::new("sequence index out of bounds"));
    }
    bigint_to_usize(&adjusted, "sequence index")
}

pub(super) fn normalize_sequence_insert_index(
    index: &VmValue,
    length: usize,
) -> Result<usize, VmExecutionError> {
    let raw = index.as_bigint()?;
    let length_value = BigInt::from(length);
    let adjusted = if raw.sign() == Sign::Minus {
        &length_value + &raw
    } else {
        raw
    };
    let clamped = if adjusted.sign() == Sign::Minus {
        BigInt::from(0usize)
    } else if adjusted > length_value {
        length_value
    } else {
        adjusted
    };
    bigint_to_usize(&clamped, "sequence insert index")
}

pub(super) fn normalize_search_bounds(
    length: usize,
    start: Option<&VmValue>,
    end: Option<&VmValue>,
) -> Result<(usize, usize), VmExecutionError> {
    let length_value = BigInt::from(length);
    let normalize =
        |value: Option<&VmValue>, default: &BigInt| -> Result<BigInt, VmExecutionError> {
            let Some(value) = value else {
                return Ok(default.clone());
            };
            let mut raw = value.as_bigint()?;
            if raw.sign() == Sign::Minus {
                raw += &length_value;
            }
            if raw.sign() == Sign::Minus {
                raw = BigInt::zero();
            }
            if raw > length_value {
                raw = length_value.clone();
            }
            Ok(raw)
        };

    let start = normalize(start, &BigInt::zero())?;
    let end = normalize(end, &length_value)?;
    let clamped_end = if start > end { start.clone() } else { end };
    Ok((
        bigint_to_usize(&start, "sequence search start")?,
        bigint_to_usize(&clamped_end, "sequence search end")?,
    ))
}

pub(super) fn slice_positions(
    length: usize,
    lower: Option<BigInt>,
    upper: Option<BigInt>,
    step: Option<BigInt>,
) -> Result<Vec<usize>, VmExecutionError> {
    let length_value = i64::try_from(length)
        .map_err(|_| VmExecutionError::new("sequence length exceeds supported range"))?;
    let step_value = match step {
        Some(value) => bigint_to_i64(&value, "slice step")?,
        None => 1,
    };
    if step_value == 0 {
        return Err(VmExecutionError::new("slice step cannot be zero"));
    }

    let normalize = |value: Option<BigInt>,
                     default: i64,
                     allow_negative_endpoint: bool|
     -> Result<i64, VmExecutionError> {
        let mut raw = match value {
            Some(value) => bigint_to_i64(&value, "slice bound")?,
            None => return Ok(default),
        };
        if raw < 0 {
            raw += length_value;
        }
        if allow_negative_endpoint {
            if raw < -1 {
                raw = -1;
            }
        } else if raw < 0 {
            raw = 0;
        }
        if raw > length_value {
            raw = length_value;
        }
        Ok(raw)
    };

    let mut positions = Vec::new();
    if step_value > 0 {
        let start = normalize(lower, 0, false)?;
        let stop = normalize(upper, length_value, false)?;
        let mut index = start;
        while index < stop {
            positions.push(
                usize::try_from(index)
                    .map_err(|_| VmExecutionError::new("slice position out of bounds"))?,
            );
            index += step_value;
        }
        return Ok(positions);
    }

    let start = normalize(lower, length_value - 1, true)?;
    let stop = normalize(upper, -1, true)?;
    let mut index = start;
    while index > stop {
        positions.push(
            usize::try_from(index)
                .map_err(|_| VmExecutionError::new("slice position out of bounds"))?,
        );
        index += step_value;
    }
    Ok(positions)
}

pub(super) fn dict_set(entries: &mut Vec<(VmValue, VmValue)>, key: VmValue, value: VmValue) {
    if let Some(existing) = entries.iter_mut().find(|(entry_key, _)| *entry_key == key) {
        existing.1 = value;
        return;
    }
    entries.push((key, value));
}

pub(super) fn dict_get(entries: &[(VmValue, VmValue)], key: &VmValue) -> Option<VmValue> {
    entries
        .iter()
        .find(|(entry_key, _)| entry_key == key)
        .map(|(_, value)| value.clone())
}

pub(super) fn dict_pop(entries: &mut Vec<(VmValue, VmValue)>, key: &VmValue) -> Option<VmValue> {
    let index = entries.iter().position(|(entry_key, _)| entry_key == key)?;
    Some(entries.remove(index).1)
}

pub(super) fn substring_by_char_bounds(value: &str, start: usize, end: usize) -> String {
    value
        .chars()
        .skip(start)
        .take(end.saturating_sub(start))
        .collect()
}

pub(super) fn string_match_candidates(value: &VmValue) -> Result<Vec<String>, VmExecutionError> {
    match value {
        VmValue::String(candidate) => Ok(vec![candidate.clone()]),
        VmValue::Tuple(values) => values
            .iter()
            .map(VmValue::as_string)
            .collect::<Result<Vec<_>, _>>(),
        other => Err(VmExecutionError::new(format!(
            "expected str or tuple[str, ...], found {}",
            other.type_name()
        ))),
    }
}

pub(super) fn split_string(
    value: &str,
    separator: Option<&str>,
    maxsplit: Option<usize>,
) -> Result<Vec<String>, VmExecutionError> {
    match separator {
        Some("") => Err(VmExecutionError::new("empty separator")),
        Some(separator) => {
            if matches!(maxsplit, Some(0)) {
                return Ok(vec![value.to_owned()]);
            }
            let mut parts = Vec::new();
            let mut remaining = value;
            let mut splits = 0usize;
            while maxsplit.is_none_or(|limit| splits < limit) {
                let Some(index) = remaining.find(separator) else {
                    break;
                };
                parts.push(remaining[..index].to_owned());
                remaining = &remaining[index + separator.len()..];
                splits += 1;
            }
            parts.push(remaining.to_owned());
            Ok(parts)
        }
        None => {
            let mut remaining = value.trim_start_matches(char::is_whitespace);
            if remaining.is_empty() {
                return Ok(Vec::new());
            }
            if matches!(maxsplit, Some(0)) {
                return Ok(vec![remaining.to_owned()]);
            }

            let mut parts = Vec::new();
            let mut splits = 0usize;
            while !remaining.is_empty() && maxsplit.is_none_or(|limit| splits < limit) {
                let start = remaining
                    .char_indices()
                    .find(|(_, ch)| !ch.is_whitespace())
                    .map(|(index, _)| index)
                    .unwrap_or(remaining.len());
                remaining = &remaining[start..];
                if remaining.is_empty() {
                    break;
                }

                let boundary = remaining
                    .char_indices()
                    .find(|(_, ch)| ch.is_whitespace())
                    .map(|(index, _)| index)
                    .unwrap_or(remaining.len());
                if boundary == remaining.len() {
                    parts.push(remaining.to_owned());
                    return Ok(parts);
                }

                parts.push(remaining[..boundary].to_owned());
                remaining = &remaining[boundary..];
                remaining = remaining.trim_start_matches(char::is_whitespace);
                splits += 1;
            }
            if !remaining.is_empty() {
                parts.push(remaining.to_owned());
            }
            Ok(parts)
        }
    }
}

pub(super) fn type_matches(value: &VmValue, marker: &VmValue) -> bool {
    match marker {
        VmValue::TypeMarker(name) => type_matches_name(value, name),
        VmValue::Builtin(name) => type_matches_name(value, name),
        VmValue::Tuple(markers) => markers.iter().any(|marker| type_matches(value, marker)),
        _ => false,
    }
}

pub(super) fn type_matches_name(value: &VmValue, name: &str) -> bool {
    match name {
        "Any" => true,
        "bool" => matches!(value, VmValue::Bool(_)),
        "int" => matches!(value, VmValue::Int(_)),
        "float" => matches!(value, VmValue::Float(_)),
        "decimal" => matches!(value, VmValue::Decimal(_)),
        "datetime.datetime" => matches!(value, VmValue::DateTime(_)),
        "datetime.timedelta" => matches!(value, VmValue::TimeDelta(_)),
        "str" => matches!(value, VmValue::String(_)),
        "bytes" => matches!(value, VmValue::Bytes(_)),
        "bytearray" => matches!(value, VmValue::ByteArray(_)),
        "list" => matches!(value, VmValue::List(_)),
        "dict" => matches!(value, VmValue::Dict(_)),
        "tuple" => matches!(value, VmValue::Tuple(_)),
        "set" => matches!(value, VmValue::Set(_)),
        "frozenset" => matches!(value, VmValue::FrozenSet(_)),
        _ => false,
    }
}

pub(super) fn issubclass_matches(
    candidate: &VmValue,
    target: &VmValue,
) -> Result<bool, VmExecutionError> {
    let candidate_names = type_marker_names(candidate)?;
    let target_names = type_marker_names(target)?;
    Ok(candidate_names.iter().any(|candidate_name| {
        target_names
            .iter()
            .any(|target_name| subclass_matches_name(candidate_name, target_name))
    }))
}

fn type_marker_names(value: &VmValue) -> Result<Vec<String>, VmExecutionError> {
    match value {
        VmValue::TypeMarker(name) | VmValue::Builtin(name) => Ok(vec![name.clone()]),
        VmValue::Tuple(markers) => markers
            .iter()
            .map(type_marker_names)
            .collect::<Result<Vec<_>, _>>()
            .map(|groups| groups.into_iter().flatten().collect()),
        other => Err(VmExecutionError::new(format!(
            "issubclass() arg 1 must be a class or tuple of classes, got {}",
            other.type_name()
        ))),
    }
}

fn subclass_matches_name(candidate: &str, target: &str) -> bool {
    candidate == target || target == "Any" || matches!((candidate, target), ("bool", "int"))
}

pub(super) fn ascii_render(value: &str) -> String {
    let mut rendered = String::new();
    for ch in value.chars() {
        if ch.is_ascii() {
            rendered.push(ch);
        } else {
            rendered.extend(ch.escape_default());
        }
    }
    rendered
}

pub(super) fn ascii_string_repr(value: &str) -> String {
    let mut rendered = String::from("'");
    for ch in value.chars() {
        match ch {
            '\'' => rendered.push_str("\\'"),
            '\\' => rendered.push_str("\\\\"),
            '\n' => rendered.push_str("\\n"),
            '\r' => rendered.push_str("\\r"),
            '\t' => rendered.push_str("\\t"),
            ch if ch.is_ascii() && !ch.is_ascii_control() => rendered.push(ch),
            ch => {
                let code = u32::from(ch);
                if code <= 0xff {
                    rendered.push_str(&format!("\\x{code:02x}"));
                } else if code <= 0xffff {
                    rendered.push_str(&format!("\\u{code:04x}"));
                } else {
                    rendered.push_str(&format!("\\U{code:08x}"));
                }
            }
        }
    }
    rendered.push('\'');
    rendered
}

pub(super) fn format_integer_builtin(value: &BigInt, radix: u32, prefix: &str) -> String {
    if value.sign() == Sign::Minus {
        format!("-{prefix}{}", (-value).to_str_radix(radix))
    } else {
        format!("{prefix}{}", value.to_str_radix(radix))
    }
}

pub(super) fn round_builtin_value(
    value: &VmValue,
    digits: Option<i32>,
) -> Result<VmValue, VmExecutionError> {
    match value {
        VmValue::Int(number) => Ok(match digits {
            Some(places) if places < 0 => {
                let factor = BigInt::from(10u32).pow(places.unsigned_abs());
                let rounded = round_bigint_to_factor(number, &factor)?;
                VmValue::Int(rounded)
            }
            _ => VmValue::Int(number.clone()),
        }),
        VmValue::Float(number) => Ok(match digits {
            Some(places) => {
                let scale = 10f64.powi(places);
                VmValue::Float((number * scale).round() / scale)
            }
            None => VmValue::Int(f64_to_bigint_trunc(number.round(), "round() input")?),
        }),
        VmValue::Decimal(number) => {
            const DECIMAL_PLACES: u32 = 30;
            Ok(match digits {
                Some(places) => {
                    let exponent = if places >= 0 {
                        DECIMAL_PLACES.saturating_sub(places as u32)
                    } else {
                        DECIMAL_PLACES.saturating_add(places.unsigned_abs())
                    };
                    let factor = BigInt::from(10u32).pow(exponent);
                    let rounded = round_bigint_to_factor(&number.scaled, &factor)?;
                    VmValue::Decimal(VmDecimal::from_scaled(rounded)?)
                }
                None => VmValue::Int(f64_to_bigint_trunc(
                    number.to_f64()?.round(),
                    "round() input",
                )?),
            })
        }
        other => Err(VmExecutionError::new(format!(
            "round() does not support {}",
            other.type_name()
        ))),
    }
}

fn round_bigint_to_factor(value: &BigInt, factor: &BigInt) -> Result<BigInt, VmExecutionError> {
    if factor.is_zero() {
        return Err(VmExecutionError::new("round() factor cannot be zero"));
    }
    let quotient = value / factor;
    let remainder = value % factor;
    let half = factor / BigInt::from(2u32);
    let remainder_abs = if remainder.sign() == Sign::Minus {
        -remainder
    } else {
        remainder
    };
    let adjust = if remainder_abs >= half {
        if value.sign() == Sign::Minus {
            -BigInt::from(1u32)
        } else {
            BigInt::from(1u32)
        }
    } else {
        BigInt::zero()
    };
    Ok((quotient + adjust) * factor)
}

pub(super) fn option_string_value(value: &Option<String>) -> VmValue {
    value
        .as_ref()
        .map(|value| VmValue::String(value.clone()))
        .unwrap_or(VmValue::None)
}

pub(super) fn option_entry_value(value: &Option<(String, String)>) -> VmValue {
    value
        .as_ref()
        .map(|(contract, function)| {
            VmValue::Tuple(vec![
                VmValue::String(contract.clone()),
                VmValue::String(function.clone()),
            ])
        })
        .unwrap_or(VmValue::None)
}

pub(super) fn normalize_event_payload(
    schema: &VmValue,
    payload: VmValue,
) -> Result<(Vec<(String, VmValue)>, Vec<(String, VmValue)>), VmExecutionError> {
    let schema_entries = match schema {
        VmValue::Dict(entries) => entries,
        other => {
            return Err(VmExecutionError::new(format!(
                "event schema must be a dict, got {}",
                other.type_name()
            )))
        }
    };
    let payload_entries = match payload {
        VmValue::Dict(entries) => entries,
        other => {
            return Err(VmExecutionError::new(format!(
                "event payload must be a dict, got {}",
                other.type_name()
            )))
        }
    };

    let mut data_indexed = Vec::new();
    let mut data = Vec::new();

    for (schema_key, schema_value) in schema_entries {
        let key = match schema_key {
            VmValue::String(value) => value.clone(),
            other => {
                return Err(VmExecutionError::new(format!(
                    "event schema keys must be strings, got {}",
                    other.type_name()
                )))
            }
        };
        let value = dict_get(&payload_entries, &VmValue::String(key.clone())).ok_or_else(|| {
            VmExecutionError::new(format!("event payload is missing key '{}'", key))
        })?;
        if event_param_is_indexed(schema_value) {
            data_indexed.push((key, value));
        } else {
            data.push((key, value));
        }
    }

    if payload_entries.len() != data_indexed.len() + data.len() {
        return Err(VmExecutionError::new("event payload has unexpected keys"));
    }

    Ok((data_indexed, data))
}

pub(super) fn event_param_is_indexed(schema_value: &VmValue) -> bool {
    match schema_value {
        VmValue::Dict(entries) => {
            dict_get(entries, &VmValue::String("idx".to_owned())) == Some(VmValue::Bool(true))
        }
        _ => false,
    }
}

pub(super) fn contract_target_label(target: &VmContractTarget) -> &str {
    match target {
        VmContractTarget::StaticImport { module, .. }
        | VmContractTarget::DynamicImport { module }
        | VmContractTarget::LocalHandle { module, .. }
        | VmContractTarget::FactoryCall { module, .. } => module,
    }
}

pub(super) fn normalize_hash_key(value: &VmValue) -> Result<String, VmExecutionError> {
    let normalized = match value {
        VmValue::Tuple(values) => {
            if values.len() > MAX_HASH_DIMENSIONS {
                return Err(VmExecutionError::new(format!(
                    "Too many dimensions ({}) for hash. Max is {MAX_HASH_DIMENSIONS}",
                    values.len()
                )));
            }
            let mut rendered = Vec::new();
            for item in values {
                let part = storage_key_part(item)?;
                rendered.push(part);
            }
            rendered.join(STORAGE_DELIMITER)
        }
        other => storage_key_part(other)?,
    };

    if normalized.len() > MAX_STORAGE_KEY_SIZE {
        return Err(VmExecutionError::new(format!(
            "Key is too long ({}). Max is {MAX_STORAGE_KEY_SIZE}.",
            normalized.len()
        )));
    }

    Ok(normalized)
}

pub(super) fn normalize_hash_prefix(values: &[VmValue]) -> Result<String, VmExecutionError> {
    normalize_hash_key(&VmValue::Tuple(values.to_vec()))
}

pub(super) fn prefix_matches_hash_entry(storage_key: &str, prefix: &str) -> bool {
    prefix.is_empty()
        || storage_key == prefix
        || storage_key.starts_with(&format!("{prefix}{STORAGE_DELIMITER}"))
}

pub(super) fn storage_key_part(value: &VmValue) -> Result<String, VmExecutionError> {
    let rendered = match value {
        VmValue::String(value) => value.clone(),
        VmValue::Int(value) => value.to_string(),
        VmValue::Bool(true) => "True".to_owned(),
        VmValue::Bool(false) => "False".to_owned(),
        VmValue::Float(value) => format!("{value:?}"),
        VmValue::None => "None".to_owned(),
        VmValue::TypeMarker(name) => name.clone(),
        other => other.python_repr(),
    };

    if rendered.contains(STORAGE_DELIMITER) {
        return Err(VmExecutionError::new("Illegal delimiter in key."));
    }
    if rendered.contains(STORAGE_INDEX_SEPARATOR) {
        return Err(VmExecutionError::new("Illegal separator in key."));
    }
    Ok(rendered)
}

pub(super) fn foreign_storage_key(contract: &str, name: &str) -> String {
    format!("{contract}{STORAGE_DELIMITER}{name}")
}

pub(super) fn variable_storage_key(contract: &str, binding: &str) -> String {
    format!("{contract}{STORAGE_INDEX_SEPARATOR}{binding}")
}

pub(super) fn hash_storage_key(
    contract: &str,
    binding: &str,
    key: &VmValue,
) -> Result<String, VmExecutionError> {
    Ok(format!(
        "{}{}{}",
        variable_storage_key(contract, binding),
        STORAGE_DELIMITER,
        normalize_hash_key(key)?
    ))
}

pub(super) fn hash_storage_key_from_normalized(
    contract: &str,
    binding: &str,
    normalized_key: &str,
) -> String {
    format!(
        "{}{}{}",
        variable_storage_key(contract, binding),
        STORAGE_DELIMITER,
        normalized_key
    )
}

pub(super) fn split_foreign_storage_key(key: &str) -> Result<(String, String), VmExecutionError> {
    let Some((contract, binding)) = key.split_once(STORAGE_DELIMITER) else {
        return Err(VmExecutionError::new(format!(
            "invalid foreign storage key '{key}'"
        )));
    };
    Ok((contract.to_owned(), binding.to_owned()))
}

pub(super) fn explicit_syscall_metering_cost(
    syscall_id: &str,
    args: &[VmValue],
    kwargs: &[(String, VmValue)],
) -> Result<Option<u64>, VmExecutionError> {
    match syscall_id {
        "zk.verify_groth16_bn254" => {
            if !kwargs.is_empty() || args.len() != 3 {
                return Err(VmExecutionError::new(
                    "zk.verify_groth16_bn254() expects three positional arguments",
                ));
            }
            let vk_hex = args[0].as_string()?;
            let proof_hex = args[1].as_string()?;
            let public_inputs = as_string_list(&args[2], "public_inputs")?;
            Ok(Some(zk_payload_metering_cost(
                &vk_hex,
                &proof_hex,
                &public_inputs,
            )?))
        }
        "zk.verify_groth16" => {
            if !kwargs.is_empty() || args.len() != 3 {
                return Err(VmExecutionError::new(
                    "zk.verify_groth16() expects three positional arguments",
                ));
            }
            let vk_id = args[0].as_string()?;
            let proof_hex = args[1].as_string()?;
            let public_inputs = as_string_list(&args[2], "public_inputs")?;
            Ok(Some(zk_registry_metering_cost(
                &vk_id,
                &proof_hex,
                &public_inputs,
            )?))
        }
        "zk.shielded_note_append_commitments" => {
            if args.len() != 3 || !kwargs.is_empty() {
                return Err(VmExecutionError::new(
                    "zk.shielded_note_append_commitments() expects three positional arguments",
                ));
            }
            let commitments = as_string_list(&args[2], "commitments")?;
            Ok(Some(250_000 + (commitments.len() as u64 * 500_000)))
        }
        "zk.shielded_command_nullifier_digest" => {
            if args.len() != 1 || !kwargs.is_empty() {
                return Err(VmExecutionError::new(
                    "zk.shielded_command_nullifier_digest() expects one positional argument",
                ));
            }
            let input_nullifiers = as_string_list(&args[0], "input_nullifiers")?;
            Ok(Some(100_000 + (input_nullifiers.len() as u64 * 50_000)))
        }
        "zk.shielded_command_binding" => Ok(Some(100_000)),
        "zk.shielded_command_execution_tag" => Ok(Some(50_000)),
        "zk.shielded_output_payload_hash" => {
            if args.len() != 1 || !kwargs.is_empty() {
                return Err(VmExecutionError::new(
                    "zk.shielded_output_payload_hash() expects one positional argument",
                ));
            }
            let payload_hex = args[0].as_string()?;
            if payload_hex.is_empty() {
                return Ok(Some(0));
            }
            Ok(Some(hex_payload_bytes(&payload_hex)?))
        }
        _ => Ok(None),
    }
}

pub(super) fn as_string_list(
    value: &VmValue,
    label: &str,
) -> Result<Vec<String>, VmExecutionError> {
    match value {
        VmValue::List(values) | VmValue::Tuple(values) => values
            .iter()
            .map(VmValue::as_string)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| VmExecutionError::new(format!("{label} must be a list of strings"))),
        _ => Err(VmExecutionError::new(format!(
            "{label} must be a list of strings"
        ))),
    }
}

pub(super) fn hex_payload_bytes(value: &str) -> Result<u64, VmExecutionError> {
    let Some(payload) = value.strip_prefix("0x") else {
        return Ok(0);
    };
    if payload.len() % 2 != 0 {
        return Ok(0);
    }
    Ok((payload.len() / 2) as u64)
}

pub(super) fn zk_payload_metering_cost(
    vk_hex: &str,
    proof_hex: &str,
    public_inputs: &[String],
) -> Result<u64, VmExecutionError> {
    let payload_bytes = hex_payload_bytes(vk_hex)?
        + hex_payload_bytes(proof_hex)?
        + public_inputs
            .iter()
            .map(|value| hex_payload_bytes(value))
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .sum::<u64>();
    Ok(750_000 + (public_inputs.len() as u64 * 50_000) + (payload_bytes * 50))
}

pub(super) fn zk_registry_metering_cost(
    vk_id: &str,
    proof_hex: &str,
    public_inputs: &[String],
) -> Result<u64, VmExecutionError> {
    let payload_bytes = vk_id.len() as u64
        + hex_payload_bytes(proof_hex)?
        + public_inputs
            .iter()
            .map(|value| hex_payload_bytes(value))
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .sum::<u64>();
    Ok(500_000 + 250_000 + (public_inputs.len() as u64 * 50_000) + (payload_bytes * 25))
}

pub(super) fn resolve_contract_import_arg(
    args: &[VmValue],
    kwargs: &[(String, VmValue)],
) -> Result<String, VmExecutionError> {
    if let Some((_, value)) = kwargs.iter().find(|(key, _)| key == "module") {
        return value.as_string();
    }
    if let Some((_, value)) = kwargs.iter().find(|(key, _)| key == "name") {
        return value.as_string();
    }
    let first = args
        .first()
        .ok_or_else(|| VmExecutionError::new("contract.import expects a module name"))?;
    first.as_string()
}

pub(super) fn positional_value(
    instance: &mut VmInstance,
    args: &[Value],
    index: usize,
    host: &mut dyn VmHost,
) -> Result<Option<VmValue>, VmExecutionError> {
    args.get(index)
        .map(|value| instance.eval_expression(value, &mut instance.globals.clone(), host))
        .transpose()
}

pub(super) fn keyword_value(
    instance: &mut VmInstance,
    keywords: &[Value],
    name: &str,
    host: &mut dyn VmHost,
) -> Result<Option<VmValue>, VmExecutionError> {
    let Some(keyword) = keywords.iter().find(|keyword| {
        as_object(keyword, "keyword")
            .ok()
            .and_then(|object| optional_string(object, "arg"))
            == Some(name)
    }) else {
        return Ok(None);
    };
    let keyword_object = as_object(keyword, "keyword")?;
    instance
        .eval_expression(
            required_value(keyword_object, "value")?,
            &mut instance.globals.clone(),
            host,
        )
        .map(Some)
}

pub(super) fn required_value<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a Value, VmExecutionError> {
    object
        .get(field)
        .ok_or_else(|| VmExecutionError::new(format!("missing field '{field}'")))
}

pub(super) fn required_array<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a [Value], VmExecutionError> {
    object
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| VmExecutionError::new(format!("field '{field}' must be an array")))
}

pub(super) fn required_string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a str, VmExecutionError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| VmExecutionError::new(format!("field '{field}' must be a string")))
}

pub(super) fn optional_string<'a>(object: &'a Map<String, Value>, field: &str) -> Option<&'a str> {
    object.get(field).and_then(Value::as_str)
}

pub(super) fn required_string_value(value: &Value) -> Result<&str, VmExecutionError> {
    value
        .as_str()
        .ok_or_else(|| VmExecutionError::new("value must be a string"))
}

pub(super) fn required_bool(
    object: &Map<String, Value>,
    field: &str,
) -> Result<bool, VmExecutionError> {
    object
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| VmExecutionError::new(format!("field '{field}' must be a bool")))
}

pub(super) fn required_bigint(
    object: &Map<String, Value>,
    field: &str,
) -> Result<BigInt, VmExecutionError> {
    let value = object
        .get(field)
        .ok_or_else(|| VmExecutionError::new(format!("field '{field}' must be an int")))?;
    match value {
        Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                return Ok(BigInt::from(value));
            }
            if let Some(value) = number.as_u64() {
                return Ok(BigInt::from(value));
            }
            BigInt::from_str(&number.to_string())
                .map_err(|_| VmExecutionError::new(format!("field '{field}' must be an int")))
        }
        Value::String(value) => BigInt::from_str(value)
            .map_err(|_| VmExecutionError::new(format!("field '{field}' must be an int"))),
        _ => Err(VmExecutionError::new(format!(
            "field '{field}' must be an int"
        ))),
    }
}

pub(super) fn required_f64(
    object: &Map<String, Value>,
    field: &str,
) -> Result<f64, VmExecutionError> {
    object
        .get(field)
        .and_then(Value::as_f64)
        .ok_or_else(|| VmExecutionError::new(format!("field '{field}' must be a float")))
}

pub(super) fn as_object<'a>(
    value: &'a Value,
    label: &str,
) -> Result<&'a Map<String, Value>, VmExecutionError> {
    value.as_object().ok_or_else(|| {
        VmExecutionError::new(format!(
            "{label} must be an object, got {}",
            serde_json::to_string(value).unwrap_or_else(|_| "<unserializable>".to_owned())
        ))
    })
}

#[cfg(test)]
mod signature_security_tests {
    use super::*;

    #[test]
    fn crypto_verify_rejects_small_order_identity_forgery() {
        let identity = format!("01{}", "00".repeat(31));
        let signature = format!("{}{}", identity, "00".repeat(32));
        let result = crypto_ed25519_verify(
            vec![
                VmValue::String(identity),
                VmValue::String("xian parity test".into()),
                VmValue::String(signature),
            ],
            vec![],
        )
        .unwrap();
        assert!(matches!(result, VmValue::Bool(false)));
    }

    #[test]
    fn crypto_verify_accepts_rfc8032_vector() {
        let result = crypto_ed25519_verify(
            vec![
                VmValue::String(
                    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a".into(),
                ),
                VmValue::String(String::new()),
                VmValue::String(
                    concat!(
                        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb",
                        "8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
                    )
                    .into(),
                ),
            ],
            vec![],
        )
        .unwrap();
        assert!(matches!(result, VmValue::Bool(true)));
    }
}
