use crate::{validate_module_ir, FunctionIr, ModuleIr};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use num_bigint::{BigInt, Sign};
use num_traits::{Num, Signed, ToPrimitive, Zero};
use serde_json::{Map, Value};
use sha2::Digest as Sha2Digest;
use sha2::Sha256;
use sha3::Sha3_256;
use std::collections::{HashMap, HashSet};
use std::env;
use std::str::FromStr;

const STORAGE_DELIMITER: &str = ":";
const STORAGE_INDEX_SEPARATOR: &str = ".";
const MAX_HASH_DIMENSIONS: usize = 16;
const MAX_STORAGE_KEY_SIZE: usize = 1024;
pub(crate) const MAX_SEQUENCE_LENGTH: usize = 1024 * 128;
pub(crate) const MAX_BINARY_ALLOCATION_BYTES: usize = 1024 * 128;
pub(crate) const MAX_INTEGER_BITS: u64 = (MAX_BINARY_ALLOCATION_BYTES as u64) * 8;
pub(crate) const MAX_INT_STRING_CHARS: usize = 8192;
pub(crate) const MAX_MODULAR_POW_EXPONENT_BITS: u64 = 8192;
pub(crate) const VM_GAS_CALL_DISPATCH: u64 = 5_000;
const VM_GAS_EVENT_EMIT: u64 = 8_000;
const VM_GAS_VARIABLE_GET: u64 = 1_280;
const VM_GAS_VARIABLE_SET: u64 = 5_120;
const VM_GAS_HASH_SCAN: u64 = 4_096;
const VM_GAS_FUNCTION_ENTRY_COMPLEXITY_FLOOR: u64 = 40;
const VM_GAS_FUNCTION_ENTRY_EXCESS_NODE: u64 = 150;
const VM_GAS_LOOP_ITERATION: u64 = 96;
const VM_GAS_STMT_ASSIGN: u64 = 64;
const VM_GAS_STMT_STORAGE_SET: u64 = 5_120;
const VM_GAS_STMT_STORAGE_MUTATE: u64 = 5_120;
const VM_GAS_STMT_AUG_ASSIGN: u64 = 96;
const VM_GAS_STMT_RETURN: u64 = 32;
const VM_GAS_STMT_EXPR: u64 = 32;
const VM_GAS_STMT_IF: u64 = 96;
const VM_GAS_STMT_WHILE: u64 = 96;
const VM_GAS_STMT_FOR: u64 = 96;
const VM_GAS_STMT_ASSERT: u64 = 96;
const VM_GAS_STMT_RAISE: u64 = 96;
const VM_GAS_STMT_BREAK: u64 = 32;
const VM_GAS_STMT_CONTINUE: u64 = 32;
const VM_GAS_STMT_PASS: u64 = 32;
const VM_GAS_EXPR_NAME: u64 = 64;
const VM_GAS_EXPR_CONSTANT: u64 = 32;
const VM_GAS_EXPR_LIST: u64 = 128;
const VM_GAS_EXPR_LIST_COMP: u64 = 224;
const VM_GAS_EXPR_DICT_COMP: u64 = 288;
const VM_GAS_EXPR_TUPLE: u64 = 128;
const VM_GAS_EXPR_DICT: u64 = 608;
const VM_GAS_EXPR_ATTRIBUTE: u64 = 96;
const VM_GAS_EXPR_SUBSCRIPT: u64 = 96;
const VM_GAS_EXPR_STORAGE_GET: u64 = 1_280;
const VM_GAS_EXPR_COMPARE: u64 = 96;
const VM_GAS_EXPR_BOOL_OP: u64 = 96;
const VM_GAS_EXPR_BINARY_OP: u64 = 96;
const VM_GAS_EXPR_UNARY_OP: u64 = 64;
const VM_GAS_EXPR_IF_EXPR: u64 = 96;
const VM_GAS_EXPR_F_STRING: u64 = 96;
const VM_GAS_EXPR_FORMATTED_VALUE: u64 = 96;

#[path = "foreign_storage.rs"]
mod foreign_storage;
#[path = "interpreter_support.rs"]
mod support;
use crate::values::*;
use support::*;

const SUBMISSION_CONTRACT: &str = "submission";
const SUBMISSION_ONLY_SYSCALLS: [&str; 3] = [
    "contract.deploy",
    "contract.set_owner",
    "contract.set_developer",
];

fn vm_trace_enabled(flag: &str) -> bool {
    env::var_os(flag).is_some()
}

#[cfg(feature = "python-extension")]
pub(crate) fn vm_variable_storage_key(contract: &str, binding: &str) -> String {
    variable_storage_key(contract, binding)
}

#[cfg(feature = "python-extension")]
pub(crate) fn vm_hash_storage_key(
    contract: &str,
    binding: &str,
    key: &VmValue,
) -> Result<String, VmExecutionError> {
    hash_storage_key(contract, binding, key)
}

fn vm_statement_gas_cost(
    node: &str,
    _object: &Map<String, Value>,
) -> Result<u64, VmExecutionError> {
    Ok(match node {
        "assign" => VM_GAS_STMT_ASSIGN,
        "storage_set" => VM_GAS_STMT_STORAGE_SET,
        "storage_mutate" => VM_GAS_STMT_STORAGE_MUTATE,
        "aug_assign" => VM_GAS_STMT_AUG_ASSIGN,
        "return" => VM_GAS_STMT_RETURN,
        "expr" => VM_GAS_STMT_EXPR,
        "if" => VM_GAS_STMT_IF,
        "while" => VM_GAS_STMT_WHILE,
        "for" => VM_GAS_STMT_FOR,
        "assert" => VM_GAS_STMT_ASSERT,
        "raise" => VM_GAS_STMT_RAISE,
        "break" => VM_GAS_STMT_BREAK,
        "continue" => VM_GAS_STMT_CONTINUE,
        "pass" => VM_GAS_STMT_PASS,
        other => {
            return Err(VmExecutionError::new(format!(
                "unsupported statement node '{other}'"
            )))
        }
    })
}

fn vm_expression_gas_cost(
    node: &str,
    object: &Map<String, Value>,
) -> Result<u64, VmExecutionError> {
    Ok(match node {
        "name" => VM_GAS_EXPR_NAME,
        "constant" => VM_GAS_EXPR_CONSTANT,
        "list" => VM_GAS_EXPR_LIST,
        "list_comp" => VM_GAS_EXPR_LIST_COMP,
        "dict_comp" => VM_GAS_EXPR_DICT_COMP,
        "tuple" => VM_GAS_EXPR_TUPLE,
        "dict" => VM_GAS_EXPR_DICT,
        "attribute" => VM_GAS_EXPR_ATTRIBUTE,
        "subscript" => VM_GAS_EXPR_SUBSCRIPT,
        "storage_get" => VM_GAS_EXPR_STORAGE_GET,
        "slice" => VM_GAS_EXPR_SUBSCRIPT,
        "call" => VM_GAS_CALL_DISPATCH,
        "compare" => {
            let comparisons = required_array(object, "operators")?.len().max(1) as u64;
            VM_GAS_EXPR_COMPARE * comparisons
        }
        "bool_op" => {
            let branches = required_array(object, "values")?
                .len()
                .saturating_sub(1)
                .max(1) as u64;
            VM_GAS_EXPR_BOOL_OP * branches
        }
        "bin_op" => VM_GAS_EXPR_BINARY_OP,
        "unary_op" => VM_GAS_EXPR_UNARY_OP,
        "if_expr" => VM_GAS_EXPR_IF_EXPR,
        "f_string" => {
            let segments = required_array(object, "values")?.len().max(1) as u64;
            VM_GAS_EXPR_F_STRING * segments
        }
        "formatted_value" => VM_GAS_EXPR_FORMATTED_VALUE,
        other => {
            return Err(VmExecutionError::new(format!(
                "unsupported expression node '{other}'"
            )))
        }
    })
}

fn charge_storage_read(
    host: &mut dyn VmHost,
    key: &str,
    value: &VmValue,
) -> Result<(), VmExecutionError> {
    host.charge_storage_read(key, value)
}

fn collect_target_names(target: &Value, names: &mut Vec<String>) -> Result<(), VmExecutionError> {
    let object = as_object(target, "target")?;
    match required_string(object, "node")? {
        "name" => {
            names.push(required_string(object, "id")?.to_owned());
            Ok(())
        }
        "tuple_target" | "list_target" => {
            for element in required_array(object, "elements")? {
                collect_target_names(element, names)?;
            }
            Ok(())
        }
        other => Err(VmExecutionError::new(format!(
            "unsupported comprehension target '{other}'"
        ))),
    }
}

fn capture_target_bindings(
    target: &Value,
    scope: &HashMap<String, VmValue>,
) -> Result<Vec<(String, Option<VmValue>)>, VmExecutionError> {
    let mut names = Vec::new();
    collect_target_names(target, &mut names)?;
    Ok(names
        .into_iter()
        .map(|name| {
            let previous = scope.get(&name).cloned();
            (name, previous)
        })
        .collect())
}

fn restore_target_bindings(
    scope: &mut HashMap<String, VmValue>,
    previous: Vec<(String, Option<VmValue>)>,
) {
    for (name, value) in previous {
        if let Some(value) = value {
            scope.insert(name, value);
        } else {
            scope.remove(&name);
        }
    }
}

fn ir_node_complexity(value: &Value) -> u64 {
    match value {
        Value::Object(object) => {
            let self_cost = if object.contains_key("node") { 1 } else { 0 };
            self_cost + object.values().map(ir_node_complexity).sum::<u64>()
        }
        Value::Array(items) => items.iter().map(ir_node_complexity).sum(),
        _ => 0,
    }
}

fn function_entry_gas_cost(function: &FunctionIr) -> u64 {
    let mut complexity = 0;
    for parameter in &function.parameters {
        if let Some(default) = &parameter.default {
            complexity += ir_node_complexity(default);
        }
    }
    complexity += function.body.iter().map(ir_node_complexity).sum::<u64>();
    complexity
        .saturating_sub(VM_GAS_FUNCTION_ENTRY_COMPLEXITY_FLOOR)
        .saturating_mul(VM_GAS_FUNCTION_ENTRY_EXCESS_NODE)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TypeAnnotation {
    base: String,
    args: Vec<TypeAnnotation>,
}

impl TypeAnnotation {
    fn source(&self) -> String {
        if self.args.is_empty() {
            return self.base.clone();
        }
        format!(
            "{}[{}]",
            self.base,
            self.args
                .iter()
                .map(TypeAnnotation::source)
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

fn parse_type_annotation(annotation: &str) -> Option<TypeAnnotation> {
    let trimmed = annotation.trim();
    if trimmed.is_empty() {
        return None;
    }

    let Some(open_index) = trimmed.find('[') else {
        if trimmed.contains([']', ',']) {
            return None;
        }
        return Some(TypeAnnotation {
            base: trimmed.to_owned(),
            args: Vec::new(),
        });
    };

    let base = trimmed[..open_index].trim();
    if base.is_empty() {
        return None;
    }

    let mut depth = 0i32;
    let mut close_index = None;
    for (index, ch) in trimmed
        .char_indices()
        .skip_while(|(index, _)| *index < open_index)
    {
        match ch {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth < 0 {
                    return None;
                }
                if depth == 0 {
                    close_index = Some(index);
                    break;
                }
            }
            _ => {}
        }
    }

    let close_index = close_index?;
    if close_index != trimmed.len() - 1 {
        return None;
    }

    let args = split_type_annotation_args(&trimmed[open_index + 1..close_index])?;
    Some(TypeAnnotation {
        base: base.to_owned(),
        args,
    })
}

fn split_type_annotation_args(input: &str) -> Option<Vec<TypeAnnotation>> {
    let mut args = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;

    for (index, ch) in input.char_indices() {
        match ch {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth < 0 {
                    return None;
                }
            }
            ',' if depth == 0 => {
                args.push(parse_type_annotation(input[start..index].trim())?);
                start = index + ch.len_utf8();
            }
            _ => {}
        }
    }

    if depth != 0 {
        return None;
    }

    let tail = input[start..].trim();
    if tail.is_empty() {
        return None;
    }
    args.push(parse_type_annotation(tail)?);
    Some(args)
}

fn export_typecheck_enabled(function: &FunctionIr) -> bool {
    let Some(decorator) = &function.decorator else {
        return false;
    };
    if decorator.name != "export" {
        return false;
    }

    decorator.keywords.iter().any(|keyword| {
        let Some(object) = keyword.as_object() else {
            return false;
        };
        if object.get("arg").and_then(Value::as_str) != Some("typecheck") {
            return false;
        }
        let Some(value) = object.get("value").and_then(Value::as_object) else {
            return false;
        };
        value.get("node").and_then(Value::as_str) == Some("constant")
            && value.get("value_type").and_then(Value::as_str) == Some("bool")
            && value.get("value").and_then(Value::as_bool) == Some(true)
    })
}

fn typecheck_error(label: &str, annotation: &TypeAnnotation, value: &VmValue) -> VmExecutionError {
    let message = format!(
        "{label} must be {}, got {}!",
        annotation_label(annotation),
        value_typecheck_name(value)
    );
    VmExecutionError::new(format!("TypeError({message:?})"))
}

fn annotation_label(annotation: &TypeAnnotation) -> String {
    if !annotation.args.is_empty() {
        return annotation.source();
    }
    match annotation.base.as_str() {
        "Any" => "Any".to_owned(),
        "datetime.datetime" => "datetime.datetime".to_owned(),
        "datetime.timedelta" => "datetime.timedelta".to_owned(),
        "set" => "set".to_owned(),
        "frozenset" => "frozenset".to_owned(),
        "int" => "<class 'int'>".to_owned(),
        "bytes" => "<class 'bytes'>".to_owned(),
        "bytearray" => "<class 'bytearray'>".to_owned(),
        base => format!("<class '{base}'>"),
    }
}

fn value_typecheck_name(value: &VmValue) -> &'static str {
    match value {
        VmValue::None => "NoneType",
        VmValue::Decimal(_) => "ContractingDecimal",
        VmValue::DateTime(_) => "Datetime",
        VmValue::TimeDelta(_) => "Timedelta",
        other => other.type_name(),
    }
}

fn check_function_arguments(
    function: &FunctionIr,
    scope: &HashMap<String, VmValue>,
) -> Result<(), VmExecutionError> {
    for parameter in &function.parameters {
        let Some(annotation) = &parameter.annotation else {
            continue;
        };
        let Some(value) = scope.get(&parameter.name) else {
            continue;
        };
        let parsed = parse_type_annotation(annotation).ok_or_else(|| {
            VmExecutionError::new(format!("unsupported type annotation '{annotation}'"))
        })?;
        check_typed_value(value, &parsed, &format!("Argument '{}'", parameter.name))?;
    }
    Ok(())
}

fn check_function_return(function: &FunctionIr, value: &VmValue) -> Result<(), VmExecutionError> {
    let Some(annotation) = &function.returns else {
        return Ok(());
    };
    let parsed = parse_type_annotation(annotation).ok_or_else(|| {
        VmExecutionError::new(format!("unsupported type annotation '{annotation}'"))
    })?;
    check_typed_value(value, &parsed, "Return value")
}

fn check_typed_value(
    value: &VmValue,
    annotation: &TypeAnnotation,
    label: &str,
) -> Result<(), VmExecutionError> {
    if annotation.base == "Any" {
        return Ok(());
    }

    match annotation.base.as_str() {
        "list" => {
            let VmValue::List(items) = value else {
                return Err(typecheck_error(label, annotation, value));
            };
            if let Some(item_annotation) = annotation.args.first() {
                for (index, item) in items.iter().enumerate() {
                    check_typed_value(item, item_annotation, &format!("{label}[{index}]"))?;
                }
            }
            Ok(())
        }
        "dict" => {
            let VmValue::Dict(entries) = value else {
                return Err(typecheck_error(label, annotation, value));
            };
            if annotation.args.len() >= 2 {
                let key_annotation = &annotation.args[0];
                let value_annotation = &annotation.args[1];
                for (key, item) in entries {
                    check_typed_value(key, key_annotation, &format!("{label} key"))?;
                    check_typed_value(
                        item,
                        value_annotation,
                        &format!("{label}[{}]", typecheck_dict_key_repr(key)),
                    )?;
                }
            }
            Ok(())
        }
        "set" => {
            let VmValue::Set(items) = value else {
                return Err(typecheck_error(label, annotation, value));
            };
            if let Some(item_annotation) = annotation.args.first() {
                for (index, item) in items.iter().enumerate() {
                    check_typed_value(item, item_annotation, &format!("{label}[{index}]"))?;
                }
            }
            Ok(())
        }
        "frozenset" => {
            let VmValue::FrozenSet(items) = value else {
                return Err(typecheck_error(label, annotation, value));
            };
            if let Some(item_annotation) = annotation.args.first() {
                for (index, item) in items.iter().enumerate() {
                    check_typed_value(item, item_annotation, &format!("{label}[{index}]"))?;
                }
            }
            Ok(())
        }
        "bool" => {
            if matches!(value, VmValue::Bool(_)) {
                Ok(())
            } else {
                Err(typecheck_error(label, annotation, value))
            }
        }
        "int" => {
            if matches!(value, VmValue::Int(_)) {
                Ok(())
            } else {
                Err(typecheck_error(label, annotation, value))
            }
        }
        "float" => {
            if matches!(
                value,
                VmValue::Int(_) | VmValue::Float(_) | VmValue::Decimal(_)
            ) {
                Ok(())
            } else {
                Err(typecheck_error(label, annotation, value))
            }
        }
        "str" => {
            if matches!(value, VmValue::String(_)) {
                Ok(())
            } else {
                Err(typecheck_error(label, annotation, value))
            }
        }
        "bytes" => {
            if matches!(value, VmValue::Bytes(_)) {
                Ok(())
            } else {
                Err(typecheck_error(label, annotation, value))
            }
        }
        "bytearray" => {
            if matches!(value, VmValue::ByteArray(_)) {
                Ok(())
            } else {
                Err(typecheck_error(label, annotation, value))
            }
        }
        "datetime.datetime" => {
            if matches!(value, VmValue::DateTime(_)) {
                Ok(())
            } else {
                Err(typecheck_error(label, annotation, value))
            }
        }
        "datetime.timedelta" => {
            if matches!(value, VmValue::TimeDelta(_)) {
                Ok(())
            } else {
                Err(typecheck_error(label, annotation, value))
            }
        }
        _ => Err(VmExecutionError::new(format!(
            "unsupported type annotation '{}'",
            annotation.source()
        ))),
    }
}

fn typecheck_dict_key_repr(key: &VmValue) -> String {
    match key {
        VmValue::String(value) => ascii_string_repr(value),
        other => other.python_repr(),
    }
}

pub trait VmHost {
    fn charge_execution_cost(&mut self, _cost: u64) -> Result<(), VmExecutionError> {
        Ok(())
    }

    fn charge_storage_read(
        &mut self,
        _key: &str,
        _value: &VmValue,
    ) -> Result<(), VmExecutionError> {
        Ok(())
    }

    fn charge_storage_write(
        &mut self,
        _key: &str,
        _value: &VmValue,
    ) -> Result<(), VmExecutionError> {
        Ok(())
    }

    fn record_storage_write(
        &mut self,
        _key: &str,
        _value: &VmValue,
    ) -> Result<(), VmExecutionError> {
        Ok(())
    }

    fn read_recorded_storage_write(
        &mut self,
        _key: &str,
    ) -> Result<Option<VmValue>, VmExecutionError> {
        Ok(None)
    }

    fn emit_event(&mut self, _event: VmEvent) -> Result<(), VmExecutionError> {
        Ok(())
    }

    fn read_variable(
        &mut self,
        _contract: &str,
        _binding: &str,
    ) -> Result<Option<VmValue>, VmExecutionError> {
        Ok(None)
    }

    fn read_hash(
        &mut self,
        _contract: &str,
        _binding: &str,
        _key: &VmValue,
    ) -> Result<Option<VmValue>, VmExecutionError> {
        Ok(None)
    }

    fn scan_hash_entries(
        &mut self,
        _contract: &str,
        _binding: &str,
        _prefix: &str,
    ) -> Result<Vec<(String, VmValue)>, VmExecutionError> {
        Ok(Vec::new())
    }

    /// Return canonically ordered entries, charged before they are retained.
    /// Native hosts override this to consume persistent state incrementally.
    fn scan_hash_entries_metered(
        &mut self,
        contract: &str,
        binding: &str,
        prefix: &str,
    ) -> Result<Vec<(String, VmValue)>, VmExecutionError> {
        let mut entries = self.scan_hash_entries(contract, binding, prefix)?;
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let mut budget = crate::storage_scan::ScanBudget::default();
        for (suffix, value) in &entries {
            let key = hash_storage_key_from_normalized(contract, binding, suffix);
            self.charge_storage_read(&key, value)?;
            budget.observe(&key, value)?;
        }
        Ok(entries)
    }

    fn load_owner(&mut self, _contract: &str) -> Result<Option<String>, VmExecutionError> {
        Ok(None)
    }

    fn call_contract(&mut self, call: VmContractCall) -> Result<VmValue, VmExecutionError> {
        Err(VmExecutionError::unsupported(format!(
            "host does not support contract call {}.{}",
            contract_target_label(&call.target),
            call.function
        )))
    }

    fn handle_syscall(
        &mut self,
        syscall_id: &str,
        _args: Vec<VmValue>,
        _kwargs: Vec<(String, VmValue)>,
    ) -> Result<VmValue, VmExecutionError> {
        Err(VmExecutionError::unsupported(format!(
            "unsupported host syscall '{syscall_id}'"
        )))
    }
}

#[derive(Debug, Clone, PartialEq)]
struct VariableState {
    default_value: VmValue,
    value: Option<VmValue>,
    foreign_key: Option<String>,
    snapshot_local: bool,
    dirty: bool,
}

#[derive(Debug, Clone, PartialEq)]
struct HashState {
    default_value: VmValue,
    entries: HashMap<String, VmValue>,
    foreign_key: Option<String>,
    snapshot_local: bool,
    dirty_entries: HashSet<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VmVariableSnapshot {
    pub binding: String,
    pub default_value: VmValue,
    pub value: Option<VmValue>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VmHashSnapshot {
    pub binding: String,
    pub default_value: VmValue,
    pub entries: HashMap<String, VmValue>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VmModuleStorageSnapshot {
    pub contract_name: String,
    pub variables: Vec<VmVariableSnapshot>,
    pub hashes: Vec<VmHashSnapshot>,
}

#[derive(Debug, Clone, PartialEq)]
enum ControlFlow {
    Next,
    Return(VmValue),
    Break,
    Continue,
}

#[derive(Debug, Clone, PartialEq)]
enum NativeMethodResult {
    Value(VmValue),
    Mutated { receiver: VmValue, value: VmValue },
}

#[derive(Debug, Clone, PartialEq)]
enum ResolvedAssignmentTarget {
    Name(String),
    Subscript {
        parent: Box<ResolvedAssignmentTarget>,
        container: VmValue,
        index: VmValue,
    },
    Unsupported(String),
}

pub struct VmInstance {
    module: ModuleIr,
    functions: HashMap<String, FunctionIr>,
    imports: HashMap<String, String>,
    globals: HashMap<String, VmValue>,
    variables: HashMap<String, VariableState>,
    hashes: HashMap<String, HashState>,
    context: VmExecutionContext,
}

impl VmInstance {
    pub fn new(module: ModuleIr, context: VmExecutionContext) -> Result<Self, VmExecutionError> {
        Self::new_with_host(module, context, &mut NoopHost {})
    }

    pub fn new_with_host(
        module: ModuleIr,
        context: VmExecutionContext,
        host: &mut dyn VmHost,
    ) -> Result<Self, VmExecutionError> {
        validate_module_ir(&module).map_err(|err| VmExecutionError::new(err.to_string()))?;

        let functions = module
            .functions
            .iter()
            .cloned()
            .map(|function| (function.name.clone(), function))
            .collect::<HashMap<_, _>>();
        let imports = module
            .imports
            .iter()
            .map(|import| {
                (
                    import
                        .alias
                        .clone()
                        .unwrap_or_else(|| import.module.clone()),
                    import.module.clone(),
                )
            })
            .collect::<HashMap<_, _>>();

        let mut instance = Self {
            module,
            functions,
            imports,
            globals: HashMap::new(),
            variables: HashMap::new(),
            hashes: HashMap::new(),
            context,
        };

        if instance.context.this.is_none() {
            instance.context.this = Some(instance.module.module_name.clone());
        }

        for (binding, module) in instance.imports.clone() {
            instance.globals.insert(
                binding,
                VmValue::ContractHandle(VmContractHandle {
                    module,
                    origin: "static_import".to_owned(),
                }),
            );
        }

        let declarations = instance.module.global_declarations.clone();
        for declaration in &declarations {
            instance.apply_global_declaration(declaration, host)?;
        }

        let module_body = instance.module.module_body.clone();
        if !module_body.is_empty() {
            let mut scope = instance.globals.clone();
            let flow = instance.execute_block(&module_body, &mut scope, host)?;
            if flow != ControlFlow::Next {
                return Err(VmExecutionError::new(
                    "module body cannot return or break execution",
                ));
            }
            instance.globals = scope;
        }

        Ok(instance)
    }

    pub fn context(&self) -> &VmExecutionContext {
        &self.context
    }

    pub fn context_mut(&mut self) -> &mut VmExecutionContext {
        &mut self.context
    }

    pub fn has_export(&self, name: &str) -> bool {
        self.functions
            .get(name)
            .map(|function| function.visibility == "export")
            .unwrap_or(false)
    }

    pub fn storage_snapshot(&self) -> VmModuleStorageSnapshot {
        VmModuleStorageSnapshot {
            contract_name: self.module.module_name.clone(),
            variables: self
                .variables
                .iter()
                .filter(|(_, state)| state.snapshot_local && state.dirty)
                .map(|(binding, state)| VmVariableSnapshot {
                    binding: binding.clone(),
                    default_value: state.default_value.clone(),
                    value: state.value.clone(),
                })
                .collect(),
            hashes: self
                .hashes
                .iter()
                .filter(|(_, state)| state.snapshot_local)
                .map(|(binding, state)| VmHashSnapshot {
                    binding: binding.clone(),
                    default_value: state.default_value.clone(),
                    entries: state
                        .entries
                        .iter()
                        .filter(|(key, _)| state.dirty_entries.contains(*key))
                        .map(|(key, value)| (key.clone(), value.clone()))
                        .collect(),
                })
                .filter(|snapshot| !snapshot.entries.is_empty())
                .collect(),
        }
    }

    pub fn apply_foreign_snapshot(&mut self, snapshot: &VmModuleStorageSnapshot) {
        for variable in &snapshot.variables {
            self.variables.insert(
                foreign_storage_key(&snapshot.contract_name, &variable.binding),
                VariableState {
                    default_value: variable.default_value.clone(),
                    value: variable.value.clone(),
                    foreign_key: None,
                    snapshot_local: false,
                    dirty: false,
                },
            );
        }
        for hash in &snapshot.hashes {
            self.hashes.insert(
                foreign_storage_key(&snapshot.contract_name, &hash.binding),
                HashState {
                    default_value: hash.default_value.clone(),
                    entries: hash.entries.clone(),
                    foreign_key: None,
                    snapshot_local: false,
                    dirty_entries: HashSet::new(),
                },
            );
        }
    }

    pub fn set_foreign_variable(
        &mut self,
        foreign_contract: &str,
        foreign_name: &str,
        value: VmValue,
    ) {
        let key = foreign_storage_key(foreign_contract, foreign_name);
        self.variables
            .entry(key)
            .and_modify(|state| state.value = Some(value.clone()))
            .or_insert(VariableState {
                default_value: VmValue::None,
                value: Some(value),
                foreign_key: None,
                snapshot_local: false,
                dirty: false,
            });
    }

    pub fn set_foreign_hash_value(
        &mut self,
        foreign_contract: &str,
        foreign_name: &str,
        key: &VmValue,
        value: VmValue,
    ) -> Result<(), VmExecutionError> {
        let storage_key = foreign_storage_key(foreign_contract, foreign_name);
        let normalized = normalize_hash_key(key)?;
        self.hashes
            .entry(storage_key)
            .and_modify(|state| {
                state.entries.insert(normalized.clone(), value.clone());
            })
            .or_insert_with(|| {
                let mut entries = HashMap::new();
                entries.insert(normalized, value);
                HashState {
                    default_value: VmValue::None,
                    entries,
                    foreign_key: None,
                    snapshot_local: false,
                    dirty_entries: HashSet::new(),
                }
            });
        Ok(())
    }

    pub fn get_variable(&self, binding: &str) -> Option<VmValue> {
        self.variables.get(binding).map(|state| {
            state
                .value
                .clone()
                .unwrap_or_else(|| state.default_value.clone())
        })
    }

    pub fn peek_variable_value(&self, binding: &str) -> Option<VmValue> {
        self.variables
            .get(binding)
            .and_then(|state| state.value.clone())
    }

    pub fn get_hash_value(
        &self,
        binding: &str,
        key: &VmValue,
    ) -> Result<Option<VmValue>, VmExecutionError> {
        let normalized = normalize_hash_key(key)?;
        Ok(self.hashes.get(binding).map(|state| {
            state
                .entries
                .get(&normalized)
                .cloned()
                .unwrap_or_else(|| state.default_value.clone())
        }))
    }

    pub fn peek_hash_entry(
        &self,
        binding: &str,
        key: &VmValue,
    ) -> Result<Option<VmValue>, VmExecutionError> {
        let normalized = normalize_hash_key(key)?;
        Ok(self
            .hashes
            .get(binding)
            .and_then(|state| state.entries.get(&normalized).cloned()))
    }

    pub fn set_variable_state(
        &mut self,
        binding: &str,
        value: VmValue,
    ) -> Result<(), VmExecutionError> {
        self.variable_set(binding, value)
    }

    pub fn set_hash_value(
        &mut self,
        binding: &str,
        key: &VmValue,
        value: VmValue,
    ) -> Result<(), VmExecutionError> {
        self.hash_set(binding, key, value)
    }

    pub fn call_function(
        &mut self,
        host: &mut dyn VmHost,
        name: &str,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
    ) -> Result<VmValue, VmExecutionError> {
        let trace_calls = vm_trace_enabled("XIAN_VM_TRACE_CALLS");
        if trace_calls {
            eprintln!(
                "[vm-call] enter {}.{} caller={} signer={}",
                self.module.module_name,
                name,
                option_string_value(&self.context.caller).python_repr(),
                option_string_value(&self.context.signer).python_repr(),
            );
        }
        let previous_entry = self.context.entry.clone();
        let injected_entry = if self.context.entry.is_none() {
            self.context.entry = Some((self.module.module_name.clone(), name.to_owned()));
            true
        } else {
            false
        };
        let result = self.call_named_function(host, name, args, kwargs);
        if injected_entry {
            self.context.entry = previous_entry;
        }
        if trace_calls {
            match &result {
                Ok(value) => eprintln!(
                    "[vm-call] exit {}.{} -> {} ({})",
                    self.module.module_name,
                    name,
                    value.python_repr(),
                    value.type_name(),
                ),
                Err(err) => eprintln!(
                    "[vm-call] error {}.{} -> {}",
                    self.module.module_name, name, err
                ),
            }
        }
        result
    }

    fn read_subscript(
        &mut self,
        value: VmValue,
        index: &VmValue,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        if let VmValue::ForeignStorageRef(reference) = &value {
            return foreign_storage::read_hash(reference, index, host);
        }
        subscript_value(value, index)
    }

    fn eval_slice_subscript(
        &mut self,
        value: VmValue,
        slice: &Map<String, Value>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let lower = match slice.get("lower") {
            Some(Value::Null) | None => None,
            Some(lower) => Some(self.eval_expression(lower, scope, host)?.as_bigint()?),
        };
        let upper = match slice.get("upper") {
            Some(Value::Null) | None => None,
            Some(upper) => Some(self.eval_expression(upper, scope, host)?.as_bigint()?),
        };
        let step = match slice.get("step") {
            Some(Value::Null) | None => None,
            Some(step) => Some(self.eval_expression(step, scope, host)?.as_bigint()?),
        };
        subscript_slice_value(value, lower, upper, step)
    }

    fn apply_global_declaration(
        &mut self,
        declaration: &Value,
        host: &mut dyn VmHost,
    ) -> Result<(), VmExecutionError> {
        let object = as_object(declaration, "global declaration")?;
        let node = required_string(object, "node")?;
        match node {
            "storage_decl" => {
                let binding = required_string(object, "name")?.to_owned();
                let storage_type = required_string(object, "storage_type")?.to_owned();
                let args = required_array(object, "args")?;
                let keywords = required_array(object, "keywords")?;

                match storage_type.as_str() {
                    "Variable" | "ForeignVariable" => {
                        let state = self.build_variable_state(
                            &binding,
                            &storage_type,
                            args,
                            keywords,
                            host,
                        )?;
                        self.variables.insert(binding.clone(), state);
                    }
                    "Hash" | "ForeignHash" => {
                        let state =
                            self.build_hash_state(&binding, &storage_type, args, keywords, host)?;
                        self.hashes.insert(binding.clone(), state);
                    }
                    other => {
                        return Err(VmExecutionError::new(format!(
                            "unsupported storage declaration type '{other}'"
                        )))
                    }
                }

                self.globals.insert(
                    binding.clone(),
                    VmValue::StorageRef(VmStorageRef {
                        binding,
                        storage_type,
                    }),
                );
                Ok(())
            }
            "event_decl" => {
                let binding = required_string(object, "name")?.to_owned();
                let event_name = required_string(object, "event_name")?.to_owned();
                let params = self.eval_expression(
                    required_value(object, "params")?,
                    &mut self.globals.clone(),
                    host,
                )?;
                self.globals.insert(
                    binding.clone(),
                    VmValue::EventRef(Box::new(VmEventDefinition {
                        binding,
                        event_name,
                        params,
                    })),
                );
                Ok(())
            }
            "binding_decl" => {
                let binding = required_string(object, "name")?.to_owned();
                let value = self.eval_expression(
                    required_value(object, "value")?,
                    &mut self.globals.clone(),
                    host,
                )?;
                self.globals.insert(binding, value);
                Ok(())
            }
            other => Err(VmExecutionError::new(format!(
                "unsupported global declaration node '{other}'"
            ))),
        }
    }

    fn build_variable_state(
        &mut self,
        binding: &str,
        storage_type: &str,
        args: &[Value],
        keywords: &[Value],
        host: &mut dyn VmHost,
    ) -> Result<VariableState, VmExecutionError> {
        let default_value = if storage_type == "Variable" {
            keyword_value(self, keywords, "default_value", host)?.unwrap_or(VmValue::None)
        } else {
            VmValue::None
        };

        let foreign_key = if storage_type == "ForeignVariable" {
            let foreign_contract = keyword_value(self, keywords, "foreign_contract", host)?
                .or_else(|| positional_value(self, args, 2, host).ok().flatten())
                .ok_or_else(|| {
                    VmExecutionError::new(format!(
                        "ForeignVariable '{binding}' requires foreign_contract"
                    ))
                })?
                .as_string()?;
            let foreign_name = keyword_value(self, keywords, "foreign_name", host)?
                .or_else(|| positional_value(self, args, 3, host).ok().flatten())
                .ok_or_else(|| {
                    VmExecutionError::new(format!(
                        "ForeignVariable '{binding}' requires foreign_name"
                    ))
                })?
                .as_string()?;
            Some(foreign_storage_key(&foreign_contract, &foreign_name))
        } else {
            None
        };

        Ok(VariableState {
            default_value,
            value: None,
            foreign_key,
            snapshot_local: storage_type == "Variable",
            dirty: false,
        })
    }

    fn build_hash_state(
        &mut self,
        binding: &str,
        storage_type: &str,
        args: &[Value],
        keywords: &[Value],
        host: &mut dyn VmHost,
    ) -> Result<HashState, VmExecutionError> {
        let default_value =
            keyword_value(self, keywords, "default_value", host)?.unwrap_or(VmValue::None);
        let foreign_key = if storage_type == "ForeignHash" {
            let foreign_contract = keyword_value(self, keywords, "foreign_contract", host)?
                .or_else(|| positional_value(self, args, 2, host).ok().flatten())
                .ok_or_else(|| {
                    VmExecutionError::new(format!(
                        "ForeignHash '{binding}' requires foreign_contract"
                    ))
                })?
                .as_string()?;
            let foreign_name = keyword_value(self, keywords, "foreign_name", host)?
                .or_else(|| positional_value(self, args, 3, host).ok().flatten())
                .ok_or_else(|| {
                    VmExecutionError::new(format!("ForeignHash '{binding}' requires foreign_name"))
                })?
                .as_string()?;
            Some(foreign_storage_key(&foreign_contract, &foreign_name))
        } else {
            None
        };

        Ok(HashState {
            default_value,
            entries: HashMap::new(),
            foreign_key,
            snapshot_local: storage_type == "Hash",
            dirty_entries: HashSet::new(),
        })
    }

    fn call_named_function(
        &mut self,
        host: &mut dyn VmHost,
        name: &str,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
    ) -> Result<VmValue, VmExecutionError> {
        let function = self
            .functions
            .get(name)
            .cloned()
            .ok_or_else(|| VmExecutionError::new(format!("unknown function '{name}'")))?;
        host.charge_execution_cost(function_entry_gas_cost(&function))?;
        let mut scope = self.bind_function_arguments(&function, args, kwargs, host)?;
        let typecheck = export_typecheck_enabled(&function);
        if typecheck {
            check_function_arguments(&function, &scope)?;
        }
        let result = match self.execute_block(&function.body, &mut scope, host)? {
            ControlFlow::Next => Ok(VmValue::None),
            ControlFlow::Return(value) => Ok(value),
            ControlFlow::Break | ControlFlow::Continue => Err(VmExecutionError::new(format!(
                "function '{name}' leaked loop control"
            ))),
        }?;
        if typecheck {
            check_function_return(&function, &result)?;
        }
        Ok(result)
    }

    fn call_callable_value(
        &mut self,
        host: &mut dyn VmHost,
        callee: VmValue,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
    ) -> Result<VmValue, VmExecutionError> {
        match callee {
            VmValue::Builtin(name) => self.call_builtin(host, &name, args, kwargs),
            VmValue::FunctionRef(name) => self.call_named_function(host, &name, args, kwargs),
            other => Err(VmExecutionError::new(format!(
                "value of type {} is not callable",
                other.type_name()
            ))),
        }
    }

    fn bind_function_arguments(
        &mut self,
        function: &FunctionIr,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        host: &mut dyn VmHost,
    ) -> Result<HashMap<String, VmValue>, VmExecutionError> {
        let type_error = |message: String| VmExecutionError::new(format!("TypeError({message:?})"));
        let mut remaining_args = args;
        let mut remaining_kwargs = HashMap::new();
        for (key, value) in kwargs {
            if remaining_kwargs.insert(key.clone(), value).is_some() {
                return Err(type_error(format!(
                    "__{}() got multiple values for keyword argument '{}'",
                    function.name, key
                )));
            }
        }
        let mut bound = HashMap::new();
        let mut vararg_name = None;
        let mut kwarg_name = None;

        for parameter in &function.parameters {
            match parameter.kind.as_str() {
                "positional_or_keyword" => {
                    if !remaining_args.is_empty() {
                        if remaining_kwargs.contains_key(&parameter.name) {
                            return Err(type_error(format!(
                                "__{}() got multiple values for keyword argument '{}'",
                                function.name, parameter.name
                            )));
                        }
                        bound.insert(parameter.name.clone(), remaining_args.remove(0));
                        continue;
                    }
                    if let Some(value) = remaining_kwargs.remove(&parameter.name) {
                        bound.insert(parameter.name.clone(), value);
                        continue;
                    }
                    if let Some(default) = &parameter.default {
                        let value = self.eval_expression(default, &mut bound.clone(), host)?;
                        bound.insert(parameter.name.clone(), value);
                        continue;
                    }
                    return Err(type_error(format!(
                        "missing required argument '{}'",
                        parameter.name
                    )));
                }
                "keyword_only" => {
                    if let Some(value) = remaining_kwargs.remove(&parameter.name) {
                        bound.insert(parameter.name.clone(), value);
                        continue;
                    }
                    if let Some(default) = &parameter.default {
                        let value = self.eval_expression(default, &mut bound.clone(), host)?;
                        bound.insert(parameter.name.clone(), value);
                        continue;
                    }
                    return Err(type_error(format!(
                        "missing required keyword-only argument '{}'",
                        parameter.name
                    )));
                }
                "vararg" => {
                    vararg_name = Some(parameter.name.clone());
                }
                "kwarg" => {
                    kwarg_name = Some(parameter.name.clone());
                }
                other => {
                    return Err(VmExecutionError::new(format!(
                        "unsupported parameter kind '{other}'"
                    )))
                }
            }
        }

        if let Some(name) = vararg_name {
            bound.insert(name, VmValue::Tuple(remaining_args));
            remaining_args = Vec::new();
        }

        if !remaining_args.is_empty() {
            return Err(type_error(format!(
                "too many positional arguments for '{}'",
                function.name
            )));
        }

        if let Some(name) = kwarg_name {
            let mut entries = Vec::new();
            for (key, value) in remaining_kwargs.drain() {
                entries.push((VmValue::String(key), value));
            }
            bound.insert(name, VmValue::Dict(entries));
        } else if let Some(unexpected) = remaining_kwargs.keys().next() {
            return Err(type_error(format!(
                "unexpected keyword argument '{unexpected}'"
            )));
        }

        Ok(bound)
    }

    fn execute_block(
        &mut self,
        statements: &[Value],
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<ControlFlow, VmExecutionError> {
        for statement in statements {
            let flow = self.execute_statement(statement, scope, host)?;
            if flow != ControlFlow::Next {
                return Ok(flow);
            }
        }
        Ok(ControlFlow::Next)
    }

    fn execute_statement(
        &mut self,
        statement: &Value,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<ControlFlow, VmExecutionError> {
        let object = as_object(statement, "statement")?;
        let node = required_string(object, "node")?;
        host.charge_execution_cost(vm_statement_gas_cost(node, object)?)?;
        let trace_statements = vm_trace_enabled("XIAN_VM_TRACE_STATEMENTS");
        if trace_statements {
            eprintln!("[vm-stmt] {} {}", self.module.module_name, node);
        }
        match node {
            "assign" => {
                let value = self.eval_expression(required_value(object, "value")?, scope, host)?;
                for target in required_array(object, "targets")? {
                    self.assign_target(target, value.clone(), scope, host, false)?;
                }
                Ok(ControlFlow::Next)
            }
            "storage_set" => {
                let binding = required_string(object, "binding")?;
                let key = self.eval_expression(required_value(object, "key")?, scope, host)?;
                let value = self.eval_expression(required_value(object, "value")?, scope, host)?;
                self.hash_set(binding, &key, value.clone())?;
                let storage_key = hash_storage_key(&self.module.module_name, binding, &key)?;
                host.record_storage_write(&storage_key, &value)?;
                host.charge_storage_write(&storage_key, &value)?;
                Ok(ControlFlow::Next)
            }
            "storage_mutate" => {
                let binding = required_string(object, "binding")?;
                let key = self.eval_expression(required_value(object, "key")?, scope, host)?;
                let current = self.hash_get(binding, &key, host)?;
                let operand =
                    self.eval_expression(required_value(object, "value")?, scope, host)?;
                let operator = required_string(object, "operator")?;
                let result = apply_binary_operator(operator, current, operand)?;
                self.hash_set(binding, &key, result.clone())?;
                let storage_key = hash_storage_key(&self.module.module_name, binding, &key)?;
                host.record_storage_write(&storage_key, &result)?;
                host.charge_storage_write(&storage_key, &result)?;
                Ok(ControlFlow::Next)
            }
            "aug_assign" => {
                let target = required_value(object, "target")?;
                let target_object = as_object(target, "target")?;
                let target_node = required_string(target_object, "node")?;
                let (resolved, current) = if matches!(target_node, "name" | "subscript") {
                    let (resolved, current) =
                        self.resolve_assignment_target(target, scope, host, true)?;
                    let current = current.ok_or_else(|| {
                        VmExecutionError::new("augmented assignment target has no value")
                    })?;
                    (Some(resolved), current)
                } else {
                    (None, self.eval_target_value(target, scope, host)?)
                };
                let operand =
                    self.eval_expression(required_value(object, "value")?, scope, host)?;
                let result =
                    apply_binary_operator(required_string(object, "operator")?, current, operand)?;
                if let Some(resolved) = resolved {
                    self.assign_resolved_target(resolved, result, scope, false)
                } else {
                    self.assign_target(target, result, scope, host, false)
                }?;
                Ok(ControlFlow::Next)
            }
            "return" => {
                let value = match object.get("value") {
                    Some(Value::Null) | None => VmValue::None,
                    Some(value) => self.eval_expression(value, scope, host)?,
                };
                Ok(ControlFlow::Return(value))
            }
            "expr" => {
                self.eval_expression(required_value(object, "value")?, scope, host)?;
                Ok(ControlFlow::Next)
            }
            "if" => {
                let test = self.eval_expression(required_value(object, "test")?, scope, host)?;
                if test.truthy() {
                    self.execute_block(required_array(object, "body")?, scope, host)
                } else {
                    self.execute_block(required_array(object, "orelse")?, scope, host)
                }
            }
            "while" => self.execute_while_loop(object, scope, host),
            "for" => self.execute_for_loop(object, scope, host),
            "assert" => {
                let test = self.eval_expression(required_value(object, "test")?, scope, host)?;
                if !test.truthy() {
                    let error_repr = object
                        .get("message")
                        .filter(|value| !value.is_null())
                        .map(|value| self.eval_expression(value, scope, host))
                        .transpose()?
                        .map(|message: VmValue| {
                            let rendered = match message {
                                VmValue::String(value) => {
                                    let escaped = value.replace('\\', "\\\\").replace('\'', "\\'");
                                    format!("'{escaped}'")
                                }
                                other => other.python_repr(),
                            };
                            format!("AssertionError({rendered})")
                        })
                        .unwrap_or_else(|| "AssertionError()".to_owned());
                    return Err(VmExecutionError::new(error_repr));
                }
                Ok(ControlFlow::Next)
            }
            "raise" => {
                if let Some(cause) = object.get("cause") {
                    if !cause.is_null() {
                        let _ = self.eval_expression(cause, scope, host)?;
                    }
                }
                let error_repr = match object.get("exception") {
                    None | Some(Value::Null) => {
                        "RuntimeError('No active exception to reraise')".to_owned()
                    }
                    Some(exception) => match self.eval_expression(exception, scope, host)? {
                        VmValue::Exception(value) => value.python_repr(),
                        VmValue::Builtin(name)
                            if matches!(
                                name.as_str(),
                                "Exception" | "RuntimeError" | "ValueError" | "TypeError"
                            ) =>
                        {
                            format!("{name}()")
                        }
                        other => {
                            return Err(VmExecutionError::new(format!(
                                "TypeError('exceptions must derive from BaseException, got {}')",
                                other.type_name()
                            )))
                        }
                    },
                };
                Err(VmExecutionError::new(error_repr))
            }
            "break" => Ok(ControlFlow::Break),
            "continue" => Ok(ControlFlow::Continue),
            "pass" => Ok(ControlFlow::Next),
            other => Err(VmExecutionError::new(format!(
                "unsupported statement node '{other}'"
            ))),
        }
    }

    fn execute_for_loop(
        &mut self,
        object: &Map<String, Value>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<ControlFlow, VmExecutionError> {
        let iter_value = self.eval_expression(required_value(object, "iter")?, scope, host)?;
        let values = iterate_value(&iter_value)?;
        let body = required_array(object, "body")?;
        let orelse = required_array(object, "orelse")?;

        let mut broke = false;
        for item in values {
            host.charge_execution_cost(VM_GAS_LOOP_ITERATION)?;
            self.assign_target(required_value(object, "target")?, item, scope, host, false)?;
            match self.execute_block(body, scope, host)? {
                ControlFlow::Next => {}
                ControlFlow::Continue => continue,
                ControlFlow::Break => {
                    broke = true;
                    break;
                }
                ControlFlow::Return(value) => return Ok(ControlFlow::Return(value)),
            }
        }

        if !broke {
            self.execute_block(orelse, scope, host)
        } else {
            Ok(ControlFlow::Next)
        }
    }

    fn execute_while_loop(
        &mut self,
        object: &Map<String, Value>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<ControlFlow, VmExecutionError> {
        let body = required_array(object, "body")?;
        let orelse = required_array(object, "orelse")?;

        let mut broke = false;
        while self
            .eval_expression(required_value(object, "test")?, scope, host)?
            .truthy()
        {
            host.charge_execution_cost(VM_GAS_LOOP_ITERATION)?;
            match self.execute_block(body, scope, host)? {
                ControlFlow::Next => {}
                ControlFlow::Continue => continue,
                ControlFlow::Break => {
                    broke = true;
                    break;
                }
                ControlFlow::Return(value) => return Ok(ControlFlow::Return(value)),
            }
        }

        if !broke {
            self.execute_block(orelse, scope, host)
        } else {
            Ok(ControlFlow::Next)
        }
    }

    fn assign_target(
        &mut self,
        target: &Value,
        value: VmValue,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
        module_scope: bool,
    ) -> Result<(), VmExecutionError> {
        let object = as_object(target, "target")?;
        match required_string(object, "node")? {
            "name" => {
                let id = required_string(object, "id")?.to_owned();
                if module_scope {
                    self.globals.insert(id.clone(), value.clone());
                }
                scope.insert(id, value);
                Ok(())
            }
            "tuple_target" | "list_target" => {
                let items = match value {
                    VmValue::List(items) | VmValue::Tuple(items) => items,
                    other => {
                        return Err(VmExecutionError::new(format!(
                            "cannot destructure {}",
                            other.type_name()
                        )))
                    }
                };
                let elements = required_array(object, "elements")?;
                if elements.len() != items.len() {
                    return Err(VmExecutionError::new(
                        "destructuring target count does not match value length",
                    ));
                }
                for (target, item) in elements.iter().zip(items.into_iter()) {
                    self.assign_target(target, item, scope, host, module_scope)?;
                }
                Ok(())
            }
            "subscript" => {
                let (resolved, current) =
                    self.resolve_assignment_target(target, scope, host, false)?;
                debug_assert!(current.is_none());
                self.assign_resolved_target(resolved, value, scope, module_scope)
            }
            "attribute" => Err(VmExecutionError::new(
                "attribute assignment is not yet supported in xian-vm-core",
            )),
            other => Err(VmExecutionError::new(format!(
                "unsupported assignment target '{other}'"
            ))),
        }
    }

    // Capture every container and index in an assignment path once. Native VM values are
    // immutable, so writeback rebuilds the captured path instead of re-evaluating expressions.
    fn resolve_assignment_target(
        &mut self,
        target: &Value,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
        load_value: bool,
    ) -> Result<(ResolvedAssignmentTarget, Option<VmValue>), VmExecutionError> {
        let object = as_object(target, "target")?;
        match required_string(object, "node")? {
            "name" => {
                let current = if load_value {
                    Some(self.eval_expression(target, scope, host)?)
                } else {
                    None
                };
                Ok((
                    ResolvedAssignmentTarget::Name(required_string(object, "id")?.to_owned()),
                    current,
                ))
            }
            "subscript" => {
                if load_value {
                    host.charge_execution_cost(vm_expression_gas_cost("subscript", object)?)?;
                }
                let value_expression = required_value(object, "value")?;
                let value_object = as_object(value_expression, "subscript target value")?;
                let value_node = required_string(value_object, "node")?;
                let (parent, container) = if matches!(value_node, "name" | "subscript") {
                    let (parent, container) =
                        self.resolve_assignment_target(value_expression, scope, host, true)?;
                    let container = container.ok_or_else(|| {
                        VmExecutionError::new("subscript assignment container has no value")
                    })?;
                    (parent, container)
                } else {
                    (
                        ResolvedAssignmentTarget::Unsupported(value_node.to_owned()),
                        self.eval_expression(value_expression, scope, host)?,
                    )
                };
                let index = self.eval_expression(required_value(object, "slice")?, scope, host)?;
                let current = if load_value {
                    Some(self.read_subscript(container.clone(), &index, host)?)
                } else {
                    None
                };
                Ok((
                    ResolvedAssignmentTarget::Subscript {
                        parent: Box::new(parent),
                        container,
                        index,
                    },
                    current,
                ))
            }
            other => Err(VmExecutionError::new(format!(
                "unsupported assignment target '{other}'"
            ))),
        }
    }

    fn assign_resolved_target(
        &mut self,
        target: ResolvedAssignmentTarget,
        value: VmValue,
        scope: &mut HashMap<String, VmValue>,
        module_scope: bool,
    ) -> Result<(), VmExecutionError> {
        match target {
            ResolvedAssignmentTarget::Name(id) => {
                if module_scope {
                    self.globals.insert(id.clone(), value.clone());
                }
                scope.insert(id, value);
                Ok(())
            }
            ResolvedAssignmentTarget::Subscript {
                parent,
                container,
                index,
            } => {
                if matches!(container, VmValue::ForeignStorageRef(_)) {
                    return Err(VmExecutionError::new("cannot write to foreign storage"));
                }
                let updated = assign_subscript(container, &index, value)?;
                self.assign_resolved_target(*parent, updated, scope, module_scope)
            }
            ResolvedAssignmentTarget::Unsupported(node) => Err(VmExecutionError::new(format!(
                "unsupported assignment target '{node}'"
            ))),
        }
    }

    fn eval_target_value(
        &mut self,
        target: &Value,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let object = as_object(target, "target")?;
        match required_string(object, "node")? {
            "name" | "attribute" | "subscript" => self.eval_expression(target, scope, host),
            other => Err(VmExecutionError::new(format!(
                "unsupported aug-assign target '{other}'"
            ))),
        }
    }

    fn eval_expression(
        &mut self,
        expression: &Value,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let object = as_object(expression, "expression")?;
        let node = required_string(object, "node")?;
        host.charge_execution_cost(vm_expression_gas_cost(node, object)?)?;
        match node {
            "name" => self.eval_name(object, scope),
            "constant" => self.eval_constant(object),
            "list" => {
                let mut values = Vec::new();
                for element in required_array(object, "elements")? {
                    values.push(self.eval_expression(element, scope, host)?);
                }
                Ok(VmValue::List(values))
            }
            "list_comp" => self.eval_list_comprehension(object, scope, host),
            "dict_comp" => self.eval_dict_comprehension(object, scope, host),
            "tuple" => {
                let mut values = Vec::new();
                for element in required_array(object, "elements")? {
                    values.push(self.eval_expression(element, scope, host)?);
                }
                Ok(VmValue::Tuple(values))
            }
            "dict" => {
                let mut entries = Vec::new();
                for entry in required_array(object, "entries")? {
                    let entry_object = as_object(entry, "dict entry")?;
                    if let Some(unpack) = entry_object.get("unpack") {
                        let unpacked = self.eval_expression(unpack, scope, host)?;
                        let VmValue::Dict(unpacked_entries) = unpacked else {
                            return Err(VmExecutionError::new(
                                "dict unpacking requires a dict value",
                            ));
                        };
                        for (key, value) in unpacked_entries {
                            entries.push((key, value));
                        }
                    } else {
                        let key = self.eval_expression(
                            required_value(entry_object, "key")?,
                            scope,
                            host,
                        )?;
                        let value = self.eval_expression(
                            required_value(entry_object, "value")?,
                            scope,
                            host,
                        )?;
                        entries.push((key, value));
                    }
                }
                Ok(VmValue::Dict(entries))
            }
            "attribute" => self.eval_attribute(object, scope, host),
            "subscript" => {
                let value = self.eval_expression(required_value(object, "value")?, scope, host)?;
                let slice = required_value(object, "slice")?;
                if let Some(slice_object) = slice.as_object() {
                    if required_string(slice_object, "node")? == "slice" {
                        return self.eval_slice_subscript(value, slice_object, scope, host);
                    }
                }
                let index = self.eval_expression(slice, scope, host)?;
                self.read_subscript(value, &index, host)
            }
            "storage_get" => {
                let binding = required_string(object, "binding")?;
                let key = self.eval_expression(required_value(object, "key")?, scope, host)?;
                self.hash_get(binding, &key, host)
            }
            "slice" => Err(VmExecutionError::new(
                "slice expressions are only supported as subscripts",
            )),
            "call" => self.eval_call(object, scope, host),
            "compare" => self.eval_compare(object, scope, host),
            "bool_op" => self.eval_bool_op(object, scope, host),
            "bin_op" => {
                let left = self.eval_expression(required_value(object, "left")?, scope, host)?;
                let right = self.eval_expression(required_value(object, "right")?, scope, host)?;
                apply_binary_operator(required_string(object, "operator")?, left, right)
            }
            "unary_op" => {
                let operand =
                    self.eval_expression(required_value(object, "operand")?, scope, host)?;
                apply_unary_operator(required_string(object, "operator")?, operand)
            }
            "if_expr" => {
                let test = self.eval_expression(required_value(object, "test")?, scope, host)?;
                if test.truthy() {
                    self.eval_expression(required_value(object, "body")?, scope, host)
                } else {
                    self.eval_expression(required_value(object, "orelse")?, scope, host)
                }
            }
            "f_string" => {
                let mut buffer = String::new();
                for value in required_array(object, "values")? {
                    buffer.push_str(&self.eval_expression(value, scope, host)?.python_repr());
                }
                Ok(VmValue::String(buffer))
            }
            "formatted_value" => {
                if optional_string(object, "conversion").is_some() {
                    return Err(VmExecutionError::new(
                        "f-string conversions are not supported in xian-vm-core",
                    ));
                }
                if object
                    .get("format_spec")
                    .is_some_and(|value| !value.is_null())
                {
                    return Err(VmExecutionError::new(
                        "f-string format specifications are not supported in xian-vm-core",
                    ));
                }
                let value = self.eval_expression(required_value(object, "value")?, scope, host)?;
                Ok(VmValue::String(value.python_repr()))
            }
            other => Err(VmExecutionError::new(format!(
                "unsupported expression node '{other}'"
            ))),
        }
    }

    fn eval_list_comprehension(
        &mut self,
        object: &Map<String, Value>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let element = required_value(object, "element")?;
        let generators = required_array(object, "generators")?;
        let mut results = Vec::new();
        self.eval_list_comprehension_generator(generators, 0, element, scope, host, &mut results)?;
        Ok(VmValue::List(results))
    }

    fn eval_list_comprehension_generator(
        &mut self,
        generators: &[Value],
        index: usize,
        element: &Value,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
        results: &mut Vec<VmValue>,
    ) -> Result<(), VmExecutionError> {
        let generator = as_object(
            generators
                .get(index)
                .ok_or_else(|| VmExecutionError::new("missing list comprehension generator"))?,
            "list comprehension generator",
        )?;
        let target = required_value(generator, "target")?;
        let iter_value = self.eval_expression(required_value(generator, "iter")?, scope, host)?;
        let items = iterate_value(&iter_value)?;
        let previous_bindings = capture_target_bindings(target, scope)?;

        for item in items {
            host.charge_execution_cost(VM_GAS_LOOP_ITERATION)?;
            self.assign_target(target, item, scope, host, false)?;
            let mut allowed = true;
            for condition in required_array(generator, "ifs")? {
                if !self.eval_expression(condition, scope, host)?.truthy() {
                    allowed = false;
                    break;
                }
            }
            if !allowed {
                continue;
            }
            if index + 1 == generators.len() {
                results.push(self.eval_expression(element, scope, host)?);
            } else {
                self.eval_list_comprehension_generator(
                    generators,
                    index + 1,
                    element,
                    scope,
                    host,
                    results,
                )?;
            }
        }

        restore_target_bindings(scope, previous_bindings);
        Ok(())
    }

    fn eval_dict_comprehension(
        &mut self,
        object: &Map<String, Value>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let key = required_value(object, "key")?;
        let value = required_value(object, "value")?;
        let generators = required_array(object, "generators")?;
        let mut results = Vec::new();
        self.eval_dict_comprehension_generator(
            generators,
            0,
            key,
            value,
            scope,
            host,
            &mut results,
        )?;
        Ok(VmValue::Dict(results))
    }

    fn eval_dict_comprehension_generator(
        &mut self,
        generators: &[Value],
        index: usize,
        key: &Value,
        value: &Value,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
        results: &mut Vec<(VmValue, VmValue)>,
    ) -> Result<(), VmExecutionError> {
        let generator = as_object(
            generators
                .get(index)
                .ok_or_else(|| VmExecutionError::new("missing dict comprehension generator"))?,
            "dict comprehension generator",
        )?;
        let target = required_value(generator, "target")?;
        let iter_value = self.eval_expression(required_value(generator, "iter")?, scope, host)?;
        let items = iterate_value(&iter_value)?;
        let previous_bindings = capture_target_bindings(target, scope)?;

        for item in items {
            host.charge_execution_cost(VM_GAS_LOOP_ITERATION)?;
            self.assign_target(target, item, scope, host, false)?;
            let mut allowed = true;
            for condition in required_array(generator, "ifs")? {
                if !self.eval_expression(condition, scope, host)?.truthy() {
                    allowed = false;
                    break;
                }
            }
            if !allowed {
                continue;
            }
            if index + 1 == generators.len() {
                let dict_key = self.eval_expression(key, scope, host)?;
                let dict_value = self.eval_expression(value, scope, host)?;
                dict_set(results, dict_key, dict_value);
            } else {
                self.eval_dict_comprehension_generator(
                    generators,
                    index + 1,
                    key,
                    value,
                    scope,
                    host,
                    results,
                )?;
            }
        }

        restore_target_bindings(scope, previous_bindings);
        Ok(())
    }

    fn eval_name(
        &self,
        object: &Map<String, Value>,
        scope: &HashMap<String, VmValue>,
    ) -> Result<VmValue, VmExecutionError> {
        let id = required_string(object, "id")?;
        if let Some(value) = scope.get(id) {
            return Ok(value.clone());
        }
        if let Some(value) = self.globals.get(id) {
            return Ok(value.clone());
        }
        if self.functions.contains_key(id) {
            return Ok(VmValue::FunctionRef(id.to_owned()));
        }
        if let Some(builtin) = builtin_name_value(id) {
            return Ok(builtin);
        }
        if let Some(host_binding_id) = optional_string(object, "host_binding_id") {
            return self.resolve_host_binding(host_binding_id);
        }
        Err(VmExecutionError::new(format!("unknown name '{id}'")))
    }

    fn eval_constant(&self, object: &Map<String, Value>) -> Result<VmValue, VmExecutionError> {
        match required_string(object, "value_type")? {
            "none" => Ok(VmValue::None),
            "bool" => Ok(VmValue::Bool(required_bool(object, "value")?)),
            "int" => Ok(VmValue::Int(required_bigint(object, "value")?)),
            "float" => {
                let literal = if let Some(literal) = optional_string(object, "literal") {
                    literal.to_owned()
                } else {
                    required_f64(object, "value")?.to_string()
                };
                Ok(VmValue::Decimal(VmDecimal::from_str_literal(&literal)?))
            }
            "str" => Ok(VmValue::String(
                required_string(object, "value")?.to_owned(),
            )),
            "bytes" => Ok(VmValue::Bytes(
                hex::decode(required_string(object, "value")?).map_err(|error| {
                    VmExecutionError::new(format!("invalid bytes constant: {error}"))
                })?,
            )),
            other => Err(VmExecutionError::new(format!(
                "unsupported constant value_type '{other}'"
            ))),
        }
    }

    fn eval_attribute(
        &mut self,
        object: &Map<String, Value>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        if let Some(host_binding_id) = optional_string(object, "host_binding_id") {
            if !self.host_binding_root_is_shadowed(object, scope)? {
                return self.resolve_host_binding(host_binding_id);
            }
        }
        let value = self.eval_expression(required_value(object, "value")?, scope, host)?;
        let attr = required_string(object, "attr")?;
        native_attribute_value(&value, attr)
    }

    fn host_binding_root_is_shadowed(
        &self,
        object: &Map<String, Value>,
        scope: &HashMap<String, VmValue>,
    ) -> Result<bool, VmExecutionError> {
        let Some(root) = ir_root_name(required_value(object, "value")?)? else {
            return Ok(false);
        };
        Ok(scope.contains_key(root) || self.globals.contains_key(root))
    }

    fn resolve_host_binding(&self, host_binding_id: &str) -> Result<VmValue, VmExecutionError> {
        match host_binding_id {
            "numeric.decimal.new" => Ok(VmValue::TypeMarker("decimal".to_owned())),
            "typing.any" => Ok(VmValue::TypeMarker("Any".to_owned())),
            "storage.variable.new" => Ok(VmValue::TypeMarker("Variable".to_owned())),
            "storage.hash.new" => Ok(VmValue::TypeMarker("Hash".to_owned())),
            "storage.foreign_variable.new" => Ok(VmValue::TypeMarker("ForeignVariable".to_owned())),
            "storage.foreign_hash.new" => Ok(VmValue::TypeMarker("ForeignHash".to_owned())),
            "event.log.new" => Ok(VmValue::TypeMarker("LogEvent".to_owned())),
            "module.importlib" => Ok(VmValue::Builtin("importlib".to_owned())),
            "module.hashlib" => Ok(VmValue::Builtin("hashlib".to_owned())),
            "module.crypto" => Ok(VmValue::Builtin("crypto".to_owned())),
            "module.datetime" => Ok(VmValue::Builtin("datetime".to_owned())),
            "module.random" => Ok(VmValue::Builtin("random".to_owned())),
            "module.zk" => Ok(VmValue::Builtin("zk".to_owned())),
            "time.datetime.new" | "time.datetime.strptime" => {
                Ok(VmValue::TypeMarker("datetime.datetime".to_owned()))
            }
            "time.timedelta.new" => Ok(VmValue::TypeMarker("datetime.timedelta".to_owned())),
            "time.seconds" => Ok(VmValue::TimeDelta(VmTimeDelta::new(0, 0, 0, 0, 1)?)),
            "time.minutes" => Ok(VmValue::TimeDelta(VmTimeDelta::new(0, 0, 0, 1, 0)?)),
            "time.hours" => Ok(VmValue::TimeDelta(VmTimeDelta::new(0, 0, 1, 0, 0)?)),
            "time.days" => Ok(VmValue::TimeDelta(VmTimeDelta::new(0, 1, 0, 0, 0)?)),
            "time.weeks" => Ok(VmValue::TimeDelta(VmTimeDelta::new(1, 0, 0, 0, 0)?)),
            "context.caller" => Ok(option_string_value(&self.context.caller)),
            "context.signer" => Ok(option_string_value(&self.context.signer)),
            "context.this" => Ok(option_string_value(&self.context.this)),
            "context.owner" => Ok(option_string_value(&self.context.owner)),
            "context.entry" => Ok(option_entry_value(&self.context.entry)),
            "context.submission_name" => Ok(option_string_value(&self.context.submission_name)),
            "env.now" => Ok(self.context.now.clone()),
            "env.block_num" => Ok(self.context.block_num.clone()),
            "env.block_hash" => Ok(self.context.block_hash.clone()),
            "env.chain_id" => Ok(self.context.chain_id.clone()),
            other => Err(VmExecutionError::new(format!(
                "unsupported host binding '{other}'"
            ))),
        }
    }

    fn eval_call(
        &mut self,
        object: &Map<String, Value>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let args = self.eval_call_arguments(required_array(object, "args")?, scope, host)?;
        let kwargs = self.eval_call_keywords(required_array(object, "keywords")?, scope, host)?;
        let func = required_value(object, "func")?;

        if let Some(syscall_id) = optional_string(object, "syscall_id") {
            return self.eval_syscall(object, syscall_id, args, kwargs, scope, host);
        }

        if let Some(value) =
            self.eval_native_attribute_call(func, args.clone(), kwargs.clone(), scope, host)?
        {
            return Ok(value);
        }

        let callee = self.eval_expression(func, scope, host)?;
        self.call_callable_value(host, callee, args, kwargs)
    }

    fn eval_native_attribute_call(
        &mut self,
        func: &Value,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<Option<VmValue>, VmExecutionError> {
        let func_object = as_object(func, "callable")?;
        if required_string(func_object, "node")? != "attribute"
            || optional_string(func_object, "host_binding_id").is_some()
        {
            return Ok(None);
        }

        let receiver_expr = required_value(func_object, "value")?;
        let receiver_object = as_object(receiver_expr, "native method receiver")?;
        let receiver_node = required_string(receiver_object, "node")?;
        let (resolved_receiver, receiver) = if matches!(receiver_node, "name" | "subscript") {
            let (resolved, receiver) =
                self.resolve_assignment_target(receiver_expr, scope, host, true)?;
            let receiver = receiver
                .ok_or_else(|| VmExecutionError::new("native method receiver has no value"))?;
            (Some(resolved), receiver)
        } else {
            (None, self.eval_expression(receiver_expr, scope, host)?)
        };
        let attr = required_string(func_object, "attr")?;
        if let VmValue::ForeignStorageRef(reference) = &receiver {
            return foreign_storage::call_method(reference, attr, args, kwargs, host).map(Some);
        }
        let result = call_native_method(receiver, attr, args, kwargs)?;
        match result {
            NativeMethodResult::Value(value) => Ok(Some(value)),
            NativeMethodResult::Mutated { receiver, value } => {
                let module_scope = target_writes_module_scope(receiver_expr, scope, &self.globals)?;
                if let Some(resolved) = resolved_receiver {
                    self.assign_resolved_target(resolved, receiver, scope, module_scope)?;
                } else {
                    self.assign_target(receiver_expr, receiver, scope, host, module_scope)?;
                }
                Ok(Some(value))
            }
        }
    }

    fn eval_call_arguments(
        &mut self,
        args: &[Value],
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<Vec<VmValue>, VmExecutionError> {
        let mut values = Vec::new();
        for argument in args {
            values.push(self.eval_expression(argument, scope, host)?);
        }
        Ok(values)
    }

    fn eval_call_keywords(
        &mut self,
        keywords: &[Value],
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<Vec<(String, VmValue)>, VmExecutionError> {
        let mut values = Vec::new();
        for keyword in keywords {
            let keyword_object = as_object(keyword, "keyword")?;
            match keyword_object
                .get("node")
                .and_then(Value::as_str)
                .unwrap_or("keyword")
            {
                "keyword" => values.push((
                    required_string(keyword_object, "arg")?.to_owned(),
                    self.eval_expression(required_value(keyword_object, "value")?, scope, host)?,
                )),
                "keyword_unpack" => {
                    let unpacked = self.eval_expression(
                        required_value(keyword_object, "value")?,
                        scope,
                        host,
                    )?;
                    let VmValue::Dict(entries) = unpacked else {
                        return Err(VmExecutionError::new(
                            "keyword unpacking requires a dict value",
                        ));
                    };
                    for (key, value) in entries {
                        values.push((key.as_string()?, value));
                    }
                }
                other => {
                    return Err(VmExecutionError::new(format!(
                        "unsupported keyword node '{other}'"
                    )))
                }
            }
        }
        Ok(values)
    }

    fn eval_syscall(
        &mut self,
        object: &Map<String, Value>,
        syscall_id: &str,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        match syscall_id {
            "storage.foreign_hash.new" => {
                foreign_storage::new_reference("ForeignHash", args, kwargs)
            }
            "storage.foreign_variable.new" => {
                foreign_storage::new_reference("ForeignVariable", args, kwargs)
            }
            "numeric.decimal.new" => {
                if !kwargs.is_empty() || args.len() != 1 {
                    return Err(VmExecutionError::new("decimal() expects one argument"));
                }
                Ok(VmValue::Decimal(VmDecimal::from_vm_value(
                    args.first().expect("decimal() argument should exist"),
                )?))
            }
            "time.datetime.new" => time_datetime_new(args, kwargs),
            "time.datetime.strptime" => time_datetime_strptime(args, kwargs),
            "time.timedelta.new" => time_timedelta_new(args, kwargs),
            "hash.sha3_256_text" => hash_sha3_256_text(args, kwargs),
            "hash.sha3_256_hex" => hash_sha3_256_hex(args, kwargs),
            "hash.sha256_text" => hash_sha256_text(args, kwargs),
            "hash.sha256_hex" => hash_sha256_hex(args, kwargs),
            "crypto.ed25519_verify" => crypto_ed25519_verify(args, kwargs),
            "crypto.key_is_valid" => crypto_key_is_valid(args, kwargs),
            "storage.variable.get" => {
                host.charge_execution_cost(VM_GAS_VARIABLE_GET)?;
                let binding = required_string(object, "receiver_binding")?;
                self.variable_get(binding, host)
            }
            "storage.variable.set" => {
                host.charge_execution_cost(VM_GAS_VARIABLE_SET)?;
                let binding = required_string(object, "receiver_binding")?;
                let value = args
                    .first()
                    .cloned()
                    .ok_or_else(|| VmExecutionError::new("Variable.set expects one argument"))?;
                self.variable_set(binding, value.clone())?;
                let storage_key = variable_storage_key(&self.module.module_name, binding);
                host.record_storage_write(&storage_key, &value)?;
                host.charge_storage_write(&storage_key, &value)?;
                Ok(VmValue::None)
            }
            "storage.foreign_variable.get" => {
                host.charge_execution_cost(VM_GAS_VARIABLE_GET)?;
                let binding = required_string(object, "receiver_binding")?;
                self.variable_get(binding, host)
            }
            "storage.hash.all" | "storage.foreign_hash.all" => {
                host.charge_execution_cost(VM_GAS_HASH_SCAN)?;
                let binding = required_string(object, "receiver_binding")?;
                self.hash_all(binding, &args, host)
            }
            "contract.import" => {
                let module = resolve_contract_import_arg(&args, &kwargs)?;
                Ok(VmValue::ContractHandle(VmContractHandle {
                    module,
                    origin: "dynamic_import".to_owned(),
                }))
            }
            "contract.call" => {
                if !kwargs.is_empty() || args.len() > 3 {
                    return Err(VmExecutionError::new(
                        "contract.call expects target, function, and optional kwargs dict",
                    ));
                }
                let target = match args
                    .first()
                    .cloned()
                    .ok_or_else(|| VmExecutionError::new("contract.call expects a target"))?
                {
                    VmValue::String(module) => VmContractTarget::DynamicImport { module },
                    VmValue::ContractHandle(handle) => VmContractTarget::DynamicImport {
                        module: handle.module,
                    },
                    other => {
                        return Err(VmExecutionError::new(format!(
                            "contract.call target must be a contract name or handle, got {}",
                            other.type_name()
                        )))
                    }
                };
                let function = args
                    .get(1)
                    .ok_or_else(|| VmExecutionError::new("contract.call expects a function"))?
                    .as_string()?;
                let call_kwargs = match args.get(2) {
                    None | Some(VmValue::None) => Vec::new(),
                    Some(VmValue::Dict(entries)) => entries
                        .iter()
                        .map(|(key, value)| Ok((key.as_string()?, value.clone())))
                        .collect::<Result<Vec<_>, VmExecutionError>>()?,
                    Some(other) => {
                        return Err(VmExecutionError::new(format!(
                            "contract.call kwargs must be a dict, got {}",
                            other.type_name()
                        )))
                    }
                };
                host.call_contract(VmContractCall {
                    target,
                    function,
                    args: Vec::new(),
                    kwargs: call_kwargs,
                    caller_contract: self.context.this.clone(),
                    signer: self.context.signer.clone(),
                    entry: self.context.entry.clone(),
                    submission_name: self.context.submission_name.clone(),
                    now: self.context.now.clone(),
                    block_num: self.context.block_num.clone(),
                    block_hash: self.context.block_hash.clone(),
                    chain_id: self.context.chain_id.clone(),
                })
            }
            "event.log.emit" => {
                host.charge_execution_cost(VM_GAS_EVENT_EMIT)?;
                let event_binding = required_string(object, "event_binding")?;
                let event = self.globals.get(event_binding).cloned().ok_or_else(|| {
                    VmExecutionError::new(format!("unknown event binding '{event_binding}'"))
                })?;
                let event = match event {
                    VmValue::EventRef(event) => *event,
                    other => {
                        return Err(VmExecutionError::new(format!(
                            "binding '{event_binding}' is not an event reference but {}",
                            other.type_name()
                        )))
                    }
                };
                let payload = if let Some(first) = args.first() {
                    first.clone()
                } else if kwargs.is_empty() {
                    VmValue::None
                } else {
                    VmValue::Dict(
                        kwargs
                            .iter()
                            .map(|(key, value)| (VmValue::String(key.clone()), value.clone()))
                            .collect(),
                    )
                };
                let (data_indexed, data) = normalize_event_payload(&event.params, payload)?;
                for (key, value) in data_indexed.iter().map(|(key, value)| (key, value)) {
                    host.charge_storage_write(key, value)?;
                }
                for (key, value) in data.iter().map(|(key, value)| (key, value)) {
                    host.charge_storage_write(key, value)?;
                }
                host.emit_event(VmEvent {
                    contract: self
                        .context
                        .this
                        .clone()
                        .unwrap_or_else(|| self.module.module_name.clone()),
                    event: event.event_name,
                    signer: option_string_value(&self.context.signer),
                    caller: option_string_value(&self.context.caller),
                    data_indexed,
                    data,
                })?;
                Ok(VmValue::None)
            }
            "contract.export_call" => {
                let function_name = required_string(object, "function_name")?;
                let contract_target = required_value(object, "contract_target")?;
                let target = self.resolve_contract_target(contract_target, scope, host)?;
                host.call_contract(VmContractCall {
                    target,
                    function: function_name.to_owned(),
                    args,
                    kwargs,
                    caller_contract: self.context.this.clone(),
                    signer: self.context.signer.clone(),
                    entry: self.context.entry.clone(),
                    submission_name: self.context.submission_name.clone(),
                    now: self.context.now.clone(),
                    block_num: self.context.block_num.clone(),
                    block_hash: self.context.block_hash.clone(),
                    chain_id: self.context.chain_id.clone(),
                })
            }
            "event.indexed" => {
                let type_value = if args.len() == 1 {
                    coerce_type_marker(args[0].clone())
                } else {
                    VmValue::Tuple(args.into_iter().map(coerce_type_marker).collect())
                };
                Ok(VmValue::Dict(vec![
                    (VmValue::String("type".to_owned()), type_value),
                    (VmValue::String("idx".to_owned()), VmValue::Bool(true)),
                ]))
            }
            "random.shuffle" => {
                let target = required_array(object, "args")?.first().ok_or_else(|| {
                    VmExecutionError::new("random.shuffle() expects one argument")
                })?;
                let module_scope = target_writes_module_scope(target, scope, &self.globals)?;
                let (resolved_target, _) =
                    self.resolve_assignment_target(target, scope, host, false)?;
                if let Some(cost) = explicit_syscall_metering_cost(syscall_id, &args, &kwargs)? {
                    host.charge_execution_cost(cost)?;
                }
                let shuffled = host.handle_syscall(syscall_id, args, kwargs)?;
                self.assign_resolved_target(resolved_target, shuffled, scope, module_scope)?;
                Ok(VmValue::None)
            }
            other => {
                // Contract metadata syscalls are checked against the contract
                // executing right now, not the transaction's entry contract,
                // so a constructor or a contract called from submission can't
                // use them.
                if SUBMISSION_ONLY_SYSCALLS.contains(&other)
                    && self.context.this.as_deref() != Some(SUBMISSION_CONTRACT)
                {
                    return Err(VmExecutionError::new(
                        "Contract metadata changes are restricted to submission.",
                    ));
                }
                if let Some(cost) = explicit_syscall_metering_cost(other, &args, &kwargs)? {
                    host.charge_execution_cost(cost)?;
                }
                host.handle_syscall(other, args, kwargs)
            }
        }
    }

    fn resolve_contract_target(
        &mut self,
        value: &Value,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmContractTarget, VmExecutionError> {
        let object = as_object(value, "contract_target")?;
        match required_string(object, "kind")? {
            "static_import" => {
                let binding = required_string(object, "binding")?.to_owned();
                let module = self.imports.get(&binding).cloned().ok_or_else(|| {
                    VmExecutionError::new(format!("unknown static import binding '{binding}'"))
                })?;
                Ok(VmContractTarget::StaticImport { binding, module })
            }
            "dynamic_import" => {
                let source = required_value(object, "source")?;
                let handle = self
                    .eval_expression(source, scope, host)?
                    .as_contract_handle()?;
                Ok(VmContractTarget::DynamicImport {
                    module: handle.module,
                })
            }
            "local_handle" => {
                let binding = required_string(object, "binding")?.to_owned();
                let source = required_value(object, "source")?;
                let handle = self
                    .eval_expression(source, scope, host)?
                    .as_contract_handle()?;
                Ok(VmContractTarget::LocalHandle {
                    binding,
                    module: handle.module,
                })
            }
            "factory_call" => {
                let factory = required_string(object, "factory")?.to_owned();
                let source = required_value(object, "source")?;
                let handle = self
                    .eval_expression(source, scope, host)?
                    .as_contract_handle()?;
                Ok(VmContractTarget::FactoryCall {
                    factory,
                    module: handle.module,
                })
            }
            other => Err(VmExecutionError::new(format!(
                "unsupported contract target kind '{other}'"
            ))),
        }
    }

    fn eval_compare(
        &mut self,
        object: &Map<String, Value>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let mut left = self.eval_expression(required_value(object, "left")?, scope, host)?;
        let operators = required_array(object, "operators")?;
        let comparators = required_array(object, "comparators")?;
        if operators.len() != comparators.len() {
            return Err(VmExecutionError::new(
                "compare operator/comparator count mismatch",
            ));
        }

        for (operator, comparator) in operators.iter().zip(comparators.iter()) {
            let right = self.eval_expression(comparator, scope, host)?;
            let passed = apply_compare_operator(required_string_value(operator)?, &left, &right)?;
            if !passed {
                return Ok(VmValue::Bool(false));
            }
            left = right;
        }

        Ok(VmValue::Bool(true))
    }

    fn eval_bool_op(
        &mut self,
        object: &Map<String, Value>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let operator = required_string(object, "operator")?;
        let values = required_array(object, "values")?;
        match operator {
            "and" => {
                let mut last = VmValue::Bool(true);
                for value in values {
                    last = self.eval_expression(value, scope, host)?;
                    if !last.truthy() {
                        return Ok(last);
                    }
                }
                Ok(last)
            }
            "or" => {
                let mut last = VmValue::Bool(false);
                for value in values {
                    last = self.eval_expression(value, scope, host)?;
                    if last.truthy() {
                        return Ok(last);
                    }
                }
                Ok(last)
            }
            other => Err(VmExecutionError::new(format!(
                "unsupported bool operator '{other}'"
            ))),
        }
    }

    fn call_builtin(
        &mut self,
        host: &mut dyn VmHost,
        name: &str,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
    ) -> Result<VmValue, VmExecutionError> {
        match name {
            "len" => {
                if !kwargs.is_empty() || args.len() != 1 {
                    return Err(VmExecutionError::new("len() expects one argument"));
                }
                match &args[0] {
                    VmValue::String(value) => Ok(vm_int(value.chars().count())),
                    VmValue::Bytes(value) | VmValue::ByteArray(value) => Ok(vm_int(value.len())),
                    VmValue::List(values)
                    | VmValue::Tuple(values)
                    | VmValue::Set(values)
                    | VmValue::FrozenSet(values) => Ok(vm_int(values.len())),
                    VmValue::Dict(entries) => Ok(vm_int(entries.len())),
                    other => Err(VmExecutionError::new(format!(
                        "len() does not support {}",
                        other.type_name()
                    ))),
                }
            }
            "range" => {
                if !kwargs.is_empty() || args.is_empty() || args.len() > 3 {
                    return Err(VmExecutionError::new(
                        "range() expects between one and three positional arguments",
                    ));
                }
                let (start, stop, step) = match args.len() {
                    1 => (BigInt::zero(), args[0].as_bigint()?, BigInt::from(1)),
                    2 => (args[0].as_bigint()?, args[1].as_bigint()?, BigInt::from(1)),
                    3 => (
                        args[0].as_bigint()?,
                        args[1].as_bigint()?,
                        args[2].as_bigint()?,
                    ),
                    _ => unreachable!(),
                };
                if step.is_zero() {
                    return Err(VmExecutionError::new("range() step cannot be zero"));
                }
                let mut values = Vec::new();
                let mut current = start;
                if step.sign() != Sign::Minus {
                    while current < stop {
                        if values.len() >= MAX_SEQUENCE_LENGTH {
                            return Err(VmExecutionError::new(
                                "range() exceeds the maximum allowed allocation size",
                            ));
                        }
                        values.push(VmValue::Int(current.clone()));
                        current += &step;
                    }
                } else {
                    while current > stop {
                        if values.len() >= MAX_SEQUENCE_LENGTH {
                            return Err(VmExecutionError::new(
                                "range() exceeds the maximum allowed allocation size",
                            ));
                        }
                        values.push(VmValue::Int(current.clone()));
                        current += &step;
                    }
                }
                Ok(VmValue::List(values))
            }
            "str" => {
                if !kwargs.is_empty() || args.len() != 1 {
                    return Err(VmExecutionError::new("str() expects one argument"));
                }
                Ok(VmValue::String(args[0].python_repr()))
            }
            "bytes" => {
                if !kwargs.is_empty() || args.len() > 3 {
                    return Err(VmExecutionError::new(
                        "bytes() expects between zero and three positional arguments",
                    ));
                }
                match args.as_slice() {
                    [] => Ok(VmValue::Bytes(Vec::new())),
                    [VmValue::String(_value)] => {
                        Err(VmExecutionError::new("string argument without an encoding"))
                    }
                    [VmValue::String(value), encoding] | [VmValue::String(value), encoding, _] => {
                        let encoding = encoding.as_string()?.to_lowercase();
                        match encoding.as_str() {
                            "utf-8" | "utf8" => Ok(VmValue::Bytes(value.as_bytes().to_vec())),
                            "ascii" => {
                                if !value.is_ascii() {
                                    return Err(VmExecutionError::new(
                                        "'ascii' codec can't encode characters outside ASCII range",
                                    ));
                                }
                                Ok(VmValue::Bytes(value.as_bytes().to_vec()))
                            }
                            other => Err(VmExecutionError::new(format!(
                                "unsupported bytes() encoding '{other}'",
                            ))),
                        }
                    }
                    [VmValue::Int(size)] => {
                        if size.sign() == Sign::Minus {
                            return Err(VmExecutionError::new("negative count"));
                        }
                        let size = bigint_to_usize(size, "bytes() size")?;
                        if size > MAX_BINARY_ALLOCATION_BYTES {
                            return Err(VmExecutionError::new(
                                "bytes() exceeds the maximum allowed allocation size",
                            ));
                        }
                        Ok(VmValue::Bytes(vec![0; size]))
                    }
                    [value] => Ok(VmValue::Bytes(clone_as_bytes_like(value)?)),
                    _ => Err(VmExecutionError::new("encoding without a string argument")),
                }
            }
            "bytearray" => {
                if !kwargs.is_empty() || args.len() > 3 {
                    return Err(VmExecutionError::new(
                        "bytearray() expects between zero and three positional arguments",
                    ));
                }
                match args.as_slice() {
                    [] => Ok(VmValue::ByteArray(Vec::new())),
                    [VmValue::String(_value)] => {
                        Err(VmExecutionError::new("string argument without an encoding"))
                    }
                    [VmValue::String(value), encoding] | [VmValue::String(value), encoding, _] => {
                        let encoding = encoding.as_string()?.to_lowercase();
                        match encoding.as_str() {
                            "utf-8" | "utf8" => Ok(VmValue::ByteArray(value.as_bytes().to_vec())),
                            "ascii" => {
                                if !value.is_ascii() {
                                    return Err(VmExecutionError::new(
                                        "'ascii' codec can't encode characters outside ASCII range",
                                    ));
                                }
                                Ok(VmValue::ByteArray(value.as_bytes().to_vec()))
                            }
                            other => Err(VmExecutionError::new(format!(
                                "unsupported bytearray() encoding '{other}'",
                            ))),
                        }
                    }
                    [VmValue::Int(size)] => {
                        if size.sign() == Sign::Minus {
                            return Err(VmExecutionError::new("negative count"));
                        }
                        let size = bigint_to_usize(size, "bytearray() size")?;
                        if size > MAX_BINARY_ALLOCATION_BYTES {
                            return Err(VmExecutionError::new(
                                "bytearray() exceeds the maximum allowed allocation size",
                            ));
                        }
                        Ok(VmValue::ByteArray(vec![0; size]))
                    }
                    [value] => Ok(VmValue::ByteArray(clone_as_bytes_like(value)?)),
                    _ => Err(VmExecutionError::new("encoding without a string argument")),
                }
            }
            "set" => {
                if !kwargs.is_empty() || args.len() > 1 {
                    return Err(VmExecutionError::new("set() expects at most one argument"));
                }
                let values = match args.as_slice() {
                    [] => Vec::new(),
                    [value] => iterate_value(value)?,
                    _ => unreachable!(),
                };
                Ok(VmValue::Set(normalize_set_items(values)?))
            }
            "frozenset" => {
                if !kwargs.is_empty() || args.len() > 1 {
                    return Err(VmExecutionError::new(
                        "frozenset() expects at most one argument",
                    ));
                }
                let values = match args.as_slice() {
                    [] => Vec::new(),
                    [value] => iterate_value(value)?,
                    _ => unreachable!(),
                };
                Ok(VmValue::FrozenSet(normalize_set_items(values)?))
            }
            "bool" => {
                if !kwargs.is_empty() || args.len() != 1 {
                    return Err(VmExecutionError::new("bool() expects one argument"));
                }
                Ok(VmValue::Bool(args[0].truthy()))
            }
            "abs" => {
                if !kwargs.is_empty() || args.len() != 1 {
                    return Err(VmExecutionError::new("abs() expects one argument"));
                }
                match &args[0] {
                    VmValue::Int(value) => Ok(VmValue::Int(value.abs())),
                    VmValue::Float(value) => Ok(VmValue::Float(value.abs())),
                    VmValue::Decimal(value) => Ok(VmValue::Decimal(VmDecimal::from_scaled(
                        if value.scaled.sign() == Sign::Minus {
                            -value.scaled.clone()
                        } else {
                            value.scaled.clone()
                        },
                    )?)),
                    other => Err(VmExecutionError::new(format!(
                        "abs() does not support {}",
                        other.type_name()
                    ))),
                }
            }
            "int" => {
                if !kwargs.is_empty() || args.is_empty() || args.len() > 2 {
                    return Err(VmExecutionError::new(
                        "int() expects one or two positional arguments",
                    ));
                }
                match (&args[0], args.get(1)) {
                    (VmValue::String(value), Some(base)) => {
                        ensure_int_input_size(value)?;
                        let base = bigint_to_u32(&base.as_bigint()?, "int() base")?;
                        if !(2..=36).contains(&base) {
                            return Err(VmExecutionError::new(
                                "int() base must be between 2 and 36",
                            ));
                        }
                        BigInt::from_str_radix(value, base)
                            .map(|value| checked_int_value(value, "int()"))
                            .map_err(|_| {
                                VmExecutionError::new(format!(
                                    "cannot convert '{value}' to int with base {base}"
                                ))
                            })?
                    }
                    (_, Some(_)) => Err(VmExecutionError::new(
                        "int() base argument requires a string input",
                    )),
                    (VmValue::Int(value), None) => checked_int_value(value.clone(), "int()"),
                    (VmValue::Bool(value), None) => Ok(vm_int(if *value { 1 } else { 0 })),
                    (VmValue::Float(value), None) => {
                        checked_int_value(f64_to_bigint_trunc(*value, "float() input")?, "int()")
                    }
                    (VmValue::Decimal(value), None) => {
                        checked_int_value(value.to_bigint(), "int()")
                    }
                    (VmValue::String(value), None) => {
                        ensure_int_input_size(value)?;
                        BigInt::from_str(value)
                            .map(|value| checked_int_value(value, "int()"))
                            .map_err(|_| {
                                VmExecutionError::new(format!("cannot convert '{value}' to int"))
                            })?
                    }
                    (VmValue::Bytes(value), None) | (VmValue::ByteArray(value), None) => {
                        ensure_int_bytes_input_size(value)?;
                        let rendered = String::from_utf8(value.clone()).map_err(|_| {
                            VmExecutionError::new("cannot convert non-text bytes to int")
                        })?;
                        ensure_int_input_size(&rendered)?;
                        BigInt::from_str(&rendered)
                            .map(|value| checked_int_value(value, "int()"))
                            .map_err(|_| {
                                VmExecutionError::new(format!(
                                    "cannot convert '{}' to int",
                                    String::from_utf8_lossy(value)
                                ))
                            })?
                    }
                    (other, None) => Err(VmExecutionError::new(format!(
                        "int() does not support {}",
                        other.type_name()
                    ))),
                }
            }
            "pow" => {
                if !kwargs.is_empty() || args.len() < 2 || args.len() > 3 {
                    return Err(VmExecutionError::new(
                        "pow() expects two or three positional arguments",
                    ));
                }
                if let Some(modulus) = args.get(2) {
                    let base = args[0].as_bigint()?;
                    let exponent = args[1].as_bigint()?;
                    let modulus = modulus.as_bigint()?;
                    if exponent.sign() == Sign::Minus {
                        return Err(VmExecutionError::new(
                            "pow() 3rd argument not allowed unless all arguments are integers",
                        ));
                    }
                    if modulus.is_zero() {
                        return Err(VmExecutionError::new("pow() 3rd argument cannot be 0"));
                    }
                    ensure_bigint_bits(&modulus, "modular exponentiation modulus")?;
                    if exponent.bits() > MAX_MODULAR_POW_EXPONENT_BITS {
                        return Err(integer_limit_error("modular exponentiation exponent"));
                    }
                    return checked_int_value(
                        base.modpow(&exponent, &modulus),
                        "modular exponentiation",
                    );
                }
                match (&args[0], &args[1]) {
                    (VmValue::Int(base), VmValue::Int(exponent)) => {
                        checked_bigint_pow(base, exponent, "integer exponentiation")
                    }
                    (VmValue::Decimal(base), VmValue::Decimal(exponent)) => {
                        Ok(VmValue::Decimal(base.pow(exponent)?))
                    }
                    (VmValue::Decimal(base), exponent) => Ok(VmValue::Decimal(
                        base.pow(&VmDecimal::from_vm_value(exponent)?)?,
                    )),
                    (base, VmValue::Decimal(exponent)) => Ok(VmValue::Decimal(
                        VmDecimal::from_vm_value(base)?.pow(exponent)?,
                    )),
                    (VmValue::Float(base), VmValue::Float(exponent)) => {
                        Ok(VmValue::Float(base.powf(*exponent)))
                    }
                    (VmValue::Float(base), VmValue::Int(exponent)) => Ok(VmValue::Float(
                        base.powf(bigint_to_f64(exponent, "pow() exponent")?),
                    )),
                    (VmValue::Int(base), VmValue::Float(exponent)) => Ok(VmValue::Float(
                        bigint_to_f64(base, "pow() base")?.powf(*exponent),
                    )),
                    (left, right) => Err(VmExecutionError::new(format!(
                        "pow() does not support {} and {}",
                        left.type_name(),
                        right.type_name()
                    ))),
                }
            }
            "format" => {
                if args.is_empty() || args.len() > 2 || !kwargs.is_empty() {
                    return Err(VmExecutionError::new(
                        "format() expects one or two positional arguments",
                    ));
                }
                let spec = if let Some(value) = args.get(1) {
                    value.as_string()?
                } else {
                    String::new()
                };
                Ok(VmValue::String(format_builtin_value(&args[0], &spec)?))
            }
            "float" => {
                if !kwargs.is_empty() || args.len() != 1 {
                    return Err(VmExecutionError::new("float() expects one argument"));
                }
                match &args[0] {
                    VmValue::Int(value) => {
                        Ok(VmValue::Float(bigint_to_f64(value, "float() input")?))
                    }
                    VmValue::Bool(value) => Ok(VmValue::Float(if *value { 1.0 } else { 0.0 })),
                    VmValue::Float(value) => Ok(VmValue::Float(*value)),
                    VmValue::Decimal(value) => Ok(VmValue::Float(value.to_f64()?)),
                    VmValue::String(value) => {
                        value.parse::<f64>().map(VmValue::Float).map_err(|_| {
                            VmExecutionError::new(format!("cannot convert '{value}' to float"))
                        })
                    }
                    VmValue::Bytes(value) | VmValue::ByteArray(value) => {
                        let rendered = String::from_utf8(value.clone()).map_err(|_| {
                            VmExecutionError::new("cannot convert non-text bytes to float")
                        })?;
                        rendered.parse::<f64>().map(VmValue::Float).map_err(|_| {
                            VmExecutionError::new(format!(
                                "cannot convert '{}' to float",
                                String::from_utf8_lossy(value)
                            ))
                        })
                    }
                    other => Err(VmExecutionError::new(format!(
                        "float() does not support {}",
                        other.type_name()
                    ))),
                }
            }
            "ord" => {
                if args.len() != 1 || !kwargs.is_empty() {
                    return Err(VmExecutionError::new("ord() expects one argument"));
                }
                match &args[0] {
                    VmValue::String(value) => {
                        let mut chars = value.chars();
                        let first = chars.next().ok_or_else(|| {
                            VmExecutionError::new(
                                "ord() expected a character, but string was empty",
                            )
                        })?;
                        if chars.next().is_some() {
                            return Err(VmExecutionError::new(
                                "ord() expected a character, but string of length > 1 found",
                            ));
                        }
                        Ok(vm_int(u32::from(first)))
                    }
                    VmValue::Bytes(value) | VmValue::ByteArray(value) => match value.as_slice() {
                        [byte] => Ok(vm_int(*byte)),
                        [] => Err(VmExecutionError::new(
                            "ord() expected a character, but string was empty",
                        )),
                        _ => Err(VmExecutionError::new(
                            "ord() expected a character, but string of length > 1 found",
                        )),
                    },
                    other => Err(VmExecutionError::new(format!(
                        "ord() does not support {}",
                        other.type_name()
                    ))),
                }
            }
            "ascii" => {
                if args.len() != 1 || !kwargs.is_empty() {
                    return Err(VmExecutionError::new("ascii() expects one argument"));
                }
                Ok(VmValue::String(match &args[0] {
                    VmValue::String(value) => ascii_string_repr(value),
                    other => ascii_render(&other.python_repr()),
                }))
            }
            "bin" => {
                if args.len() != 1 || !kwargs.is_empty() {
                    return Err(VmExecutionError::new("bin() expects one argument"));
                }
                Ok(VmValue::String(format_integer_builtin(
                    &args[0].as_bigint()?,
                    2,
                    "0b",
                )))
            }
            "hex" => {
                if args.len() != 1 || !kwargs.is_empty() {
                    return Err(VmExecutionError::new("hex() expects one argument"));
                }
                Ok(VmValue::String(format_integer_builtin(
                    &args[0].as_bigint()?,
                    16,
                    "0x",
                )))
            }
            "oct" => {
                if args.len() != 1 || !kwargs.is_empty() {
                    return Err(VmExecutionError::new("oct() expects one argument"));
                }
                Ok(VmValue::String(format_integer_builtin(
                    &args[0].as_bigint()?,
                    8,
                    "0o",
                )))
            }
            "chr" => {
                if args.len() != 1 || !kwargs.is_empty() {
                    return Err(VmExecutionError::new("chr() expects one argument"));
                }
                let code_point = bigint_to_u32(&args[0].as_bigint()?, "chr() input")?;
                let character = char::from_u32(code_point).ok_or_else(|| {
                    VmExecutionError::new(format!("chr() arg not in range(0x110000): {code_point}"))
                })?;
                Ok(VmValue::String(character.to_string()))
            }
            "divmod" => {
                if args.len() != 2 || !kwargs.is_empty() {
                    return Err(VmExecutionError::new("divmod() expects two arguments"));
                }
                let quotient = apply_binary_operator("floordiv", args[0].clone(), args[1].clone())?;
                let remainder = apply_binary_operator("mod", args[0].clone(), args[1].clone())?;
                Ok(VmValue::Tuple(vec![quotient, remainder]))
            }
            "Exception" => {
                if !kwargs.is_empty() {
                    return Err(VmExecutionError::new(
                        "Exception() does not accept keyword arguments",
                    ));
                }
                Ok(VmValue::Exception(VmException {
                    name: "Exception".to_owned(),
                    args,
                }))
            }
            "dict" => {
                if args.len() > 1 {
                    return Err(VmExecutionError::new(
                        "dict() accepts at most one positional argument",
                    ));
                }
                let mut entries = Vec::new();
                if let Some(initial) = args.first() {
                    match initial {
                        VmValue::Dict(existing) => entries.extend(existing.clone()),
                        VmValue::List(items) | VmValue::Tuple(items) => {
                            for item in items {
                                match item {
                                    VmValue::List(values) | VmValue::Tuple(values)
                                        if values.len() == 2 =>
                                    {
                                        entries.push((values[0].clone(), values[1].clone()));
                                    }
                                    other => {
                                        return Err(VmExecutionError::new(format!(
                                            "dict() expected key/value pairs, got {}",
                                            other.type_name()
                                        )))
                                    }
                                }
                            }
                        }
                        other => {
                            return Err(VmExecutionError::new(format!(
                                "dict() does not support {}",
                                other.type_name()
                            )))
                        }
                    }
                }
                for (key, value) in kwargs {
                    dict_set(&mut entries, VmValue::String(key), value);
                }
                Ok(VmValue::Dict(entries))
            }
            "list" => {
                if args.len() > 1 || !kwargs.is_empty() {
                    return Err(VmExecutionError::new(
                        "list() accepts at most one positional argument",
                    ));
                }
                if let Some(value) = args.first() {
                    let items = iterate_value(value)?;
                    Ok(VmValue::List(items))
                } else {
                    Ok(VmValue::List(Vec::new()))
                }
            }
            "tuple" => {
                if args.len() > 1 || !kwargs.is_empty() {
                    return Err(VmExecutionError::new(
                        "tuple() accepts at most one positional argument",
                    ));
                }
                if let Some(value) = args.first() {
                    let items = iterate_value(value)?;
                    Ok(VmValue::Tuple(items))
                } else {
                    Ok(VmValue::Tuple(Vec::new()))
                }
            }
            "sorted" => {
                if args.len() != 1 || !kwargs.is_empty() {
                    return Err(VmExecutionError::new(
                        "sorted() expects one positional argument",
                    ));
                }
                let values = iterate_value(&args[0])?;
                Ok(VmValue::List(sorted_values(values)?))
            }
            "sum" => {
                if kwargs.len() > 0 || args.is_empty() || args.len() > 2 {
                    return Err(VmExecutionError::new(
                        "sum() expects one or two positional arguments",
                    ));
                }
                let mut total = if let Some(start) = args.get(1) {
                    start.clone()
                } else {
                    vm_int(0)
                };
                for value in iterate_value(&args[0])? {
                    total = apply_binary_operator("add", total, value)?;
                }
                Ok(total)
            }
            "min" => {
                if kwargs.len() > 0 || args.is_empty() {
                    return Err(VmExecutionError::new(
                        "min() expects at least one positional argument",
                    ));
                }
                let values = builtin_ordered_values(args)?;
                let mut best = values
                    .first()
                    .cloned()
                    .ok_or_else(|| VmExecutionError::new("min() received no values"))?;
                for candidate in values.into_iter().skip(1) {
                    if compare_vm_values(&candidate, &best)? == std::cmp::Ordering::Less {
                        best = candidate;
                    }
                }
                Ok(best)
            }
            "max" => {
                if kwargs.len() > 0 || args.is_empty() {
                    return Err(VmExecutionError::new(
                        "max() expects at least one positional argument",
                    ));
                }
                let values = builtin_ordered_values(args)?;
                let mut best = values
                    .first()
                    .cloned()
                    .ok_or_else(|| VmExecutionError::new("max() received no values"))?;
                for candidate in values.into_iter().skip(1) {
                    if compare_vm_values(&candidate, &best)? == std::cmp::Ordering::Greater {
                        best = candidate;
                    }
                }
                Ok(best)
            }
            "all" => {
                if args.len() != 1 || !kwargs.is_empty() {
                    return Err(VmExecutionError::new(
                        "all() expects one positional argument",
                    ));
                }
                Ok(VmValue::Bool(
                    iterate_value(&args[0])?.iter().all(VmValue::truthy),
                ))
            }
            "any" => {
                if args.len() != 1 || !kwargs.is_empty() {
                    return Err(VmExecutionError::new(
                        "any() expects one positional argument",
                    ));
                }
                Ok(VmValue::Bool(
                    iterate_value(&args[0])?.iter().any(VmValue::truthy),
                ))
            }
            "map" => {
                if !kwargs.is_empty() || args.len() < 2 {
                    return Err(VmExecutionError::new(
                        "map() must have at least two arguments",
                    ));
                }
                let function = args[0].clone();
                if function == VmValue::None {
                    return Err(VmExecutionError::new(
                        "map() must have a callable first argument",
                    ));
                }
                if !matches!(function, VmValue::Builtin(_) | VmValue::FunctionRef(_)) {
                    return Err(VmExecutionError::new(
                        "map() must have a callable first argument",
                    ));
                }
                let iterables = args[1..]
                    .iter()
                    .map(iterate_value)
                    .collect::<Result<Vec<_>, _>>()?;
                let length = iterables.iter().map(Vec::len).min().unwrap_or(0);
                let mut mapped = Vec::with_capacity(length);
                for index in 0..length {
                    let call_args = iterables
                        .iter()
                        .map(|values| values[index].clone())
                        .collect::<Vec<_>>();
                    mapped.push(self.call_callable_value(
                        host,
                        function.clone(),
                        call_args,
                        Vec::new(),
                    )?);
                }
                Ok(VmValue::List(mapped))
            }
            "filter" => {
                if !kwargs.is_empty() || args.len() != 2 {
                    return Err(VmExecutionError::new(
                        "filter() expects two positional arguments",
                    ));
                }
                let function = args[0].clone();
                let values = iterate_value(&args[1])?;
                let mut filtered = Vec::new();
                if function == VmValue::None {
                    for value in values {
                        if value.truthy() {
                            filtered.push(value);
                        }
                    }
                    return Ok(VmValue::List(filtered));
                }
                if !matches!(function, VmValue::Builtin(_) | VmValue::FunctionRef(_)) {
                    return Err(VmExecutionError::new(
                        "filter() must have a callable first argument or None",
                    ));
                }
                for value in values {
                    if self
                        .call_callable_value(
                            host,
                            function.clone(),
                            vec![value.clone()],
                            Vec::new(),
                        )?
                        .truthy()
                    {
                        filtered.push(value);
                    }
                }
                Ok(VmValue::List(filtered))
            }
            "reversed" => {
                if args.len() != 1 || !kwargs.is_empty() {
                    return Err(VmExecutionError::new(
                        "reversed() expects one positional argument",
                    ));
                }
                let mut values = iterate_value(&args[0])?;
                values.reverse();
                Ok(VmValue::List(values))
            }
            "zip" => {
                if args.is_empty() || !kwargs.is_empty() {
                    return Err(VmExecutionError::new(
                        "zip() expects one or more positional arguments",
                    ));
                }
                let iterables = args
                    .iter()
                    .map(iterate_value)
                    .collect::<Result<Vec<_>, _>>()?;
                let length = iterables.iter().map(Vec::len).min().unwrap_or(0);
                let mut zipped = Vec::with_capacity(length);
                for index in 0..length {
                    zipped.push(VmValue::Tuple(
                        iterables
                            .iter()
                            .map(|values| values[index].clone())
                            .collect(),
                    ));
                }
                Ok(VmValue::List(zipped))
            }
            "isinstance" => {
                if args.len() != 2 || !kwargs.is_empty() {
                    return Err(VmExecutionError::new(
                        "isinstance() expects two positional arguments",
                    ));
                }
                Ok(VmValue::Bool(type_matches(&args[0], &args[1])))
            }
            "issubclass" => {
                if args.len() != 2 || !kwargs.is_empty() {
                    return Err(VmExecutionError::new(
                        "issubclass() expects two positional arguments",
                    ));
                }
                Ok(VmValue::Bool(issubclass_matches(&args[0], &args[1])?))
            }
            "round" => {
                if args.is_empty() || args.len() > 2 || !kwargs.is_empty() {
                    return Err(VmExecutionError::new(
                        "round() expects one or two positional arguments",
                    ));
                }
                let digits = match args.get(1) {
                    Some(value) => Some(
                        bigint_to_i64(&value.as_bigint()?, "round() ndigits")?
                            .try_into()
                            .map_err(|_| {
                                VmExecutionError::new("round() ndigits is out of supported range")
                            })?,
                    ),
                    None => None,
                };
                round_builtin_value(&args[0], digits)
            }
            other => Err(VmExecutionError::new(format!(
                "unsupported builtin '{other}'"
            ))),
        }
    }

    fn variable_get(
        &mut self,
        binding: &str,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let module_name = self.module.module_name.clone();
        let (foreign_key, default_value, current_value) = {
            let state = self.variables.get(binding).ok_or_else(|| {
                VmExecutionError::new(format!("unknown variable binding '{binding}'"))
            })?;
            (
                state.foreign_key.clone(),
                state.default_value.clone(),
                state.value.clone(),
            )
        };
        if let Some(foreign_key) = foreign_key {
            let (foreign_contract, foreign_binding) = split_foreign_storage_key(&foreign_key)?;
            let loaded = host.read_variable(&foreign_contract, &foreign_binding)?;
            let foreign = self
                .variables
                .entry(foreign_key)
                .or_insert_with(|| VariableState {
                    default_value: VmValue::None,
                    value: None,
                    foreign_key: None,
                    snapshot_local: false,
                    dirty: false,
                });
            if loaded.is_some() {
                foreign.value = loaded;
            }
            let value = foreign
                .value
                .clone()
                .unwrap_or_else(|| foreign.default_value.clone());
            charge_storage_read(
                host,
                &variable_storage_key(&foreign_contract, &foreign_binding),
                &value,
            )?;
            return Ok(value);
        }
        let storage_key = variable_storage_key(&module_name, binding);
        if let Some(value) = host.read_recorded_storage_write(&storage_key)? {
            let state = self.variables.get_mut(binding).ok_or_else(|| {
                VmExecutionError::new(format!("unknown variable binding '{binding}'"))
            })?;
            state.value = Some(value.clone());
            charge_storage_read(host, &storage_key, &value)?;
            return Ok(value);
        }
        if current_value.is_none() {
            let loaded = host.read_variable(&module_name, binding)?;
            let state = self.variables.get_mut(binding).ok_or_else(|| {
                VmExecutionError::new(format!("unknown variable binding '{binding}'"))
            })?;
            if state.value.is_none() {
                state.value = loaded;
            }
            let value = state
                .value
                .clone()
                .unwrap_or_else(|| state.default_value.clone());
            charge_storage_read(host, &storage_key, &value)?;
            return Ok(value);
        }
        let value = current_value.unwrap_or(default_value);
        charge_storage_read(host, &storage_key, &value)?;
        Ok(value)
    }

    fn variable_set(&mut self, binding: &str, value: VmValue) -> Result<(), VmExecutionError> {
        let state = self.variables.get_mut(binding).ok_or_else(|| {
            VmExecutionError::new(format!("unknown variable binding '{binding}'"))
        })?;
        if state.foreign_key.is_some() {
            return Err(VmExecutionError::new(format!(
                "cannot set foreign variable '{binding}'"
            )));
        }
        state.value = Some(value);
        state.dirty = true;
        Ok(())
    }

    fn hash_get(
        &mut self,
        binding: &str,
        key: &VmValue,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let storage_key = normalize_hash_key(key)?;
        let module_name = self.module.module_name.clone();
        let (foreign_key, default_value, current_entry) = {
            let state = self.hashes.get(binding).ok_or_else(|| {
                VmExecutionError::new(format!("unknown hash binding '{binding}'"))
            })?;
            (
                state.foreign_key.clone(),
                state.default_value.clone(),
                state.entries.get(&storage_key).cloned(),
            )
        };
        if let Some(foreign_key) = foreign_key {
            let (foreign_contract, foreign_binding) = split_foreign_storage_key(&foreign_key)?;
            let loaded = host.read_hash(&foreign_contract, &foreign_binding, key)?;
            let foreign = self.hashes.entry(foreign_key).or_insert_with(|| HashState {
                default_value: VmValue::None,
                entries: HashMap::new(),
                foreign_key: None,
                snapshot_local: false,
                dirty_entries: HashSet::new(),
            });
            if let Some(value) = loaded {
                foreign.entries.insert(storage_key.clone(), value);
            }
            let value = foreign
                .entries
                .get(&storage_key)
                .cloned()
                .unwrap_or_else(|| foreign.default_value.clone());
            charge_storage_read(
                host,
                &hash_storage_key(&foreign_contract, &foreign_binding, key)?,
                &value,
            )?;
            return Ok(value);
        }
        let full_storage_key = hash_storage_key(&module_name, binding, key)?;
        if let Some(value) = host.read_recorded_storage_write(&full_storage_key)? {
            let state = self.hashes.get_mut(binding).ok_or_else(|| {
                VmExecutionError::new(format!("unknown hash binding '{binding}'"))
            })?;
            state.entries.insert(storage_key.clone(), value.clone());
            charge_storage_read(host, &full_storage_key, &value)?;
            return Ok(value);
        }
        if current_entry.is_none() {
            let loaded = host.read_hash(&module_name, binding, key)?;
            let state = self.hashes.get_mut(binding).ok_or_else(|| {
                VmExecutionError::new(format!("unknown hash binding '{binding}'"))
            })?;
            if let Some(value) = loaded {
                state.entries.insert(storage_key.clone(), value);
            }
            let value = state
                .entries
                .get(&storage_key)
                .cloned()
                .unwrap_or_else(|| state.default_value.clone());
            charge_storage_read(host, &full_storage_key, &value)?;
            return Ok(value);
        }
        let value = current_entry.unwrap_or(default_value);
        charge_storage_read(host, &full_storage_key, &value)?;
        Ok(value)
    }

    fn hash_all(
        &mut self,
        binding: &str,
        prefix_args: &[VmValue],
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let module_name = self.module.module_name.clone();
        let prefix = normalize_hash_prefix(prefix_args)?;
        let (scan_contract, scan_binding, state_key) = {
            let state = self.hashes.get(binding).ok_or_else(|| {
                VmExecutionError::new(format!("unknown hash binding '{binding}'"))
            })?;
            if let Some(foreign_key) = &state.foreign_key {
                let (foreign_contract, foreign_binding) = split_foreign_storage_key(foreign_key)?;
                (foreign_contract, foreign_binding, foreign_key.clone())
            } else {
                (module_name.clone(), binding.to_owned(), binding.to_owned())
            }
        };

        let scanned = host.scan_hash_entries_metered(&scan_contract, &scan_binding, &prefix)?;
        let state = self.hashes.entry(state_key).or_insert_with(|| HashState {
            default_value: VmValue::None,
            entries: HashMap::new(),
            foreign_key: None,
            snapshot_local: false,
            dirty_entries: HashSet::new(),
        });
        let mut ordered = scanned
            .into_iter()
            .collect::<std::collections::BTreeMap<_, _>>();
        // Only snapshot-local/dirty values can supplement the host. Cached reads
        // must not resurrect a tombstone written by a nested contract call.
        for (key, value) in &state.entries {
            if prefix_matches_hash_entry(key, &prefix)
                && (state.snapshot_local || state.dirty_entries.contains(key))
                && !ordered.contains_key(key)
                && !matches!(value, VmValue::None)
            {
                charge_storage_read(
                    host,
                    &hash_storage_key_from_normalized(&scan_contract, &scan_binding, key),
                    value,
                )?;
                ordered.insert(key.clone(), value.clone());
            }
        }
        let mut budget = crate::storage_scan::ScanBudget::default();
        let mut values = Vec::new();
        for (key, value) in ordered {
            if matches!(value, VmValue::None) {
                continue;
            }
            budget.observe(&key, &value)?;
            state.entries.insert(key, value.clone());
            values.push(value);
        }

        Ok(VmValue::List(values))
    }

    fn hash_set(
        &mut self,
        binding: &str,
        key: &VmValue,
        value: VmValue,
    ) -> Result<(), VmExecutionError> {
        let storage_key = normalize_hash_key(key)?;
        let state = self
            .hashes
            .get_mut(binding)
            .ok_or_else(|| VmExecutionError::new(format!("unknown hash binding '{binding}'")))?;
        if state.foreign_key.is_some() {
            return Err(VmExecutionError::new(format!(
                "cannot set foreign hash '{binding}'"
            )));
        }
        state.entries.insert(storage_key.clone(), value);
        state.dirty_entries.insert(storage_key);
        Ok(())
    }
}

struct NoopHost;

impl VmHost for NoopHost {}

fn ir_root_name(value: &Value) -> Result<Option<&str>, VmExecutionError> {
    let object = as_object(value, "expression")?;
    match required_string(object, "node")? {
        "name" => Ok(Some(required_string(object, "id")?)),
        "attribute" | "subscript" => ir_root_name(required_value(object, "value")?),
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parse_module_ir, XIAN_IR_V1, XIAN_VM_HOST_CATALOG_V1, XIAN_VM_V1_PROFILE};
    use serde_json::json;

    #[derive(Default)]
    struct RecordingHost {
        events: Vec<VmEvent>,
        calls: Vec<VmContractCall>,
    }

    #[derive(Default)]
    struct SyscallRecordingHost {
        syscalls: Vec<(String, Vec<VmValue>, Vec<(String, VmValue)>)>,
    }

    #[derive(Default)]
    struct AssignmentMeteringHost {
        budget: Option<u64>,
        raw_cost: u64,
        execution_costs: Vec<u64>,
        hash_reads: Vec<(String, String, VmValue)>,
        storage_reads: Vec<(String, VmValue)>,
    }

    impl VmHost for RecordingHost {
        fn emit_event(&mut self, event: VmEvent) -> Result<(), VmExecutionError> {
            self.events.push(event);
            Ok(())
        }

        fn call_contract(&mut self, call: VmContractCall) -> Result<VmValue, VmExecutionError> {
            self.calls.push(call.clone());
            match call.function.as_str() {
                "transfer" => Ok(VmValue::Bool(true)),
                "balance_of" => Ok(vm_int(77)),
                _ => Ok(VmValue::None),
            }
        }
    }

    impl VmHost for SyscallRecordingHost {
        fn handle_syscall(
            &mut self,
            syscall_id: &str,
            args: Vec<VmValue>,
            kwargs: Vec<(String, VmValue)>,
        ) -> Result<VmValue, VmExecutionError> {
            self.syscalls
                .push((syscall_id.to_owned(), args.clone(), kwargs.clone()));
            match syscall_id {
                "zk.verify_groth16" => Ok(VmValue::Bool(true)),
                "zk.shielded_output_payload_hash" => {
                    Ok(VmValue::String("0x".to_owned() + &"ab".repeat(32)))
                }
                other => Err(VmExecutionError::new(format!(
                    "unexpected syscall '{other}'"
                ))),
            }
        }
    }

    impl VmHost for AssignmentMeteringHost {
        fn charge_execution_cost(&mut self, cost: u64) -> Result<(), VmExecutionError> {
            self.execution_costs.push(cost);
            self.raw_cost = self
                .raw_cost
                .checked_add(cost)
                .ok_or_else(|| VmExecutionError::new("chi metering overflow"))?;
            if self.budget.is_some_and(|budget| self.raw_cost > budget) {
                return Err(VmExecutionError::new("Out of chi."));
            }
            Ok(())
        }

        fn charge_storage_read(
            &mut self,
            key: &str,
            value: &VmValue,
        ) -> Result<(), VmExecutionError> {
            self.storage_reads.push((key.to_owned(), value.clone()));
            Ok(())
        }

        fn read_hash(
            &mut self,
            contract: &str,
            binding: &str,
            key: &VmValue,
        ) -> Result<Option<VmValue>, VmExecutionError> {
            self.hash_reads
                .push((contract.to_owned(), binding.to_owned(), key.clone()));
            Ok(Some(vm_int(1)))
        }
    }

    fn empty_test_instance(module_name: &str) -> VmInstance {
        VmInstance::new(
            ModuleIr {
                ir_version: XIAN_IR_V1.to_owned(),
                vm_profile: XIAN_VM_V1_PROFILE.to_owned(),
                host_catalog_version: XIAN_VM_HOST_CATALOG_V1.to_owned(),
                module_name: module_name.to_owned(),
                source_hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_owned(),
                docstring: None,
                imports: Vec::new(),
                global_declarations: Vec::new(),
                functions: Vec::new(),
                module_body: Vec::new(),
                host_dependencies: Vec::new(),
            },
            VmExecutionContext::default(),
        )
        .expect("empty test module should instantiate")
    }

    fn test_span() -> Value {
        json!({"line": 1, "col": 0, "end_line": 1, "end_col": 1})
    }

    fn test_name(id: &str) -> Value {
        json!({
            "node": "name",
            "span": test_span(),
            "id": id,
            "host_binding_id": null,
        })
    }

    fn test_int(value: i64) -> Value {
        json!({
            "node": "constant",
            "span": test_span(),
            "value_type": "int",
            "value": value,
        })
    }

    #[test]
    fn eval_name_prefers_scope_over_stale_host_binding() {
        let mut instance = empty_test_instance("host_shadow_probe");
        let mut scope = HashMap::from([("now".to_owned(), vm_int(7))]);
        let mut host = NoopHost;
        let expression = json!({
            "node": "name",
            "span": test_span(),
            "id": "now",
            "host_binding_id": "env.now",
        });

        let result = instance
            .eval_expression(&expression, &mut scope, &mut host)
            .expect("shadowed name should evaluate");

        assert_eq!(result, vm_int(7));
    }

    #[test]
    fn formatted_value_rejects_unsupported_format_spec() {
        let mut instance = empty_test_instance("format_spec_probe");
        let mut scope = HashMap::from([("value".to_owned(), vm_int(7))]);
        let mut host = NoopHost;
        let expression = json!({
            "node": "formatted_value",
            "span": test_span(),
            "value": test_name("value"),
            "conversion": null,
            "format_spec": {
                "node": "f_string",
                "span": test_span(),
                "values": [
                    {
                        "node": "constant",
                        "span": test_span(),
                        "value_type": "str",
                        "value": "04d"
                    }
                ]
            }
        });

        let error = instance
            .eval_expression(&expression, &mut scope, &mut host)
            .expect_err("format spec should fail closed");

        assert!(error
            .to_string()
            .contains("f-string format specifications are not supported"));
    }

    #[test]
    fn subscript_assignment_uses_active_host_for_index_storage_reads() {
        let mut instance = empty_test_instance("assignment_host_probe");
        instance.hashes.insert(
            "indexes".to_owned(),
            HashState {
                default_value: vm_int(0),
                entries: HashMap::new(),
                foreign_key: None,
                snapshot_local: true,
                dirty_entries: HashSet::new(),
            },
        );
        let mut scope = HashMap::from([(
            "values".to_owned(),
            VmValue::List(vec![vm_int(10), vm_int(20)]),
        )]);
        let target = json!({
            "node": "subscript",
            "span": test_span(),
            "value": test_name("values"),
            "slice": {
                "node": "storage_get",
                "span": test_span(),
                "binding": "indexes",
                "storage_type": "Hash",
                "syscall_id": "storage.hash.get",
                "key": {
                    "node": "constant",
                    "span": test_span(),
                    "value_type": "str",
                    "value": "active",
                },
            },
        });
        let mut host = AssignmentMeteringHost::default();

        instance
            .assign_target(&target, vm_int(99), &mut scope, &mut host, false)
            .expect("subscript assignment should use the host-provided index");

        assert_eq!(
            scope.get("values"),
            Some(&VmValue::List(vec![vm_int(10), vm_int(99)]))
        );
        assert_eq!(
            host.execution_costs,
            vec![
                VM_GAS_EXPR_NAME,
                VM_GAS_EXPR_STORAGE_GET,
                VM_GAS_EXPR_CONSTANT,
            ]
        );
        assert_eq!(
            host.hash_reads,
            vec![(
                "assignment_host_probe".to_owned(),
                "indexes".to_owned(),
                VmValue::String("active".to_owned()),
            )]
        );
        assert_eq!(host.storage_reads.len(), 1);
        assert_eq!(host.storage_reads[0].1, vm_int(1));
    }

    #[test]
    fn nested_subscript_assignment_charges_container_path_once() {
        let mut instance = empty_test_instance("nested_assignment_metering");
        let mut scope = HashMap::from([(
            "matrix".to_owned(),
            VmValue::List(vec![
                VmValue::List(vec![vm_int(1), vm_int(2)]),
                VmValue::List(vec![vm_int(3), vm_int(4)]),
            ]),
        )]);
        let target = json!({
            "node": "subscript",
            "span": test_span(),
            "value": {
                "node": "subscript",
                "span": test_span(),
                "value": test_name("matrix"),
                "slice": test_int(0),
            },
            "slice": test_int(1),
        });
        let mut host = AssignmentMeteringHost::default();

        instance
            .assign_target(&target, vm_int(9), &mut scope, &mut host, false)
            .expect("nested subscript assignment should succeed");

        assert_eq!(
            scope.get("matrix"),
            Some(&VmValue::List(vec![
                VmValue::List(vec![vm_int(1), vm_int(9)]),
                VmValue::List(vec![vm_int(3), vm_int(4)]),
            ]))
        );
        assert_eq!(
            host.execution_costs,
            vec![
                VM_GAS_EXPR_SUBSCRIPT,
                VM_GAS_EXPR_NAME,
                VM_GAS_EXPR_CONSTANT,
                VM_GAS_EXPR_CONSTANT,
            ]
        );
    }

    #[test]
    fn augmented_subscript_assignment_charges_target_once() {
        let mut instance = empty_test_instance("augmented_assignment_metering");
        let mut scope = HashMap::from([("values".to_owned(), VmValue::List(vec![vm_int(3)]))]);
        let statement = json!({
            "node": "aug_assign",
            "span": test_span(),
            "operator": "add",
            "target": {
                "node": "subscript",
                "span": test_span(),
                "value": test_name("values"),
                "slice": test_int(0),
            },
            "value": test_int(4),
        });
        let mut host = AssignmentMeteringHost::default();

        instance
            .execute_statement(&statement, &mut scope, &mut host)
            .expect("augmented subscript assignment should succeed");

        assert_eq!(scope.get("values"), Some(&VmValue::List(vec![vm_int(7)])));
        assert_eq!(
            host.execution_costs,
            vec![
                VM_GAS_STMT_AUG_ASSIGN,
                VM_GAS_EXPR_SUBSCRIPT,
                VM_GAS_EXPR_NAME,
                VM_GAS_EXPR_CONSTANT,
                VM_GAS_EXPR_CONSTANT,
            ]
        );
    }

    #[test]
    fn mutable_subscript_receiver_is_evaluated_once() {
        let mut instance = empty_test_instance("mutable_receiver_metering");
        let mut scope = HashMap::from([(
            "values".to_owned(),
            VmValue::List(vec![VmValue::List(vec![vm_int(1)])]),
        )]);
        let statement = json!({
            "node": "expr",
            "span": test_span(),
            "value": {
                "node": "call",
                "span": test_span(),
                "func": {
                    "node": "attribute",
                    "span": test_span(),
                    "value": {
                        "node": "subscript",
                        "span": test_span(),
                        "value": test_name("values"),
                        "slice": test_int(0),
                    },
                    "attr": "append",
                    "path": null,
                    "host_binding_id": null,
                },
                "args": [test_int(2)],
                "keywords": [],
                "syscall_id": null,
            },
        });
        let mut host = AssignmentMeteringHost::default();

        instance
            .execute_statement(&statement, &mut scope, &mut host)
            .expect("nested mutable receiver should be written back");

        assert_eq!(
            scope.get("values"),
            Some(&VmValue::List(vec![VmValue::List(vec![
                vm_int(1),
                vm_int(2),
            ])]))
        );
        assert_eq!(
            host.execution_costs,
            vec![
                VM_GAS_STMT_EXPR,
                VM_GAS_CALL_DISPATCH,
                VM_GAS_EXPR_CONSTANT,
                VM_GAS_EXPR_SUBSCRIPT,
                VM_GAS_EXPR_NAME,
                VM_GAS_EXPR_CONSTANT,
            ]
        );
    }

    #[test]
    fn low_chi_during_subscript_target_evaluation_preserves_container() {
        let mut instance = empty_test_instance("assignment_low_chi");
        let original = VmValue::List(vec![vm_int(1), vm_int(2)]);
        let mut scope = HashMap::from([("values".to_owned(), original.clone())]);
        let statement = json!({
            "node": "assign",
            "span": test_span(),
            "targets": [{
                "node": "subscript",
                "span": test_span(),
                "value": test_name("values"),
                "slice": test_int(1),
            }],
            "value": test_int(9),
        });
        let budget = VM_GAS_STMT_ASSIGN + VM_GAS_EXPR_CONSTANT + VM_GAS_EXPR_NAME;
        let mut host = AssignmentMeteringHost {
            budget: Some(budget),
            ..AssignmentMeteringHost::default()
        };

        let error = instance
            .execute_statement(&statement, &mut scope, &mut host)
            .expect_err("index evaluation must exhaust the remaining chi");

        assert_eq!(error.to_string(), "Out of chi.");
        assert_eq!(scope.get("values"), Some(&original));
        assert_eq!(
            host.execution_costs,
            vec![
                VM_GAS_STMT_ASSIGN,
                VM_GAS_EXPR_CONSTANT,
                VM_GAS_EXPR_NAME,
                VM_GAS_EXPR_CONSTANT,
            ]
        );
    }

    #[test]
    fn unsupported_slice_assignment_is_metered_and_preserves_container() {
        let mut instance = empty_test_instance("slice_assignment_metering");
        let original = VmValue::List(vec![vm_int(1), vm_int(2), vm_int(3)]);
        let mut scope = HashMap::from([("values".to_owned(), original.clone())]);
        let statement = json!({
            "node": "assign",
            "span": test_span(),
            "targets": [{
                "node": "subscript",
                "span": test_span(),
                "value": test_name("values"),
                "slice": {
                    "node": "slice",
                    "span": test_span(),
                    "lower": test_int(1),
                    "upper": test_int(2),
                    "step": null,
                },
            }],
            "value": {
                "node": "list",
                "span": test_span(),
                "elements": [test_int(9)],
            },
        });
        let mut host = AssignmentMeteringHost::default();

        let error = instance
            .execute_statement(&statement, &mut scope, &mut host)
            .expect_err("slice assignment remains outside the native VM execution slice");

        assert_eq!(
            error.to_string(),
            "slice expressions are only supported as subscripts"
        );
        assert_eq!(scope.get("values"), Some(&original));
        assert_eq!(
            host.execution_costs,
            vec![
                VM_GAS_STMT_ASSIGN,
                VM_GAS_EXPR_LIST,
                VM_GAS_EXPR_CONSTANT,
                VM_GAS_EXPR_NAME,
                VM_GAS_EXPR_SUBSCRIPT,
            ]
        );
    }

    #[test]
    fn executes_storage_event_and_contract_calls() {
        let module = parse_module_ir(
            &json!({
                "ir_version": XIAN_IR_V1,
                "vm_profile": XIAN_VM_V1_PROFILE,
                "host_catalog_version": XIAN_VM_HOST_CATALOG_V1,
                "module_name": "sample_token",
                "source_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "docstring": null,
                "imports": [
                    {
                        "node": "import",
                        "span": {"line": 1, "col": 0, "end_line": 1, "end_col": 15},
                        "module": "currency",
                        "alias": null
                    }
                ],
                "global_declarations": [
                    {
                        "node": "storage_decl",
                        "span": {"line": 2, "col": 0, "end_line": 2, "end_col": 24},
                        "name": "balances",
                        "storage_type": "Hash",
                        "syscall_id": "storage.hash.new",
                        "args": [],
                        "keywords": [
                            {
                                "arg": "default_value",
                                "span": {"line": 2, "col": 16, "end_line": 2, "end_col": 23},
                                "value": {
                                    "node": "constant",
                                    "span": {"line": 2, "col": 23, "end_line": 2, "end_col": 24},
                                    "value_type": "int",
                                    "value": 0
                                }
                            }
                        ]
                    },
                    {
                        "node": "storage_decl",
                        "span": {"line": 3, "col": 0, "end_line": 3, "end_col": 18},
                        "name": "metadata",
                        "storage_type": "Variable",
                        "syscall_id": "storage.variable.new",
                        "args": [],
                        "keywords": []
                    },
                    {
                        "node": "event_decl",
                        "span": {"line": 4, "col": 0, "end_line": 4, "end_col": 10},
                        "name": "TransferEvent",
                        "syscall_id": "event.log.new",
                        "event_name": "Transfer",
                        "params": {
                            "node": "dict",
                            "span": {"line": 4, "col": 0, "end_line": 4, "end_col": 10},
                            "entries": [
                                {
                                    "key": {
                                        "node": "constant",
                                        "span": {"line": 4, "col": 1, "end_line": 4, "end_col": 7},
                                        "value_type": "str",
                                        "value": "from"
                                    },
                                    "value": {
                                        "node": "call",
                                        "span": {"line": 4, "col": 8, "end_line": 4, "end_col": 20},
                                        "func": {
                                            "node": "name",
                                            "span": {"line": 4, "col": 8, "end_line": 4, "end_col": 15},
                                            "id": "indexed",
                                            "host_binding_id": "event.indexed"
                                        },
                                        "args": [
                                            {
                                                "node": "name",
                                                "span": {"line": 4, "col": 16, "end_line": 4, "end_col": 19},
                                                "id": "str",
                                                "host_binding_id": null
                                            }
                                        ],
                                        "keywords": [],
                                        "syscall_id": "event.indexed"
                                    }
                                }
                            ]
                        }
                    }
                ],
                "functions": [
                    {
                        "node": "function",
                        "span": {"line": 6, "col": 0, "end_line": 14, "end_col": 20},
                        "name": "transfer",
                        "visibility": "export",
                        "decorator": null,
                        "docstring": null,
                        "parameters": [
                            {
                                "name": "amount",
                                "kind": "positional_or_keyword",
                                "annotation": "int",
                                "default": null,
                                "span": {"line": 6, "col": 13, "end_line": 6, "end_col": 23}
                            },
                            {
                                "name": "to",
                                "kind": "positional_or_keyword",
                                "annotation": "str",
                                "default": null,
                                "span": {"line": 6, "col": 25, "end_line": 6, "end_col": 32}
                            }
                        ],
                        "returns": null,
                        "body": [
                            {
                                "node": "assign",
                                "span": {"line": 7, "col": 4, "end_line": 7, "end_col": 21},
                                "targets": [
                                    {
                                        "node": "name",
                                        "span": {"line": 7, "col": 4, "end_line": 7, "end_col": 10},
                                        "id": "sender",
                                        "host_binding_id": null
                                    }
                                ],
                                "value": {
                                    "node": "attribute",
                                    "span": {"line": 7, "col": 13, "end_line": 7, "end_col": 23},
                                    "value": {
                                        "node": "name",
                                        "span": {"line": 7, "col": 13, "end_line": 7, "end_col": 16},
                                        "id": "ctx",
                                        "host_binding_id": null
                                    },
                                    "attr": "caller",
                                    "path": "ctx.caller",
                                    "host_binding_id": "context.caller"
                                }
                            },
                            {
                                "node": "expr",
                                "span": {"line": 8, "col": 4, "end_line": 8, "end_col": 21},
                                "value": {
                                    "node": "call",
                                    "span": {"line": 8, "col": 4, "end_line": 8, "end_col": 21},
                                    "func": {
                                        "node": "attribute",
                                        "span": {"line": 8, "col": 4, "end_line": 8, "end_col": 16},
                                        "value": {
                                            "node": "name",
                                            "span": {"line": 8, "col": 4, "end_line": 8, "end_col": 12},
                                            "id": "metadata",
                                            "host_binding_id": null
                                        },
                                        "attr": "set",
                                        "path": "metadata.set",
                                        "host_binding_id": null
                                    },
                                    "args": [
                                        {
                                            "node": "name",
                                            "span": {"line": 8, "col": 17, "end_line": 8, "end_col": 20},
                                            "id": "now",
                                            "host_binding_id": "env.now"
                                        }
                                    ],
                                    "keywords": [],
                                    "syscall_id": "storage.variable.set",
                                    "receiver_binding": "metadata",
                                    "receiver_type": "Variable",
                                    "method": "set"
                                }
                            },
                            {
                                "node": "storage_mutate",
                                "span": {"line": 9, "col": 4, "end_line": 9, "end_col": 30},
                                "binding": "balances",
                                "storage_type": "Hash",
                                "read_syscall_id": "storage.hash.get",
                                "write_syscall_id": "storage.hash.set",
                                "key": {
                                    "node": "name",
                                    "span": {"line": 9, "col": 13, "end_line": 9, "end_col": 19},
                                    "id": "sender",
                                    "host_binding_id": null
                                },
                                "operator": "sub",
                                "value": {
                                    "node": "name",
                                    "span": {"line": 9, "col": 24, "end_line": 9, "end_col": 30},
                                    "id": "amount",
                                    "host_binding_id": null
                                }
                            },
                            {
                                "node": "storage_mutate",
                                "span": {"line": 10, "col": 4, "end_line": 10, "end_col": 25},
                                "binding": "balances",
                                "storage_type": "Hash",
                                "read_syscall_id": "storage.hash.get",
                                "write_syscall_id": "storage.hash.set",
                                "key": {
                                    "node": "name",
                                    "span": {"line": 10, "col": 13, "end_line": 10, "end_col": 15},
                                    "id": "to",
                                    "host_binding_id": null
                                },
                                "operator": "add",
                                "value": {
                                    "node": "name",
                                    "span": {"line": 10, "col": 20, "end_line": 10, "end_col": 26},
                                    "id": "amount",
                                    "host_binding_id": null
                                }
                            },
                            {
                                "node": "expr",
                                "span": {"line": 11, "col": 4, "end_line": 11, "end_col": 43},
                                "value": {
                                    "node": "call",
                                    "span": {"line": 11, "col": 4, "end_line": 11, "end_col": 43},
                                    "func": {
                                        "node": "attribute",
                                        "span": {"line": 11, "col": 4, "end_line": 11, "end_col": 21},
                                        "value": {
                                            "node": "name",
                                            "span": {"line": 11, "col": 4, "end_line": 11, "end_col": 12},
                                            "id": "currency",
                                            "host_binding_id": null
                                        },
                                        "attr": "transfer",
                                        "path": "currency.transfer",
                                        "host_binding_id": null
                                    },
                                    "args": [],
                                    "keywords": [
                                        {
                                            "arg": "amount",
                                            "span": {"line": 11, "col": 22, "end_line": 11, "end_col": 35},
                                            "value": {
                                                "node": "name",
                                                "span": {"line": 11, "col": 29, "end_line": 11, "end_col": 35},
                                                "id": "amount",
                                                "host_binding_id": null
                                            }
                                        },
                                        {
                                            "arg": "to",
                                            "span": {"line": 11, "col": 37, "end_line": 11, "end_col": 42},
                                            "value": {
                                                "node": "name",
                                                "span": {"line": 11, "col": 40, "end_line": 11, "end_col": 42},
                                                "id": "to",
                                                "host_binding_id": null
                                            }
                                        }
                                    ],
                                    "syscall_id": "contract.export_call",
                                    "contract_target": {
                                        "kind": "static_import",
                                        "binding": "currency",
                                        "span": {"line": 11, "col": 4, "end_line": 11, "end_col": 12}
                                    },
                                    "function_name": "transfer"
                                }
                            },
                            {
                                "node": "expr",
                                "span": {"line": 12, "col": 4, "end_line": 12, "end_col": 40},
                                "value": {
                                    "node": "call",
                                    "span": {"line": 12, "col": 4, "end_line": 12, "end_col": 40},
                                    "func": {
                                        "node": "name",
                                        "span": {"line": 12, "col": 4, "end_line": 12, "end_col": 17},
                                        "id": "TransferEvent",
                                        "host_binding_id": null
                                    },
                                    "args": [
                                        {
                                            "node": "dict",
                                            "span": {"line": 12, "col": 18, "end_line": 12, "end_col": 39},
                                            "entries": [
                                                {
                                                    "key": {
                                                        "node": "constant",
                                                        "span": {"line": 12, "col": 19, "end_line": 12, "end_col": 25},
                                                        "value_type": "str",
                                                        "value": "from"
                                                    },
                                                    "value": {
                                                        "node": "name",
                                                        "span": {"line": 12, "col": 27, "end_line": 12, "end_col": 33},
                                                        "id": "sender",
                                                        "host_binding_id": null
                                                    }
                                                }
                                            ]
                                        }
                                    ],
                                    "keywords": [],
                                    "syscall_id": "event.log.emit",
                                    "event_binding": "TransferEvent"
                                }
                            },
                            {
                                "node": "return",
                                "span": {"line": 13, "col": 4, "end_line": 13, "end_col": 23},
                                "value": {
                                    "node": "storage_get",
                                    "span": {"line": 13, "col": 11, "end_line": 13, "end_col": 23},
                                    "binding": "balances",
                                    "storage_type": "Hash",
                                    "syscall_id": "storage.hash.get",
                                    "key": {
                                        "node": "name",
                                        "span": {"line": 13, "col": 20, "end_line": 13, "end_col": 22},
                                        "id": "to",
                                        "host_binding_id": null
                                    }
                                }
                            }
                        ]
                    }
                ],
                "module_body": [],
                "host_dependencies": [
                    {"binding": "Variable", "id": "storage.variable.new", "kind": "syscall", "category": "storage"},
                    {"binding": "Variable.set", "id": "storage.variable.set", "kind": "syscall", "category": "storage"},
                    {"binding": "Hash", "id": "storage.hash.new", "kind": "syscall", "category": "storage"},
                    {"binding": "Hash.__getitem__", "id": "storage.hash.get", "kind": "syscall", "category": "storage"},
                    {"binding": "Hash.__setitem__", "id": "storage.hash.set", "kind": "syscall", "category": "storage"},
                    {"binding": "LogEvent", "id": "event.log.new", "kind": "syscall", "category": "event"},
                    {"binding": "LogEvent.__call__", "id": "event.log.emit", "kind": "syscall", "category": "event"},
                    {"binding": "indexed", "id": "event.indexed", "kind": "syscall", "category": "event"},
                    {"binding": "__contract_export__", "id": "contract.export_call", "kind": "syscall", "category": "contract"},
                    {"binding": "ctx.caller", "id": "context.caller", "kind": "context_field", "category": "context"},
                    {"binding": "now", "id": "env.now", "kind": "env_value", "category": "environment"}
                ]
            })
            .to_string(),
        )
        .expect("module should parse");

        let mut instance = VmInstance::new(
            module,
            VmExecutionContext {
                caller: Some("alice".to_owned()),
                signer: Some("alice".to_owned()),
                now: vm_int(1234),
                ..VmExecutionContext::default()
            },
        )
        .expect("instance should initialize");

        instance
            .hash_set("balances", &VmValue::String("alice".to_owned()), vm_int(20))
            .expect("seed sender balance");

        let mut host = RecordingHost::default();
        let result = instance
            .call_function(
                &mut host,
                "transfer",
                vec![vm_int(5), VmValue::String("bob".to_owned())],
                vec![],
            )
            .expect("transfer should execute");

        assert_eq!(result, vm_int(5));
        assert_eq!(instance.get_variable("metadata"), Some(vm_int(1234)));
        assert_eq!(
            instance
                .get_hash_value("balances", &VmValue::String("alice".to_owned()))
                .expect("alice balance should exist"),
            Some(vm_int(15))
        );
        assert_eq!(
            instance
                .get_hash_value("balances", &VmValue::String("bob".to_owned()))
                .expect("bob balance should exist"),
            Some(vm_int(5))
        );
        assert_eq!(host.events.len(), 1);
        assert_eq!(host.events[0].contract, "sample_token");
        assert_eq!(host.events[0].event, "Transfer");
        assert_eq!(host.events[0].signer, VmValue::String("alice".to_owned()));
        assert_eq!(host.events[0].caller, VmValue::String("alice".to_owned()));
        assert_eq!(
            host.events[0].data_indexed,
            vec![("from".to_owned(), VmValue::String("alice".to_owned()))]
        );
        assert_eq!(host.events[0].data, Vec::<(String, VmValue)>::new());
        assert_eq!(host.calls.len(), 1);
        assert_eq!(contract_target_label(&host.calls[0].target), "currency");
        assert_eq!(host.calls[0].function, "transfer");
    }

    #[test]
    fn resolves_host_bindings_used_as_type_marker_values() {
        let module = parse_module_ir(
            &json!({
                "ir_version": XIAN_IR_V1,
                "vm_profile": XIAN_VM_V1_PROFILE,
                "host_catalog_version": XIAN_VM_HOST_CATALOG_V1,
                "module_name": "interface_probe",
                "source_hash": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                "docstring": null,
                "imports": [],
                "global_declarations": [
                    {
                        "node": "binding_decl",
                        "span": {"line": 1, "col": 0, "end_line": 1, "end_col": 16},
                        "name": "any_type",
                        "value": {
                            "node": "name",
                            "span": {"line": 1, "col": 11, "end_line": 1, "end_col": 14},
                            "id": "Any",
                            "host_binding_id": "typing.any"
                        }
                    },
                    {
                        "node": "binding_decl",
                        "span": {"line": 2, "col": 0, "end_line": 2, "end_col": 23},
                        "name": "variable_type",
                        "value": {
                            "node": "name",
                            "span": {"line": 2, "col": 16, "end_line": 2, "end_col": 24},
                            "id": "Variable",
                            "host_binding_id": "storage.variable.new"
                        }
                    },
                    {
                        "node": "binding_decl",
                        "span": {"line": 3, "col": 0, "end_line": 3, "end_col": 16},
                        "name": "hash_type",
                        "value": {
                            "node": "name",
                            "span": {"line": 3, "col": 12, "end_line": 3, "end_col": 16},
                            "id": "Hash",
                            "host_binding_id": "storage.hash.new"
                        }
                    },
                    {
                        "node": "binding_decl",
                        "span": {"line": 4, "col": 0, "end_line": 4, "end_col": 36},
                        "name": "foreign_variable_type",
                        "value": {
                            "node": "name",
                            "span": {"line": 4, "col": 24, "end_line": 4, "end_col": 39},
                            "id": "ForeignVariable",
                            "host_binding_id": "storage.foreign_variable.new"
                        }
                    },
                    {
                        "node": "binding_decl",
                        "span": {"line": 5, "col": 0, "end_line": 5, "end_col": 29},
                        "name": "foreign_hash_type",
                        "value": {
                            "node": "name",
                            "span": {"line": 5, "col": 20, "end_line": 5, "end_col": 31},
                            "id": "ForeignHash",
                            "host_binding_id": "storage.foreign_hash.new"
                        }
                    },
                    {
                        "node": "binding_decl",
                        "span": {"line": 6, "col": 0, "end_line": 6, "end_col": 21},
                        "name": "event_type",
                        "value": {
                            "node": "name",
                            "span": {"line": 6, "col": 13, "end_line": 6, "end_col": 21},
                            "id": "LogEvent",
                            "host_binding_id": "event.log.new"
                        }
                    }
                ],
                "functions": [
                    {
                        "node": "function",
                        "span": {"line": 8, "col": 0, "end_line": 9, "end_col": 94},
                        "name": "get_type_markers",
                        "visibility": "export",
                        "decorator": null,
                        "docstring": null,
                        "parameters": [],
                        "returns": null,
                        "body": [
                            {
                                "node": "return",
                                "span": {"line": 9, "col": 4, "end_line": 9, "end_col": 94},
                                "value": {
                                    "node": "list",
                                    "span": {"line": 9, "col": 11, "end_line": 9, "end_col": 94},
                                    "elements": [
                                        {
                                            "node": "name",
                                            "span": {"line": 9, "col": 12, "end_line": 9, "end_col": 20},
                                            "id": "any_type",
                                            "host_binding_id": null
                                        },
                                        {
                                            "node": "name",
                                            "span": {"line": 9, "col": 22, "end_line": 9, "end_col": 35},
                                            "id": "variable_type",
                                            "host_binding_id": null
                                        },
                                        {
                                            "node": "name",
                                            "span": {"line": 9, "col": 37, "end_line": 9, "end_col": 46},
                                            "id": "hash_type",
                                            "host_binding_id": null
                                        },
                                        {
                                            "node": "name",
                                            "span": {"line": 9, "col": 48, "end_line": 9, "end_col": 69},
                                            "id": "foreign_variable_type",
                                            "host_binding_id": null
                                        },
                                        {
                                            "node": "name",
                                            "span": {"line": 9, "col": 71, "end_line": 9, "end_col": 88},
                                            "id": "foreign_hash_type",
                                            "host_binding_id": null
                                        },
                                        {
                                            "node": "name",
                                            "span": {"line": 9, "col": 90, "end_line": 9, "end_col": 100},
                                            "id": "event_type",
                                            "host_binding_id": null
                                        }
                                    ]
                                }
                            }
                        ]
                    }
                ],
                "module_body": [],
                "host_dependencies": [
                    {"binding": "Any", "id": "typing.any", "kind": "type_marker", "category": "typing"},
                    {"binding": "Variable", "id": "storage.variable.new", "kind": "syscall", "category": "storage"},
                    {"binding": "Hash", "id": "storage.hash.new", "kind": "syscall", "category": "storage"},
                    {"binding": "ForeignVariable", "id": "storage.foreign_variable.new", "kind": "syscall", "category": "storage"},
                    {"binding": "ForeignHash", "id": "storage.foreign_hash.new", "kind": "syscall", "category": "storage"},
                    {"binding": "LogEvent", "id": "event.log.new", "kind": "syscall", "category": "event"}
                ]
            })
            .to_string(),
        )
        .expect("module should parse");

        let mut instance = VmInstance::new(module, VmExecutionContext::default())
            .expect("instance should initialize");
        let mut host = NoopHost;

        let result = instance
            .call_function(&mut host, "get_type_markers", vec![], vec![])
            .expect("type markers should resolve");

        assert_eq!(
            result,
            VmValue::List(vec![
                VmValue::TypeMarker("Any".to_owned()),
                VmValue::TypeMarker("Variable".to_owned()),
                VmValue::TypeMarker("Hash".to_owned()),
                VmValue::TypeMarker("ForeignVariable".to_owned()),
                VmValue::TypeMarker("ForeignHash".to_owned()),
                VmValue::TypeMarker("LogEvent".to_owned()),
            ])
        );
    }

    #[test]
    fn resolves_dynamic_imports_and_factory_calls() {
        let module = parse_module_ir(
            &json!({
                "ir_version": XIAN_IR_V1,
                "vm_profile": XIAN_VM_V1_PROFILE,
                "host_catalog_version": XIAN_VM_HOST_CATALOG_V1,
                "module_name": "adapter",
                "source_hash": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                "docstring": null,
                "imports": [],
                "global_declarations": [],
                "functions": [
                    {
                        "node": "function",
                        "span": {"line": 1, "col": 0, "end_line": 2, "end_col": 24},
                        "name": "load_token",
                        "visibility": "private",
                        "decorator": null,
                        "docstring": null,
                        "parameters": [
                            {
                                "name": "token",
                                "kind": "positional_or_keyword",
                                "annotation": "str",
                                "default": null,
                                "span": {"line": 1, "col": 14, "end_line": 1, "end_col": 24}
                            }
                        ],
                        "returns": null,
                        "body": [
                            {
                                "node": "return",
                                "span": {"line": 2, "col": 4, "end_line": 2, "end_col": 24},
                                "value": {
                                    "node": "call",
                                    "span": {"line": 2, "col": 11, "end_line": 2, "end_col": 24},
                                    "func": {
                                        "node": "attribute",
                                        "span": {"line": 2, "col": 11, "end_line": 2, "end_col": 23},
                                        "value": {
                                            "node": "name",
                                            "span": {"line": 2, "col": 11, "end_line": 2, "end_col": 20},
                                            "id": "importlib",
                                            "host_binding_id": null
                                        },
                                        "attr": "import_module",
                                        "path": "importlib.import_module",
                                        "host_binding_id": "contract.import"
                                    },
                                    "args": [
                                        {
                                            "node": "name",
                                            "span": {"line": 2, "col": 21, "end_line": 2, "end_col": 24},
                                            "id": "token",
                                            "host_binding_id": null
                                        }
                                    ],
                                    "keywords": [],
                                    "syscall_id": "contract.import"
                                }
                            }
                        ]
                    },
                    {
                        "node": "function",
                        "span": {"line": 4, "col": 0, "end_line": 5, "end_col": 40},
                        "name": "balance_of_token",
                        "visibility": "export",
                        "decorator": null,
                        "docstring": null,
                        "parameters": [
                            {
                                "name": "token",
                                "kind": "positional_or_keyword",
                                "annotation": "str",
                                "default": null,
                                "span": {"line": 4, "col": 20, "end_line": 4, "end_col": 30}
                            },
                            {
                                "name": "account",
                                "kind": "positional_or_keyword",
                                "annotation": "str",
                                "default": null,
                                "span": {"line": 4, "col": 32, "end_line": 4, "end_col": 44}
                            }
                        ],
                        "returns": null,
                        "body": [
                            {
                                "node": "return",
                                "span": {"line": 5, "col": 4, "end_line": 5, "end_col": 40},
                                "value": {
                                    "node": "call",
                                    "span": {"line": 5, "col": 11, "end_line": 5, "end_col": 40},
                                    "func": {
                                        "node": "attribute",
                                        "span": {"line": 5, "col": 11, "end_line": 5, "end_col": 29},
                                        "value": {
                                            "node": "call",
                                            "span": {"line": 5, "col": 11, "end_line": 5, "end_col": 28},
                                            "func": {
                                                "node": "name",
                                                "span": {"line": 5, "col": 11, "end_line": 5, "end_col": 21},
                                                "id": "load_token",
                                                "host_binding_id": null
                                            },
                                            "args": [
                                                {
                                                    "node": "name",
                                                    "span": {"line": 5, "col": 22, "end_line": 5, "end_col": 27},
                                                    "id": "token",
                                                    "host_binding_id": null
                                                }
                                            ],
                                            "keywords": []
                                        },
                                        "attr": "balance_of",
                                        "path": "load_token.balance_of",
                                        "host_binding_id": null
                                    },
                                    "args": [],
                                    "keywords": [
                                        {
                                            "arg": "account",
                                            "span": {"line": 5, "col": 30, "end_line": 5, "end_col": 39},
                                            "value": {
                                                "node": "name",
                                                "span": {"line": 5, "col": 38, "end_line": 5, "end_col": 45},
                                                "id": "account",
                                                "host_binding_id": null
                                            }
                                        }
                                    ],
                                    "syscall_id": "contract.export_call",
                                    "contract_target": {
                                        "kind": "factory_call",
                                        "factory": "load_token",
                                        "source": {
                                            "node": "call",
                                            "span": {"line": 5, "col": 11, "end_line": 5, "end_col": 28},
                                            "func": {
                                                "node": "name",
                                                "span": {"line": 5, "col": 11, "end_line": 5, "end_col": 21},
                                                "id": "load_token",
                                                "host_binding_id": null
                                            },
                                            "args": [
                                                {
                                                    "node": "name",
                                                    "span": {"line": 5, "col": 22, "end_line": 5, "end_col": 27},
                                                    "id": "token",
                                                    "host_binding_id": null
                                                }
                                            ],
                                            "keywords": []
                                        },
                                        "span": {"line": 5, "col": 11, "end_line": 5, "end_col": 28}
                                    },
                                    "function_name": "balance_of"
                                }
                            }
                        ]
                    }
                ],
                "module_body": [],
                "host_dependencies": [
                    {"binding": "importlib.import_module", "id": "contract.import", "kind": "syscall", "category": "import"},
                    {"binding": "__contract_export__", "id": "contract.export_call", "kind": "syscall", "category": "contract"}
                ]
            })
            .to_string(),
        )
        .expect("module should parse");

        let mut instance = VmInstance::new(module, VmExecutionContext::default())
            .expect("instance should initialize");
        let mut host = RecordingHost::default();

        let result = instance
            .call_function(
                &mut host,
                "balance_of_token",
                vec![
                    VmValue::String("shielded_note".to_owned()),
                    VmValue::String("alice".to_owned()),
                ],
                vec![],
            )
            .expect("call should execute");

        assert_eq!(result, vm_int(77));
        assert_eq!(host.calls.len(), 1);
        match &host.calls[0].target {
            VmContractTarget::FactoryCall { factory, module } => {
                assert_eq!(factory, "load_token");
                assert_eq!(module, "shielded_note");
            }
            other => panic!("unexpected contract target: {other:?}"),
        }
        assert_eq!(host.calls[0].function, "balance_of");
    }

    #[test]
    fn supports_string_replace_with_optional_count() {
        let replaced = call_native_method(
            VmValue::String("foo-foo-foo".to_owned()),
            "replace",
            vec![
                VmValue::String("foo".to_owned()),
                VmValue::String("bar".to_owned()),
            ],
            vec![],
        )
        .expect("replace should succeed");
        match replaced {
            NativeMethodResult::Value(VmValue::String(value)) => {
                assert_eq!(value, "bar-bar-bar".to_owned());
            }
            _ => panic!("unexpected replace result"),
        }

        let limited = call_native_method(
            VmValue::String("foo-foo-foo".to_owned()),
            "replace",
            vec![
                VmValue::String("foo".to_owned()),
                VmValue::String("bar".to_owned()),
                vm_int(2),
            ],
            vec![],
        )
        .expect("replace with count should succeed");
        match limited {
            NativeMethodResult::Value(VmValue::String(value)) => {
                assert_eq!(value, "bar-bar-foo".to_owned());
            }
            _ => panic!("unexpected replace result with count"),
        }

        let negative = call_native_method(
            VmValue::String("foo-foo".to_owned()),
            "replace",
            vec![
                VmValue::String("foo".to_owned()),
                VmValue::String("bar".to_owned()),
                vm_int(-1),
            ],
            vec![],
        )
        .expect("replace with negative count should replace all");
        match negative {
            NativeMethodResult::Value(VmValue::String(value)) => {
                assert_eq!(value, "bar-bar".to_owned());
            }
            _ => panic!("unexpected replace result with negative count"),
        }
    }

    #[test]
    fn supports_common_string_helper_methods() {
        let upper = call_native_method(
            VmValue::String("Alpha beta".to_owned()),
            "upper",
            vec![],
            vec![],
        )
        .expect("upper should succeed");
        assert_eq!(
            upper,
            NativeMethodResult::Value(VmValue::String("ALPHA BETA".to_owned()))
        );

        let strip = call_native_method(
            VmValue::String("  Alpha  ".to_owned()),
            "strip",
            vec![],
            vec![],
        )
        .expect("strip should succeed");
        assert_eq!(
            strip,
            NativeMethodResult::Value(VmValue::String("Alpha".to_owned()))
        );

        let endswith = call_native_method(
            VmValue::String("Alpha beta ALPHA".to_owned()),
            "endswith",
            vec![
                VmValue::Tuple(vec![
                    VmValue::String("nope".to_owned()),
                    VmValue::String("ALPHA".to_owned()),
                ]),
                vm_int(0),
                vm_int(16),
            ],
            vec![],
        )
        .expect("endswith should succeed");
        assert_eq!(endswith, NativeMethodResult::Value(VmValue::Bool(true)));

        let split = call_native_method(
            VmValue::String(" a  b c ".to_owned()),
            "split",
            vec![VmValue::None, vm_int(1)],
            vec![],
        )
        .expect("split should succeed");
        assert_eq!(
            split,
            NativeMethodResult::Value(VmValue::List(vec![
                VmValue::String("a".to_owned()),
                VmValue::String("b c ".to_owned()),
            ]))
        );
    }

    #[test]
    fn supports_list_and_dict_helper_methods() {
        let index = call_native_method(
            VmValue::List(vec![vm_int(1), vm_int(2), vm_int(2), vm_int(3)]),
            "index",
            vec![vm_int(2), vm_int(2)],
            vec![],
        )
        .expect("list.index should succeed");
        assert_eq!(index, NativeMethodResult::Value(vm_int(2)));

        let copied = call_native_method(
            VmValue::List(vec![vm_int(1), vm_int(2)]),
            "copy",
            vec![],
            vec![],
        )
        .expect("list.copy should succeed");
        assert_eq!(
            copied,
            NativeMethodResult::Value(VmValue::List(vec![vm_int(1), vm_int(2)]))
        );

        let popped = call_native_method(
            VmValue::Dict(vec![
                (VmValue::String("alpha".to_owned()), vm_int(1)),
                (VmValue::String("beta".to_owned()), vm_int(2)),
            ]),
            "pop",
            vec![VmValue::String("beta".to_owned())],
            vec![],
        )
        .expect("dict.pop should succeed");
        assert_eq!(
            popped,
            NativeMethodResult::Mutated {
                receiver: VmValue::Dict(vec![(VmValue::String("alpha".to_owned()), vm_int(1))]),
                value: vm_int(2),
            }
        );

        let cleared = call_native_method(
            VmValue::Dict(vec![(VmValue::String("alpha".to_owned()), vm_int(1))]),
            "clear",
            vec![],
            vec![],
        )
        .expect("dict.clear should succeed");
        assert_eq!(
            cleared,
            NativeMethodResult::Mutated {
                receiver: VmValue::Dict(Vec::new()),
                value: VmValue::None,
            }
        );
    }

    #[test]
    fn supports_decimal_pow_for_integer_and_square_root_exponents() {
        let nine = VmDecimal::from_str_literal("9").expect("decimal literal should parse");
        let square_root = nine
            .pow(&VmDecimal::from_str_literal("0.5").expect("decimal exponent should parse"))
            .expect("square root exponent should succeed");
        assert_eq!(
            square_root,
            VmDecimal::from_str_literal("3").expect("expected decimal should parse")
        );

        let fractional = VmDecimal::from_str_literal("0.1").expect("decimal literal should parse");
        let cubic = fractional
            .pow(&VmDecimal::from_str_literal("3.0").expect("decimal exponent should parse"))
            .expect("integer-like decimal exponent should succeed");
        assert_eq!(
            cubic,
            VmDecimal::from_str_literal("0.001").expect("expected decimal should parse")
        );
    }

    #[test]
    fn hash_syscalls_separate_text_and_hex_inputs() {
        let text = hash_sha3_256_text(vec![VmValue::String("68656c6c6f".to_owned())], vec![])
            .expect("text hash should succeed");
        let decoded = hash_sha3_256_hex(vec![VmValue::String("68656c6c6f".to_owned())], vec![])
            .expect("hex hash should succeed");

        assert_eq!(
            text,
            VmValue::String(hex::encode(Sha3_256::digest("68656c6c6f".as_bytes())))
        );
        assert_eq!(
            decoded,
            VmValue::String(hex::encode(Sha3_256::digest(b"hello")))
        );
        assert_ne!(text, decoded);

        let error = hash_sha3_256_hex(vec![VmValue::String("68 65".to_owned())], vec![])
            .expect_err("hex mode should reject whitespace");
        assert!(error.to_string().contains("hash hex input"));
    }

    #[test]
    fn integer_arithmetic_rejects_oversized_results() {
        let huge = BigInt::from(1u8) << (MAX_INTEGER_BITS as usize);
        let mul_error = apply_binary_operator("mul", VmValue::Int(huge), vm_int(2))
            .expect_err("oversized multiplication should fail");
        assert!(mul_error
            .to_string()
            .contains("integer multiplication exceeds"));

        let pow_error = apply_binary_operator("pow", vm_int(2), vm_int(MAX_INTEGER_BITS))
            .expect_err("oversized exponentiation should fail");
        assert!(pow_error
            .to_string()
            .contains("integer exponentiation exceeds"));

        let shift_error = apply_binary_operator("lshift", vm_int(1), vm_int(MAX_INTEGER_BITS))
            .expect_err("oversized left shift should fail");
        assert!(shift_error.to_string().contains("left shift exceeds"));
    }

    #[test]
    fn int_input_size_guard_rejects_oversized_strings() {
        let value = "9".repeat(MAX_INT_STRING_CHARS + 1);
        let error = ensure_int_input_size(&value).expect_err("oversized int input should fail");
        assert!(error.to_string().contains("int() input exceeds"));
    }

    #[test]
    fn delegates_zk_syscalls_to_host() {
        let span = json!({"line": 1, "col": 0, "end_line": 1, "end_col": 1});
        let module = parse_module_ir(
            &json!({
                "ir_version": XIAN_IR_V1,
                "vm_profile": XIAN_VM_V1_PROFILE,
                "host_catalog_version": XIAN_VM_HOST_CATALOG_V1,
                "module_name": "zk_probe",
                "source_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "docstring": null,
                "imports": [],
                "global_declarations": [],
                "functions": [
                    {
                        "node": "function",
                        "span": span.clone(),
                        "name": "probe",
                        "visibility": "export",
                        "decorator": null,
                        "docstring": null,
                        "parameters": [
                            {
                                "name": "payload",
                                "kind": "positional_or_keyword",
                                "annotation": "str",
                                "default": null,
                                "span": span.clone()
                            }
                        ],
                        "returns": null,
                        "body": [
                            {
                                "node": "assign",
                                "span": span.clone(),
                                "targets": [
                                    {
                                        "node": "name",
                                        "span": span.clone(),
                                        "id": "verified",
                                        "host_binding_id": null
                                    }
                                ],
                                "value": {
                                    "node": "call",
                                    "span": span.clone(),
                                    "func": {
                                        "node": "attribute",
                                        "span": span.clone(),
                                        "value": {
                                            "node": "name",
                                            "span": span.clone(),
                                            "id": "zk",
                                            "host_binding_id": null
                                        },
                                        "attr": "verify_groth16",
                                        "path": "zk.verify_groth16",
                                        "host_binding_id": "zk.verify_groth16"
                                    },
                                    "args": [
                                        {
                                            "node": "constant",
                                            "span": span.clone(),
                                            "value_type": "str",
                                            "value": "vk-main"
                                        },
                                        {
                                            "node": "constant",
                                            "span": span.clone(),
                                            "value_type": "str",
                                            "value": "proof-main"
                                        },
                                        {
                                            "node": "list",
                                            "span": span.clone(),
                                            "elements": [
                                                {
                                                    "node": "name",
                                                    "span": span.clone(),
                                                    "id": "payload",
                                                    "host_binding_id": null
                                                },
                                                {
                                                    "node": "constant",
                                                    "span": span.clone(),
                                                    "value_type": "str",
                                                    "value": "42"
                                                }
                                            ]
                                        }
                                    ],
                                    "keywords": [],
                                    "syscall_id": "zk.verify_groth16"
                                }
                            },
                            {
                                "node": "assign",
                                "span": span.clone(),
                                "targets": [
                                    {
                                        "node": "name",
                                        "span": span.clone(),
                                        "id": "digest",
                                        "host_binding_id": null
                                    }
                                ],
                                "value": {
                                    "node": "call",
                                    "span": span.clone(),
                                    "func": {
                                        "node": "attribute",
                                        "span": span.clone(),
                                        "value": {
                                            "node": "name",
                                            "span": span.clone(),
                                            "id": "zk",
                                            "host_binding_id": null
                                        },
                                        "attr": "shielded_output_payload_hash",
                                        "path": "zk.shielded_output_payload_hash",
                                        "host_binding_id": "zk.shielded_output_payload_hash"
                                    },
                                    "args": [
                                        {
                                            "node": "name",
                                            "span": span.clone(),
                                            "id": "payload",
                                            "host_binding_id": null
                                        }
                                    ],
                                    "keywords": [],
                                    "syscall_id": "zk.shielded_output_payload_hash"
                                }
                            },
                            {
                                "node": "return",
                                "span": span.clone(),
                                "value": {
                                    "node": "dict",
                                    "span": span.clone(),
                                    "entries": [
                                        {
                                            "key": {
                                                "node": "constant",
                                                "span": span.clone(),
                                                "value_type": "str",
                                                "value": "verified"
                                            },
                                            "value": {
                                                "node": "name",
                                                "span": span.clone(),
                                                "id": "verified",
                                                "host_binding_id": null
                                            }
                                        },
                                        {
                                            "key": {
                                                "node": "constant",
                                                "span": span.clone(),
                                                "value_type": "str",
                                                "value": "digest"
                                            },
                                            "value": {
                                                "node": "name",
                                                "span": span.clone(),
                                                "id": "digest",
                                                "host_binding_id": null
                                            }
                                        }
                                    ]
                                }
                            }
                        ]
                    }
                ],
                "module_body": [],
                "host_dependencies": [
                    {"binding": "zk.verify_groth16", "id": "zk.verify_groth16", "kind": "syscall", "category": "zk"},
                    {"binding": "zk.shielded_output_payload_hash", "id": "zk.shielded_output_payload_hash", "kind": "syscall", "category": "zk"}
                ]
            })
            .to_string(),
        )
        .expect("module should parse");

        let mut instance = VmInstance::new(module, VmExecutionContext::default())
            .expect("instance should initialize");
        let mut host = SyscallRecordingHost::default();

        let result = instance
            .call_function(
                &mut host,
                "probe",
                vec![VmValue::String("0x1234".to_owned())],
                vec![],
            )
            .expect("call should execute");

        let VmValue::Dict(entries) = result else {
            panic!("expected dict result");
        };
        assert_eq!(
            dict_get(&entries, &VmValue::String("verified".to_owned())),
            Some(VmValue::Bool(true))
        );
        assert_eq!(
            dict_get(&entries, &VmValue::String("digest".to_owned())),
            Some(VmValue::String("0x".to_owned() + &"ab".repeat(32)))
        );
        assert_eq!(host.syscalls.len(), 2);
        assert_eq!(host.syscalls[0].0, "zk.verify_groth16");
        assert_eq!(
            host.syscalls[0].1,
            vec![
                VmValue::String("vk-main".to_owned()),
                VmValue::String("proof-main".to_owned()),
                VmValue::List(vec![
                    VmValue::String("0x1234".to_owned()),
                    VmValue::String("42".to_owned()),
                ]),
            ]
        );
        assert_eq!(host.syscalls[1].0, "zk.shielded_output_payload_hash");
        assert_eq!(
            host.syscalls[1].1,
            vec![VmValue::String("0x1234".to_owned())]
        );
    }

    #[test]
    fn evaluates_list_comprehensions() {
        let span = json!({"line": 1, "col": 0, "end_line": 1, "end_col": 1});
        let module = parse_module_ir(
            &json!({
                "ir_version": XIAN_IR_V1,
                "vm_profile": XIAN_VM_V1_PROFILE,
                "host_catalog_version": XIAN_VM_HOST_CATALOG_V1,
                "module_name": "list_comp_probe",
                "source_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "docstring": null,
                "imports": [],
                "global_declarations": [],
                "functions": [
                    {
                        "node": "function",
                        "span": span.clone(),
                        "name": "positives",
                        "visibility": "export",
                        "decorator": null,
                        "docstring": null,
                        "parameters": [
                            {
                                "name": "values",
                                "kind": "positional_or_keyword",
                                "annotation": "list[int]",
                                "default": null,
                                "span": span.clone()
                            }
                        ],
                        "returns": null,
                        "body": [
                            {
                                "node": "return",
                                "span": span.clone(),
                                "value": {
                                    "node": "list_comp",
                                    "span": span.clone(),
                                    "element": {
                                        "node": "name",
                                        "span": span.clone(),
                                        "id": "value",
                                        "host_binding_id": null
                                    },
                                    "generators": [
                                        {
                                            "target": {
                                                "node": "name",
                                                "span": span.clone(),
                                                "id": "value",
                                                "host_binding_id": null
                                            },
                                            "iter": {
                                                "node": "name",
                                                "span": span.clone(),
                                                "id": "values",
                                                "host_binding_id": null
                                            },
                                            "ifs": [
                                                {
                                                    "node": "compare",
                                                    "span": span.clone(),
                                                    "left": {
                                                        "node": "name",
                                                        "span": span.clone(),
                                                        "id": "value",
                                                        "host_binding_id": null
                                                    },
                                                    "operators": ["gt"],
                                                    "comparators": [
                                                        {
                                                            "node": "constant",
                                                            "span": span.clone(),
                                                            "value_type": "int",
                                                            "value": 0
                                                        }
                                                    ]
                                                }
                                            ]
                                        }
                                    ]
                                }
                            }
                        ]
                    }
                ],
                "module_body": [],
                "host_dependencies": []
            })
            .to_string(),
        )
        .expect("module should parse");

        let mut instance = VmInstance::new(module, VmExecutionContext::default())
            .expect("instance should initialize");
        let mut host = RecordingHost::default();

        let result = instance
            .call_function(
                &mut host,
                "positives",
                vec![VmValue::List(vec![
                    vm_int(-2),
                    vm_int(0),
                    vm_int(3),
                    vm_int(5),
                ])],
                vec![],
            )
            .expect("call should execute");

        assert_eq!(result, VmValue::List(vec![vm_int(3), vm_int(5)]));
    }

    #[test]
    fn evaluates_dict_comprehensions() {
        let span = json!({"line": 1, "col": 0, "end_line": 1, "end_col": 1});
        let module = parse_module_ir(
            &json!({
                "ir_version": XIAN_IR_V1,
                "vm_profile": XIAN_VM_V1_PROFILE,
                "host_catalog_version": XIAN_VM_HOST_CATALOG_V1,
                "module_name": "dict_comp_probe",
                "source_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "docstring": null,
                "imports": [],
                "global_declarations": [],
                "functions": [
                    {
                        "node": "function",
                        "span": span.clone(),
                        "name": "prices",
                        "visibility": "export",
                        "decorator": null,
                        "docstring": null,
                        "parameters": [
                            {
                                "name": "values",
                                "kind": "positional_or_keyword",
                                "annotation": "list[int]",
                                "default": null,
                                "span": span.clone()
                            }
                        ],
                        "returns": null,
                        "body": [
                            {
                                "node": "return",
                                "span": span.clone(),
                                "value": {
                                    "node": "dict_comp",
                                    "span": span.clone(),
                                    "key": {
                                        "node": "call",
                                        "span": span.clone(),
                                        "func": {
                                            "node": "name",
                                            "span": span.clone(),
                                            "id": "str",
                                            "host_binding_id": null
                                        },
                                        "args": [
                                            {
                                                "node": "name",
                                                "span": span.clone(),
                                                "id": "value",
                                                "host_binding_id": null
                                            }
                                        ],
                                        "keywords": []
                                    },
                                    "value": {
                                        "node": "bin_op",
                                        "span": span.clone(),
                                        "operator": "mul",
                                        "left": {
                                            "node": "name",
                                            "span": span.clone(),
                                            "id": "value",
                                            "host_binding_id": null
                                        },
                                        "right": {
                                            "node": "constant",
                                            "span": span.clone(),
                                            "value_type": "int",
                                            "value": 2
                                        }
                                    },
                                    "generators": [
                                        {
                                            "target": {
                                                "node": "name",
                                                "span": span.clone(),
                                                "id": "value",
                                                "host_binding_id": null
                                            },
                                            "iter": {
                                                "node": "name",
                                                "span": span.clone(),
                                                "id": "values",
                                                "host_binding_id": null
                                            },
                                            "ifs": [
                                                {
                                                    "node": "compare",
                                                    "span": span.clone(),
                                                    "left": {
                                                        "node": "name",
                                                        "span": span.clone(),
                                                        "id": "value",
                                                        "host_binding_id": null
                                                    },
                                                    "operators": ["gt"],
                                                    "comparators": [
                                                        {
                                                            "node": "constant",
                                                            "span": span.clone(),
                                                            "value_type": "int",
                                                            "value": 0
                                                        }
                                                    ]
                                                }
                                            ]
                                        }
                                    ]
                                }
                            }
                        ]
                    }
                ],
                "module_body": [],
                "host_dependencies": []
            })
            .to_string(),
        )
        .expect("module should parse");

        let mut instance = VmInstance::new(module, VmExecutionContext::default())
            .expect("instance should initialize");
        let mut host = RecordingHost::default();

        let result = instance
            .call_function(
                &mut host,
                "prices",
                vec![VmValue::List(vec![
                    vm_int(-2),
                    vm_int(0),
                    vm_int(3),
                    vm_int(5),
                ])],
                vec![],
            )
            .expect("call should execute");

        let VmValue::Dict(entries) = result else {
            panic!("expected dict result");
        };
        assert_eq!(
            dict_get(&entries, &VmValue::String("3".to_owned())),
            Some(vm_int(6))
        );
        assert_eq!(
            dict_get(&entries, &VmValue::String("5".to_owned())),
            Some(vm_int(10))
        );
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn evaluates_dict_unpacking() {
        let span = json!({"line": 1, "col": 0, "end_line": 1, "end_col": 1});
        let module = parse_module_ir(
            &json!({
                "ir_version": XIAN_IR_V1,
                "vm_profile": XIAN_VM_V1_PROFILE,
                "host_catalog_version": XIAN_VM_HOST_CATALOG_V1,
                "module_name": "dict_unpack_probe",
                "source_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "docstring": null,
                "imports": [],
                "global_declarations": [],
                "functions": [
                    {
                        "node": "function",
                        "span": span.clone(),
                        "name": "payload",
                        "visibility": "export",
                        "decorator": null,
                        "docstring": null,
                        "parameters": [
                            {
                                "name": "base",
                                "kind": "positional_or_keyword",
                                "annotation": "dict",
                                "default": null,
                                "span": span.clone()
                            },
                            {
                                "name": "override",
                                "kind": "positional_or_keyword",
                                "annotation": "dict",
                                "default": null,
                                "span": span.clone()
                            }
                        ],
                        "returns": null,
                        "body": [
                            {
                                "node": "return",
                                "span": span.clone(),
                                "value": {
                                    "node": "dict",
                                    "span": span.clone(),
                                    "entries": [
                                        {
                                            "unpack": {
                                                "node": "name",
                                                "span": span.clone(),
                                                "id": "base",
                                                "host_binding_id": null
                                            }
                                        },
                                        {
                                            "key": {
                                                "node": "constant",
                                                "span": span.clone(),
                                                "value_type": "str",
                                                "value": "kind"
                                            },
                                            "value": {
                                                "node": "constant",
                                                "span": span.clone(),
                                                "value_type": "str",
                                                "value": "price"
                                            }
                                        },
                                        {
                                            "unpack": {
                                                "node": "name",
                                                "span": span.clone(),
                                                "id": "override",
                                                "host_binding_id": null
                                            }
                                        }
                                    ]
                                }
                            }
                        ]
                    }
                ],
                "module_body": [],
                "host_dependencies": []
            })
            .to_string(),
        )
        .expect("module should parse");

        let mut instance = VmInstance::new(module, VmExecutionContext::default())
            .expect("instance should initialize");
        let mut host = RecordingHost::default();

        let result = instance
            .call_function(
                &mut host,
                "payload",
                vec![
                    VmValue::Dict(vec![
                        (
                            VmValue::String("symbol".to_owned()),
                            VmValue::String("XIAN".to_owned()),
                        ),
                        (VmValue::String("value".to_owned()), vm_int(42)),
                    ]),
                    VmValue::Dict(vec![(VmValue::String("value".to_owned()), vm_int(77))]),
                ],
                vec![],
            )
            .expect("call should execute");

        assert_eq!(
            result,
            VmValue::Dict(vec![
                (
                    VmValue::String("symbol".to_owned()),
                    VmValue::String("XIAN".to_owned())
                ),
                (VmValue::String("value".to_owned()), vm_int(42)),
                (
                    VmValue::String("kind".to_owned()),
                    VmValue::String("price".to_owned())
                ),
                (VmValue::String("value".to_owned()), vm_int(77)),
            ])
        );
    }

    #[test]
    fn executes_while_loops() {
        let span = json!({"line": 1, "col": 0, "end_line": 1, "end_col": 1});
        let module = parse_module_ir(
            &json!({
                "ir_version": XIAN_IR_V1,
                "vm_profile": XIAN_VM_V1_PROFILE,
                "host_catalog_version": XIAN_VM_HOST_CATALOG_V1,
                "module_name": "while_probe",
                "source_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "docstring": null,
                "imports": [],
                "global_declarations": [],
                "functions": [
                    {
                        "node": "function",
                        "span": span.clone(),
                        "name": "countdown",
                        "visibility": "export",
                        "decorator": null,
                        "docstring": null,
                        "parameters": [
                            {
                                "name": "value",
                                "kind": "positional_or_keyword",
                                "annotation": "int",
                                "default": null,
                                "span": span.clone()
                            }
                        ],
                        "returns": null,
                        "body": [
                            {
                                "node": "while",
                                "span": span.clone(),
                                "test": {
                                    "node": "compare",
                                    "span": span.clone(),
                                    "left": {
                                        "node": "name",
                                        "span": span.clone(),
                                        "id": "value",
                                        "host_binding_id": null
                                    },
                                    "operators": ["gt"],
                                    "comparators": [
                                        {
                                            "node": "constant",
                                            "span": span.clone(),
                                            "value_type": "int",
                                            "value": 0
                                        }
                                    ]
                                },
                                "body": [
                                    {
                                        "node": "assign",
                                        "span": span.clone(),
                                        "targets": [
                                            {
                                                "node": "name",
                                                "span": span.clone(),
                                                "id": "value",
                                                "host_binding_id": null
                                            }
                                        ],
                                        "value": {
                                            "node": "bin_op",
                                            "span": span.clone(),
                                            "operator": "sub",
                                            "left": {
                                                "node": "name",
                                                "span": span.clone(),
                                                "id": "value",
                                                "host_binding_id": null
                                            },
                                            "right": {
                                                "node": "constant",
                                                "span": span.clone(),
                                                "value_type": "int",
                                                "value": 1
                                            }
                                        }
                                    }
                                ],
                                "orelse": []
                            },
                            {
                                "node": "return",
                                "span": span.clone(),
                                "value": {
                                    "node": "name",
                                    "span": span.clone(),
                                    "id": "value",
                                    "host_binding_id": null
                                }
                            }
                        ]
                    }
                ],
                "module_body": [],
                "host_dependencies": []
            })
            .to_string(),
        )
        .expect("module should parse");

        let mut instance = VmInstance::new(module, VmExecutionContext::default())
            .expect("instance should initialize");
        let mut host = RecordingHost::default();

        let result = instance
            .call_function(&mut host, "countdown", vec![vm_int(4)], vec![])
            .expect("call should execute");

        assert_eq!(result, vm_int(0));
    }

    #[test]
    fn formats_assert_failures_like_python_repr() {
        let span = json!({"line": 1, "col": 0, "end_line": 1, "end_col": 1});
        let module = parse_module_ir(
            &json!({
                "ir_version": XIAN_IR_V1,
                "vm_profile": XIAN_VM_V1_PROFILE,
                "host_catalog_version": XIAN_VM_HOST_CATALOG_V1,
                "module_name": "assert_probe",
                "source_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "docstring": null,
                "imports": [],
                "global_declarations": [],
                "functions": [
                    {
                        "node": "function",
                        "span": span.clone(),
                        "name": "must_be_positive",
                        "visibility": "export",
                        "decorator": null,
                        "docstring": null,
                        "parameters": [
                            {
                                "name": "value",
                                "kind": "positional_or_keyword",
                                "annotation": "int",
                                "default": null,
                                "span": span.clone()
                            }
                        ],
                        "returns": null,
                        "body": [
                            {
                                "node": "assert",
                                "span": span.clone(),
                                "test": {
                                    "node": "compare",
                                    "span": span.clone(),
                                    "left": {
                                        "node": "name",
                                        "span": span.clone(),
                                        "id": "value",
                                        "host_binding_id": null
                                    },
                                    "operators": ["gt"],
                                    "comparators": [
                                        {
                                            "node": "constant",
                                            "span": span.clone(),
                                            "value_type": "int",
                                            "value": 0
                                        }
                                    ]
                                },
                                "message": {
                                    "node": "constant",
                                    "span": span.clone(),
                                    "value_type": "str",
                                    "value": "value must be positive"
                                }
                            },
                            {
                                "node": "return",
                                "span": span.clone(),
                                "value": {
                                    "node": "name",
                                    "span": span.clone(),
                                    "id": "value",
                                    "host_binding_id": null
                                }
                            }
                        ]
                    }
                ],
                "module_body": [],
                "host_dependencies": []
            })
            .to_string(),
        )
        .expect("module should parse");

        let mut instance = VmInstance::new(module, VmExecutionContext::default())
            .expect("instance should initialize");
        let mut host = RecordingHost::default();

        let error = instance
            .call_function(&mut host, "must_be_positive", vec![vm_int(-1)], vec![])
            .expect_err("call should fail");

        assert_eq!(
            error.to_string(),
            "AssertionError('value must be positive')"
        );
    }

    #[test]
    fn supports_ord_builtin() {
        let span = json!({"line": 1, "col": 0, "end_line": 1, "end_col": 1});
        let module = parse_module_ir(
            &json!({
                "ir_version": XIAN_IR_V1,
                "vm_profile": XIAN_VM_V1_PROFILE,
                "host_catalog_version": XIAN_VM_HOST_CATALOG_V1,
                "module_name": "ord_probe",
                "source_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "docstring": null,
                "imports": [],
                "global_declarations": [],
                "functions": [
                    {
                        "node": "function",
                        "span": span.clone(),
                        "name": "ascii_code",
                        "visibility": "export",
                        "decorator": null,
                        "docstring": null,
                        "parameters": [
                            {
                                "name": "value",
                                "kind": "positional_or_keyword",
                                "annotation": "str",
                                "default": null,
                                "span": span.clone()
                            }
                        ],
                        "returns": null,
                        "body": [
                            {
                                "node": "return",
                                "span": span.clone(),
                                "value": {
                                    "node": "call",
                                    "span": span.clone(),
                                    "func": {
                                        "node": "name",
                                        "span": span.clone(),
                                        "id": "ord",
                                        "host_binding_id": null
                                    },
                                    "args": [
                                        {
                                            "node": "name",
                                            "span": span.clone(),
                                            "id": "value",
                                            "host_binding_id": null
                                        }
                                    ],
                                    "keywords": [],
                                    "syscall_id": null,
                                    "event_binding": null
                                }
                            }
                        ]
                    }
                ],
                "module_body": [],
                "host_dependencies": []
            })
            .to_string(),
        )
        .expect("module should parse");

        let mut instance = VmInstance::new(module, VmExecutionContext::default())
            .expect("instance should initialize");
        let mut host = RecordingHost::default();

        let result = instance
            .call_function(
                &mut host,
                "ascii_code",
                vec![VmValue::String("A".to_owned())],
                vec![],
            )
            .expect("call should execute");

        assert_eq!(result, vm_int(65));
    }
}
