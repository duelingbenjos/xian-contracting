import ast
import hashlib
import json
from dataclasses import dataclass
from typing import Any

from xian_runtime_types.decimal import ContractingDecimal
from xian_runtime_types.encoding import encode_kv

from contracting import constants
from contracting.artifacts import compile_contract_source
from contracting.execution.runtime import WRITE_MAX, rt
from contracting.names import assert_safe_contract_name
from contracting.runtime_features import (
    RUNTIME_FEATURE_ZK,
    module_ir_uses_runtime_feature,
    runtime_feature_enabled,
)
from contracting.stdlib.bridge import random as random_bridge
from contracting.stdlib.bridge import zk as zk_bridge
from contracting.storage.driver import (
    DEPLOYER_KEY,
    DEVELOPER_KEY,
    INITIATOR_KEY,
    OWNER_KEY,
    SOURCE_KEY,
    TIME_KEY,
    XIAN_VM_V1_IR_KEY,
)
from contracting.storage.ordered import iter_overlay_items

from ._native import (
    VmIrValidationError,
    VmRuntimeExecutionError,
    execute_bundle,
    runtime_info_json,
    supports_execution_policy,
    validate_module_ir_json,
)

_RANDOM_SYSCALLS = {
    "seed": random_bridge.seed,
    "random": random_bridge.random,
    "shuffle": random_bridge.shuffle,
    "getrandbits": random_bridge.getrandbits,
    "randrange": random_bridge.randrange,
    "randint": random_bridge.randint,
    "choice": random_bridge.choice,
    "choices": random_bridge.choices,
}


def _interface_type_name(value: Any) -> str:
    if isinstance(value, str):
        return value
    name = getattr(value, "__name__", None)
    if isinstance(name, str) and name:
        return name
    return str(value)


@dataclass(slots=True)
class NativeExecutionResult:
    status_code: int
    result: Any
    writes: dict[str, Any]
    events: list[dict[str, Any]]
    snapshots: list[dict[str, Any]]
    raw_cost: int
    chi_used: int
    contract_costs: dict[str, int]


def runtime_info() -> dict:
    return json.loads(runtime_info_json())


def validate_module_ir(module_ir: dict | str) -> None:
    payload = (
        module_ir
        if isinstance(module_ir, str)
        else json.dumps(module_ir, separators=(",", ":"), sort_keys=True)
    )
    validate_module_ir_json(payload)


class NativeVmHost:
    def __init__(
        self,
        driver,
        *,
        vm_profile: str = "xian_vm_v1",
        entry_contract: str | None = None,
        meter_enabled: bool = False,
        context: dict[str, Any] | None = None,
    ) -> None:
        self.driver = driver
        self.vm_profile = vm_profile
        self._ir_cache: dict[str, str] = {}
        self._parsed_ir_cache: dict[str, dict[str, Any]] = {}
        self._entry_contract = entry_contract
        self._meter_enabled = meter_enabled
        self._context = dict(context or {})
        self._pending_writes: dict[str, Any] = {}
        self._pending_events: list[dict[str, Any]] = []
        self._extra_raw_cost = 0
        self._extra_contract_costs: dict[str, int] = {}
        self._written_bytes = 0

    @property
    def pending_writes(self) -> dict[str, Any]:
        return dict(self._pending_writes)

    @property
    def pending_events(self) -> list[dict[str, Any]]:
        return list(self._pending_events)

    @property
    def extra_raw_cost(self) -> int:
        return int(self._extra_raw_cost)

    @property
    def extra_contract_costs(self) -> dict[str, int]:
        return dict(self._extra_contract_costs)

    def _make_key(self, contract: str, variable: str, args=None) -> str:
        return self.driver.make_key(contract, variable, args)

    def _lookup_key(self, key: str):
        if key in self._pending_writes:
            return self._pending_writes[key]
        return self.driver.get(key)

    def _contract_var(self, contract: str, variable: str):
        return self._lookup_key(self._make_key(contract, variable))

    def _stage_write(self, key: str, value: Any) -> None:
        self._pending_writes[key] = value

    def _record_raw_cost(self, raw_cost: int, *, contract: str | None = None):
        raw_cost = int(raw_cost)
        if raw_cost <= 0:
            return
        self._extra_raw_cost += raw_cost
        target_contract = contract or self._entry_contract
        if target_contract:
            self._extra_contract_costs[target_contract] = (
                self._extra_contract_costs.get(target_contract, 0) + raw_cost
            )

    def _add_raw_cost(self, raw_cost: int) -> None:
        raw_cost = int(raw_cost)
        if raw_cost > 0:
            self._extra_raw_cost += raw_cost

    def _write_raw_cost(self, key: str, value: Any) -> int:
        encoded_key, encoded_value = encode_kv(key, value)
        return (len(encoded_key) + len(encoded_value)) * constants.WRITE_COST_PER_BYTE

    def _charge_host_write(
        self,
        key: str,
        value: Any,
        *,
        enforce_write_cap: bool = True,
    ) -> None:
        if not self._meter_enabled:
            return
        encoded_key, encoded_value = encode_kv(key, value)
        written = len(encoded_key) + len(encoded_value)
        if enforce_write_cap:
            self._written_bytes += written
            if self._written_bytes >= WRITE_MAX:
                raise VmRuntimeExecutionError(
                    "AssertionError('You have exceeded the maximum write capacity "
                    "per transaction!')"
                )
        self._record_raw_cost(written * constants.WRITE_COST_PER_BYTE)

    def read_variable(self, contract: str, binding: str):
        return self._lookup_key(self._make_key(contract, binding))

    def read_hash(self, contract: str, binding: str, key):
        return self._lookup_key(self._make_key(contract, binding, _hash_key_args(key)))

    def iter_hash_entries(self, contract: str, binding: str, prefix: str):
        base_key = self._make_key(contract, binding)
        full_prefix = f"{base_key}{constants.DELIMITER}"
        if prefix:
            full_prefix = f"{full_prefix}{prefix}{constants.DELIMITER}"
        suffix_offset = len(base_key) + len(constants.DELIMITER)
        for key, value in iter_overlay_items(
            self._pending_writes, self.driver.iter_items(full_prefix), full_prefix
        ):
            yield key[suffix_offset:], value

    def scan_hash_entries(self, contract: str, binding: str, prefix: str) -> list[tuple[str, Any]]:
        return list(self.iter_hash_entries(contract, binding, prefix))

    def get_owner(self, contract: str):
        return self._contract_var(contract, OWNER_KEY)

    def load_module_ir_json(self, module_name: str):
        cached = self._ir_cache.get(module_name)
        if cached is not None:
            return cached
        pending_ir = self._contract_var(module_name, XIAN_VM_V1_IR_KEY)
        if isinstance(pending_ir, str) and pending_ir:
            self._ir_cache[module_name] = pending_ir
            return pending_ir
        get_contract_ir = getattr(self.driver, "get_contract_ir", None)
        payload = None
        if get_contract_ir is not None:
            payload = get_contract_ir(
                module_name,
                vm_profile=self.vm_profile,
            )
            if not isinstance(payload, str) or not payload:
                payload = None
        if payload is None:
            return None
        self._ir_cache[module_name] = payload
        return payload

    def load_module_ir(self, module_name: str) -> dict[str, Any] | None:
        cached = self._parsed_ir_cache.get(module_name)
        if cached is not None:
            self._reject_disabled_runtime_features(module_name, cached)
            return cached
        module_ir_json = self.load_module_ir_json(module_name)
        if not module_ir_json:
            return None
        module_ir = json.loads(module_ir_json)
        self._reject_disabled_runtime_features(module_name, module_ir)
        self._parsed_ir_cache[module_name] = module_ir
        return module_ir

    def _reject_disabled_runtime_features(
        self, module_name: str, module_ir: dict[str, Any]
    ) -> None:
        if module_ir_uses_runtime_feature(
            module_ir,
            RUNTIME_FEATURE_ZK,
        ) and not runtime_feature_enabled(
            self.driver,
            RUNTIME_FEATURE_ZK,
            default_enabled=True,
        ):
            raise VmRuntimeExecutionError(
                f"contract '{module_name}' uses zk host syscalls, "
                "but the chain zk runtime feature is disabled"
            )

    def _contract_exists(self, contract: str) -> bool:
        for artifact_key in (XIAN_VM_V1_IR_KEY, SOURCE_KEY):
            pending_artifact = self._contract_var(contract, artifact_key)
            if pending_artifact is not None:
                return True
        has_contract = getattr(self.driver, "has_contract", None)
        if callable(has_contract):
            return bool(has_contract(contract))
        return False

    def _contract_has_export(self, contract: str, export_name: str) -> bool:
        module_ir = self.load_module_ir(contract)
        if not module_ir:
            return False
        for function in module_ir.get("functions", []):
            if function.get("name") == export_name and function.get("visibility") == "export":
                return True
        return False

    def _contract_enforce_interface(
        self,
        contract: str,
        interface: list[dict[str, Any]],
    ) -> bool:
        module_ir = self.load_module_ir(contract)
        if not module_ir:
            return False

        functions = {
            function.get("name"): function
            for function in module_ir.get("functions", [])
            if isinstance(function, dict)
        }
        storages = {
            declaration.get("name"): declaration.get("storage_type")
            for declaration in module_ir.get("global_declarations", [])
            if isinstance(declaration, dict) and declaration.get("node") == "storage_decl"
        }

        for item in interface:
            if not isinstance(item, dict):
                raise VmRuntimeExecutionError("contract interface entries must be dict descriptors")
            kind = item.get("__vm_interface__")
            if kind == "func":
                function = functions.get(item.get("name"))
                if function is None:
                    return False
                expected_visibility = "private" if item.get("private") else "export"
                if function.get("visibility") != expected_visibility:
                    return False
                expected_args = tuple(item.get("args", ()))
                actual_args = tuple(
                    parameter.get("name")
                    for parameter in function.get("params", [])
                    if isinstance(parameter, dict)
                )
                if actual_args != expected_args:
                    return False
                continue
            if kind == "var":
                if storages.get(item.get("name")) != item.get("type"):
                    return False
                continue
            raise VmRuntimeExecutionError(f"unsupported interface descriptor kind '{kind}'")

        return True

    def _stage_contract_metadata_write(self, contract: str, variable: str, value: Any) -> None:
        key = self._make_key(contract, variable)
        self._stage_write(key, value)
        self._charge_host_write(key, value, enforce_write_cap=False)

    def _require_submission_metadata_context(self) -> None:
        active_contract = self._context.get("this")
        if not isinstance(active_contract, str) or active_contract == "":
            return
        if active_contract != constants.SUBMISSION_CONTRACT_NAME:
            raise AssertionError("Contract metadata changes are restricted to submission.")

    def _stage_contract_deploy(
        self,
        *,
        name: str,
        code: str | None,
        owner: str | None,
        constructor_args: dict | None,
        developer: str | None,
        deployer: str | None,
        initiator: str | None,
    ) -> None:
        assert_safe_contract_name(name)
        if self._contract_exists(name):
            raise VmRuntimeExecutionError("Contract already exists.")
        if not isinstance(code, str) or code == "":
            raise VmRuntimeExecutionError(
                "native contract deployment requires non-empty source code"
            )

        artifacts = compile_contract_source(
            module_name=name,
            source=code,
            lint=True,
            vm_profile=self.vm_profile,
        )
        source = artifacts["source"]
        vm_ir_json = artifacts["vm_ir_json"]

        module_ir = json.loads(vm_ir_json)
        validate_module_ir(module_ir)
        self._reject_disabled_runtime_features(name, module_ir)

        deployment_developer = developer or self._context.get("caller")
        deployment_deployer = deployer or self._context.get("caller")
        deployment_initiator = initiator or self._context.get("signer")
        submitted_at = self._context.get("now")
        if submitted_at is None:
            raise VmRuntimeExecutionError(
                "native contract deployment requires deterministic now context"
            )

        constructor_writes: dict[str, Any] = {}
        constructor_events: list[dict[str, Any]] = []
        previous_ir = self._ir_cache.get(name)
        previous_parsed_ir = self._parsed_ir_cache.get(name)
        self._ir_cache[name] = vm_ir_json
        self._parsed_ir_cache[name] = module_ir
        try:
            construct_name = _construct_function_name(module_ir)
            if construct_name is not None:
                constructor_context = {
                    "signer": deployment_initiator,
                    "caller": deployment_deployer,
                    "this": name,
                    "entry": self._context.get("entry"),
                    "owner": owner,
                    "submission_name": name,
                    "now": self._context.get("now"),
                    "block_num": self._context.get("block_num"),
                    "block_hash": self._context.get("block_hash"),
                    "chain_id": self._context.get("chain_id"),
                }
                raw = execute_bundle(
                    json.dumps(
                        {name: module_ir},
                        separators=(",", ":"),
                        sort_keys=True,
                    ),
                    name,
                    construct_name,
                    [],
                    _coerce_external_call_kwargs(dict(constructor_args or {})),
                    constructor_context,
                    self,
                    meter=self._meter_enabled,
                    chi_budget_raw=0,
                    transaction_size_bytes=0,
                )
                if int(raw["status_code"]) != 0:
                    raise VmRuntimeExecutionError(f"contract constructor failed: {raw['result']}")
                constructor_writes = {
                    **_snapshots_to_writes(
                        self.driver,
                        raw["snapshots"],
                    ),
                    **dict(raw.get("storage_writes") or {}),
                }
                constructor_events = list(raw["events"])
                self._extra_contract_costs = _merge_contract_costs(
                    self._extra_contract_costs,
                    dict(raw.get("contract_costs") or {}),
                )
                self._add_raw_cost(int(raw.get("raw_cost", 0)))
        except Exception:
            if previous_ir is None:
                self._ir_cache.pop(name, None)
            else:
                self._ir_cache[name] = previous_ir
            if previous_parsed_ir is None:
                self._parsed_ir_cache.pop(name, None)
            else:
                self._parsed_ir_cache[name] = previous_parsed_ir
            raise

        metadata_writes = {
            self._make_key(name, SOURCE_KEY): source,
            self._make_key(name, XIAN_VM_V1_IR_KEY): vm_ir_json,
            self._make_key(name, OWNER_KEY): owner,
            self._make_key(name, TIME_KEY): submitted_at,
            self._make_key(name, DEVELOPER_KEY): deployment_developer,
            self._make_key(name, DEPLOYER_KEY): deployment_deployer,
            self._make_key(name, INITIATOR_KEY): deployment_initiator,
        }
        for key, value in constructor_writes.items():
            self._stage_write(key, value)
        for key, value in metadata_writes.items():
            self._stage_write(key, value)
            if value is not None:
                self._charge_host_write(
                    key,
                    value,
                    enforce_write_cap=False,
                )

        self._pending_events.extend(constructor_events)
        self._record_raw_cost(
            constants.DEPLOYMENT_BASE_COST
            + (len(source.encode("utf-8")) * constants.DEPLOYMENT_COST_PER_SOURCE_BYTE)
        )

    def handle_syscall(self, syscall_id: str, args, kwargs):
        kwargs = dict(kwargs or {})
        if syscall_id == "contract.exists":
            return self._contract_exists(args[0])
        if syscall_id == "contract.has_export":
            return self._contract_has_export(args[0], args[1])
        if syscall_id == "contract.owner_of":
            return self._contract_var(args[0], OWNER_KEY)
        if syscall_id == "contract.info":
            return {
                "name": args[0],
                "owner": self._contract_var(args[0], OWNER_KEY),
                "developer": self._contract_var(args[0], DEVELOPER_KEY),
                "deployer": self._contract_var(args[0], DEPLOYER_KEY),
                "initiator": self._contract_var(args[0], INITIATOR_KEY),
                "submitted": self._contract_var(args[0], TIME_KEY),
            }
        if syscall_id == "contract.set_owner":
            self._require_submission_metadata_context()
            self._stage_contract_metadata_write(args[0], OWNER_KEY, args[1])
            return None
        if syscall_id == "contract.set_developer":
            self._require_submission_metadata_context()
            self._stage_contract_metadata_write(args[0], DEVELOPER_KEY, args[1])
            return None
        if syscall_id == "contract.deploy":
            name = kwargs.get("name", args[0] if len(args) > 0 else None)
            code = kwargs.get("code", args[1] if len(args) > 1 else None)
            owner = kwargs.get("owner")
            if owner is None and len(args) > 2:
                owner = args[2]
            constructor_args = kwargs.get("constructor_args")
            if constructor_args is None and len(args) > 3:
                constructor_args = args[3]
            developer = kwargs.get("developer")
            deployer = kwargs.get("deployer")
            initiator = kwargs.get("initiator")
            if kwargs.get("deployment_artifacts") is not None:
                raise VmRuntimeExecutionError("native contract deployment accepts source code only")
            self._stage_contract_deploy(
                name=name,
                code=code,
                owner=owner,
                constructor_args=constructor_args,
                developer=developer,
                deployer=deployer,
                initiator=initiator,
            )
            return None
        if syscall_id == "contract.code_hash":
            kind = kwargs.get("kind")
            if kind is None and len(args) > 1:
                kind = args[1]
            kind = kind or "runtime"
            if kind in {"runtime", "ir"}:
                contract_text = self._contract_var(args[0], XIAN_VM_V1_IR_KEY)
            else:
                contract_text = self._contract_var(args[0], SOURCE_KEY)
            if contract_text is None:
                return None
            return hashlib.sha3_256(contract_text.encode("utf-8")).hexdigest()
        if syscall_id == "contract.interface.func":
            name = args[0]
            declared_args = tuple(args[1]) if len(args) > 1 else ()
            return {
                "__vm_interface__": "func",
                "name": name,
                "args": declared_args,
                "private": bool(kwargs.get("private", False)),
            }
        if syscall_id == "contract.interface.var":
            return {
                "__vm_interface__": "var",
                "name": args[0],
                "type": _interface_type_name(args[1]),
            }
        if syscall_id == "contract.enforce_interface":
            contract = args[0]
            interface = list(args[1])
            return self._contract_enforce_interface(contract, interface)
        if syscall_id.startswith("random."):
            function_name = syscall_id.split(".", 1)[1]
            handler = _RANDOM_SYSCALLS.get(function_name)
            if handler is None:
                raise VmRuntimeExecutionError(f"unsupported host syscall '{syscall_id}'")
            if function_name == "shuffle":
                handler(*args, **kwargs)
                return args[0]
            return handler(*args, **kwargs)
        if syscall_id.startswith("zk."):
            function_name = syscall_id.split(".", 1)[1]
            handler = getattr(zk_bridge, function_name)
            return handler(*args, **kwargs)
        raise VmRuntimeExecutionError(f"unsupported host syscall '{syscall_id}'")


def execute_contract(
    *,
    driver,
    contract_name: str,
    function_name: str,
    args: list | None = None,
    kwargs: dict | None = None,
    context: dict | None = None,
    meter: bool = False,
    chi_budget_raw: int = 0,
    transaction_size_bytes: int = 0,
) -> NativeExecutionResult:
    coerced_args = _coerce_external_call_args(args or [])
    coerced_kwargs = _coerce_external_call_kwargs(kwargs or {})
    host = NativeVmHost(
        driver,
        entry_contract=contract_name,
        meter_enabled=meter,
        context=dict(context or {}),
    )
    module_ir = host.load_module_ir(contract_name)
    if module_ir is None:
        raise VmRuntimeExecutionError(
            "xian_vm_v1 requires persisted __xian_ir_v1__ for contract "
            f"'{contract_name}'; stored source is inspection-only"
        )
    # A contract with an owner may only be called by that owner, whether the
    # call comes from another contract or straight from a transaction.
    owner = host.get_owner(contract_name)
    if owner is not None and owner != (context or {}).get("caller"):
        return NativeExecutionResult(
            status_code=1,
            result=_coerce_native_error_result(1, 'Exception("Caller is not the owner!")'),
            writes={},
            events=[],
            snapshots=[],
            raw_cost=0,
            chi_used=constants.TRANSACTION_BASE_CHI,
            contract_costs={},
        )
    bundle_payload = {contract_name: module_ir}
    previous_env = dict(rt.env)
    rt.env = {**previous_env, **dict(context or {}), "__Driver": driver}
    random_bridge.clear_random_state()
    try:
        raw = execute_bundle(
            json.dumps(bundle_payload, separators=(",", ":"), sort_keys=True),
            contract_name,
            function_name,
            coerced_args,
            coerced_kwargs,
            dict(context or {}),
            host,
            meter=meter,
            chi_budget_raw=max(int(chi_budget_raw), 0),
            transaction_size_bytes=max(int(transaction_size_bytes), 0),
        )
    finally:
        random_bridge.clear_random_state()
        rt.env = previous_env
    result = _coerce_native_error_result(
        int(raw["status_code"]),
        raw["result"],
    )
    status_code = int(raw["status_code"])
    writes = {
        **_snapshots_to_writes(driver, raw["snapshots"]),
        **dict(raw.get("storage_writes") or {}),
    }
    events = list(raw["events"])
    if status_code == 0:
        writes = {**writes, **host.pending_writes}
        events = host.pending_events + events
    return NativeExecutionResult(
        status_code=status_code,
        result=result,
        writes=writes,
        events=events,
        snapshots=list(raw["snapshots"]),
        raw_cost=int(raw.get("raw_cost", 0)) + host.extra_raw_cost,
        chi_used=_combined_chi_used(
            raw_chi_used=int(raw.get("chi_used", 0)),
            raw_cost=int(raw.get("raw_cost", 0)),
            extra_raw_cost=host.extra_raw_cost,
            chi_budget_raw=max(int(chi_budget_raw), 0),
        ),
        contract_costs=_merge_contract_costs(
            dict(raw.get("contract_costs") or {}),
            host.extra_contract_costs,
        ),
    )


def _coerce_external_call_args(args: list[Any]) -> list[Any]:
    return [ContractingDecimal(str(value)) if isinstance(value, float) else value for value in args]


def _coerce_external_call_kwargs(kwargs: dict[str, Any]) -> dict[str, Any]:
    return {
        key: ContractingDecimal(str(value)) if isinstance(value, float) else value
        for key, value in kwargs.items()
    }


def _merge_contract_costs(left: dict[str, int], right: dict[str, int]) -> dict[str, int]:
    merged = dict(left)
    for contract, raw_cost in right.items():
        merged[contract] = int(merged.get(contract, 0)) + int(raw_cost)
    return merged


def _coerce_native_error_result(status_code: int, result: Any) -> Any:
    if int(status_code) == 0 or not isinstance(result, str):
        return result
    return _native_exception_from_repr(result) or result


def _native_exception_from_repr(result: str) -> BaseException | None:
    if result == "Contract metadata changes are restricted to submission.":
        return AssertionError(result)
    exception_types: dict[str, type[BaseException]] = {
        "AssertionError": AssertionError,
        "TypeError": TypeError,
        "ValueError": ValueError,
        "RuntimeError": RuntimeError,
        "Exception": Exception,
        "KeyError": KeyError,
        "IndexError": IndexError,
    }
    prefixed_name, separator, remainder = result.partition(": ")
    if separator == ": ":
        nested = _native_exception_from_repr(remainder)
        if nested is not None:
            return nested
        exception_type = exception_types.get(prefixed_name)
        if exception_type is not None:
            return exception_type(remainder)
    name, separator, args_repr = result.partition("(")
    if separator != "(" or not result.endswith(")"):
        return None
    exception_type = exception_types.get(name)
    if exception_type is None:
        return None
    inner = args_repr[:-1]
    if inner == "":
        return exception_type()
    try:
        args = ast.literal_eval(f"({inner},)")
    except (SyntaxError, ValueError):
        return exception_type(inner)
    if not isinstance(args, tuple):
        args = (args,)
    return exception_type(*args)


def _combined_chi_used(
    *,
    raw_chi_used: int,
    raw_cost: int,
    extra_raw_cost: int,
    chi_budget_raw: int,
) -> int:
    combined = ((int(raw_cost) + int(extra_raw_cost)) // 1000) + constants.TRANSACTION_BASE_CHI
    if chi_budget_raw > 0:
        combined = min(combined, chi_budget_raw // 1000)
    return max(combined, int(raw_chi_used))


def _snapshots_to_writes(driver, snapshots: list[dict[str, Any]]) -> dict[str, Any]:
    writes: dict[str, Any] = {}
    for snapshot in snapshots:
        contract_name = snapshot["contract_name"]
        for variable in snapshot["variables"]:
            writes[driver.make_key(contract_name, variable["binding"])] = variable["value"]
        for hash_snapshot in snapshot["hashes"]:
            binding = hash_snapshot["binding"]
            for storage_key, value in hash_snapshot["entries"].items():
                writes[driver.make_key(contract_name, binding, [storage_key])] = value
    return writes


def _hash_key_args(key) -> list[Any]:
    if isinstance(key, tuple):
        return list(key)
    return [key]


def _construct_function_name(module_ir: dict[str, Any]) -> str | None:
    for function in module_ir.get("functions", []):
        if function.get("visibility") == "construct":
            return function.get("name")
    return None


__all__ = [
    "NativeExecutionResult",
    "NativeVmHost",
    "VmIrValidationError",
    "VmRuntimeExecutionError",
    "execute_bundle",
    "execute_contract",
    "runtime_info",
    "runtime_info_json",
    "supports_execution_policy",
    "validate_module_ir",
    "validate_module_ir_json",
]
