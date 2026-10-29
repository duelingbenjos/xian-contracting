"""Contract metadata syscalls are only available to the submission contract."""

import pytest
from xian_runtime_types.time import Datetime

from contracting.local import ContractingClient

pytestmark = pytest.mark.optional_native

TARGET = """
@export
def ping():
    return 1
"""

CONSTRUCTOR_CHANGES_METADATA = """
@construct
def seed():
    Contract.set_developer("con_target", "mallory")

@export
def ping():
    return 1
"""

EXPORT_DEPLOYS = """
@export
def spawn():
    Contract.deploy(name="con_spawned", code="@export\\ndef ping():\\n    return 1\\n")
"""

PLAIN = """
@export
def ping():
    return 1
"""


def _context(this):
    return {
        "signer": "alice",
        "caller": "alice",
        "this": this,
        "owner": None,
        "now": Datetime(2026, 1, 1),
        "block_num": 1,
        "chain_id": "test-chain",
    }


def _submit(driver, name, code):
    import xian_vm_core

    return xian_vm_core.execute_contract(
        driver=driver,
        contract_name="submission",
        function_name="submit_contract",
        kwargs={"name": name, "code": code},
        context=_context("submission"),
        meter=True,
        chi_budget_raw=50_000_000,
    )


@pytest.fixture
def client(tmp_path):
    client = ContractingClient(storage_home=tmp_path)
    client.flush()
    client.raw_driver.set_contract_from_source("con_target", TARGET, owner=None, developer="dev")
    client.raw_driver.commit()
    yield client
    client.flush()


def test_constructor_cannot_change_another_contracts_metadata(client):
    output = _submit(client.raw_driver, "con_meta", CONSTRUCTOR_CHANGES_METADATA)

    assert output.status_code == 1
    assert "restricted to submission" in str(output.result)
    assert "con_target.__developer__" not in output.writes


def test_user_contract_cannot_deploy_contracts(client):
    import xian_vm_core

    client.raw_driver.set_contract_from_source("con_deployer", EXPORT_DEPLOYS, owner=None)
    client.raw_driver.commit()

    output = xian_vm_core.execute_contract(
        driver=client.raw_driver,
        contract_name="con_deployer",
        function_name="spawn",
        kwargs={},
        context=_context("con_deployer"),
        meter=True,
        chi_budget_raw=50_000_000,
    )

    assert output.status_code == 1
    assert "restricted to submission" in str(output.result)
    assert not any(key.startswith("con_spawned.") for key in output.writes)


def test_submission_still_deploys_contracts(client):
    output = _submit(client.raw_driver, "con_plain", PLAIN)

    assert output.status_code == 0, output.result
    assert "con_plain.__xian_ir_v1__" in output.writes
