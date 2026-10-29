"""Contract constructors are bounded by the deploying transaction's chi budget."""

import pytest
from xian_runtime_types.time import Datetime

from contracting.local import ContractingClient

pytestmark = pytest.mark.optional_native

HEAVY_CONSTRUCTOR = """
total = Variable()

@construct
def seed():
    x = 0
    while x < 2000000:
        x = x + 1
    total.set(x)

@export
def get():
    return total.get()
"""


def _deploy(driver, *, budget):
    import xian_vm_core

    return xian_vm_core.execute_contract(
        driver=driver,
        contract_name="submission",
        function_name="submit_contract",
        kwargs={"name": "con_heavy", "code": HEAVY_CONSTRUCTOR},
        context={
            "signer": "alice",
            "caller": "alice",
            "this": "submission",
            "owner": None,
            "now": Datetime(2026, 1, 1),
            "block_num": 1,
            "chain_id": "test-chain",
        },
        meter=True,
        chi_budget_raw=budget,
    )


def test_constructor_runs_within_the_transaction_budget(tmp_path):
    client = ContractingClient(storage_home=tmp_path)
    client.flush()
    try:
        output = _deploy(client.raw_driver, budget=5_000_000)

        assert output.status_code == 1
        assert "Out of chi" in str(output.result)
        assert not any(key.startswith("con_heavy.") for key in output.writes)
    finally:
        client.flush()
