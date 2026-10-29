"""Owner-restricted contracts reject direct calls from anyone but the owner."""

import pytest

from contracting.storage.driver import Driver

pytestmark = pytest.mark.optional_native

SOURCE = """
counter = Variable()

@export
def bump():
    counter.set((counter.get() or 0) + 1)
    return counter.get()
"""


def _call(driver, caller):
    import xian_vm_core

    return xian_vm_core.execute_contract(
        driver=driver,
        contract_name="con_child",
        function_name="bump",
        kwargs={},
        context={"signer": caller, "caller": caller, "this": "con_child", "owner": None},
        meter=True,
        chi_budget_raw=10_000_000,
    )


def test_direct_call_from_non_owner_is_rejected(tmp_path):
    with Driver(storage_home=tmp_path) as driver:
        driver.set_contract_from_source("con_child", SOURCE, owner="con_parent")
        driver.commit()

        rejected = _call(driver, "alice")
        assert rejected.status_code == 1
        assert "not the owner" in str(rejected.result)
        assert rejected.writes == {}
        assert rejected.chi_used > 0

        allowed = _call(driver, "con_parent")
        assert allowed.status_code == 0
        assert allowed.result == 1


def test_contract_without_owner_accepts_any_caller(tmp_path):
    with Driver(storage_home=tmp_path) as driver:
        driver.set_contract_from_source("con_child", SOURCE, owner=None)
        driver.commit()

        assert _call(driver, "alice").status_code == 0
