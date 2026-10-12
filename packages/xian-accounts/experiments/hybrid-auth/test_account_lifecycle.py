"""Adversarial lifecycle and atomic state-transition tests; generated test keys only."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import account_lifecycle as lifecycle
import hybrid_auth as hybrid
import pytest
from fixture_support import ACCOUNT
from hypothesis import given, settings
from hypothesis import strategies as st
from nacl.signing import SigningKey


def test_enroll_rotate_recover_and_invalidate_old_signatures(scenario):
    s = scenario
    registry = lifecycle.LocalRegistry(s["legacy"], enrollment_open=True)
    registry.apply(s["enrollment"])
    old_auth = hybrid.sign(s["first"].active, s["first_keys"][0], b"test-payload")
    registry.apply(s["rotation"])
    assert not hybrid.verify(registry.state.active, b"test-payload", old_auth)
    recovered = lifecycle.prepare_transition(
        s["second"],
        lifecycle.Operation.RECOVER,
        s["third"],
        authority_keys=s["second_keys"][1],
        active_keys=s["third_keys"][0],
        recovery_keys=s["third_keys"][1],
    )
    assert registry.apply(recovered) == s["third"]
    fresh = hybrid.sign(registry.state.active, s["third_keys"][0], b"test-payload")
    assert hybrid.verify(registry.state.active, b"test-payload", fresh)


def test_recovery_does_not_need_lost_active_secrets(scenario):
    registry = lifecycle.LocalRegistry(scenario["first"])
    assert registry.apply(scenario["recovery"]) == scenario["second"]


@pytest.mark.parametrize("name", ["enrollment", "rotation", "recovery"])
def test_replay_rejected_after_atomic_commit(scenario, name):
    current = scenario["legacy"] if name == "enrollment" else scenario["first"]
    registry = lifecycle.LocalRegistry(current, enrollment_open=True)
    committed = registry.apply(scenario[name])
    with pytest.raises(ValueError):
        registry.apply(scenario[name])
    assert registry.state == committed


def test_default_closed_and_irreversibly_closed_enrollment_gate(scenario):
    registry = lifecycle.LocalRegistry(scenario["legacy"])
    with pytest.raises(ValueError, match="closed"):
        registry.apply(scenario["enrollment"])
    registry = lifecycle.LocalRegistry(scenario["legacy"], enrollment_open=True)
    registry.close_enrollment()
    with pytest.raises(ValueError, match="closed"):
        registry.apply(scenario["enrollment"])
    assert registry.state == scenario["legacy"]


def test_closing_enrollment_does_not_disable_hybrid_operations(scenario):
    registry = lifecycle.LocalRegistry(scenario["legacy"], enrollment_open=True)
    registry.apply(scenario["enrollment"])
    registry.close_enrollment()
    assert registry.apply(scenario["rotation"]) == scenario["second"]


@pytest.mark.parametrize("name", ["enrollment", "rotation", "recovery"])
@pytest.mark.parametrize("proof", ["authority_proof", "active_proof", "recovery_proof"])
def test_any_invalid_proof_preserves_state(scenario, name, proof):
    request = scenario[name]
    corrupt = replace(request, **{proof: bytes(len(getattr(request, proof)))})
    current = scenario["legacy"] if name == "enrollment" else scenario["first"]
    registry = lifecycle.LocalRegistry(current, enrollment_open=True)
    with pytest.raises(ValueError, match="proof"):
        registry.apply(corrupt)
    assert registry.state is current


@pytest.mark.parametrize("proof", ["authority_proof", "active_proof", "recovery_proof"])
@pytest.mark.parametrize("value", [b"", b"x", bytes(3401), None, "x", bytearray(3400)])
def test_missing_or_malformed_proofs_rejected_at_boundary(scenario, proof, value):
    with pytest.raises(ValueError):
        replace(scenario["rotation"], **{proof: value})


def test_legacy_owner_cannot_register_uncontrolled_hybrid_keys(scenario):
    # Valid legacy ownership alone is insufficient to enroll someone else's keys.
    request = scenario["enrollment"]
    registry = lifecycle.LocalRegistry(scenario["legacy"], enrollment_open=True)
    with pytest.raises(ValueError, match="possession"):
        registry.apply(replace(request, active_proof=bytes(3400)))
    assert registry.state == scenario["legacy"]


@pytest.mark.parametrize("field", ["enrollment_nonce", "chain_id", "account_id", "ed_public_key"])
def test_legacy_signature_binds_trusted_mapping_and_nonce(scenario, field):
    values = {
        "enrollment_nonce": 10,
        "chain_id": "different-chain",
        "account_id": "account:" + "cd" * 32,
        "ed_public_key": bytes(SigningKey.generate().verify_key),
    }
    current = replace(scenario["legacy"], **{field: values[field]})
    with pytest.raises(ValueError):
        lifecycle.apply_transition(current, scenario["enrollment"], enrollment_open=True)


@pytest.mark.parametrize("field", ["chain_id", "account_id", "key_epoch"])
def test_candidate_identity_and_epoch_cannot_change(scenario, field):
    values = {"chain_id": "other", "account_id": "account:" + "cd" * 32, "key_epoch": 8}
    candidate = scenario["second"]
    modified = lifecycle.HybridState(
        replace(candidate.active, **{field: values[field]}),
        replace(candidate.recovery, **{field: values[field]}),
    )
    request = replace(scenario["rotation"], candidate=modified)
    with pytest.raises(ValueError, match="identity"):
        lifecycle.apply_transition(scenario["first"], request, enrollment_open=False)


@pytest.mark.parametrize("role", ["active", "recovery"])
@pytest.mark.parametrize("key", ["ed_public_key", "pq_public_key"])
def test_substituting_either_candidate_key_invalidates_current_authority(scenario, role, key):
    candidate = scenario["second"]
    record = replace(getattr(candidate, role), **{key: getattr(scenario["third"].active, key)})
    modified = replace(candidate, **{role: record})
    request = replace(scenario["rotation"], candidate=modified)
    with pytest.raises(ValueError, match="current authority"):
        lifecycle.apply_transition(scenario["first"], request, enrollment_open=False)


@pytest.mark.parametrize("old_role", ["active", "recovery"])
@pytest.mark.parametrize("new_role", ["active", "recovery"])
@pytest.mark.parametrize("key", ["ed_public_key", "pq_public_key"])
def test_no_current_key_can_survive_rotation_or_recovery(scenario, old_role, new_role, key):
    candidate = scenario["second"]
    record = replace(
        getattr(candidate, new_role), **{key: getattr(getattr(scenario["first"], old_role), key)}
    )
    modified = replace(candidate, **{new_role: record})
    for name in ("rotation", "recovery"):
        with pytest.raises(ValueError, match="reuse"):
            lifecycle.apply_transition(
                scenario["first"],
                replace(scenario[name], candidate=modified),
                enrollment_open=False,
            )


@pytest.mark.parametrize("field", ["ed_public_key", "pq_public_key"])
def test_recovery_and_active_roles_cannot_share_keys(scenario, field):
    state = scenario["second"]
    with pytest.raises(ValueError, match="separate"):
        lifecycle.HybridState(
            state.active, replace(state.recovery, **{field: getattr(state.active, field)})
        )


def test_swapped_new_role_proofs_rejected(scenario):
    request = scenario["rotation"]
    with pytest.raises(ValueError, match="possession"):
        lifecycle.apply_transition(
            scenario["first"],
            replace(
                request, active_proof=request.recovery_proof, recovery_proof=request.active_proof
            ),
            enrollment_open=False,
        )


def test_correct_key_signing_wrong_role_is_rejected(scenario):
    s = scenario
    message = lifecycle.transition_transcript(
        s["first"], lifecycle.Operation.ROTATE, s["second"], lifecycle.Role.NEW_RECOVERY
    )
    wrong_role = hybrid._sign_transcript(s["second"].active, s["second_keys"][0], message)
    with pytest.raises(ValueError, match="possession"):
        lifecycle.apply_transition(
            s["first"], replace(s["rotation"], active_proof=wrong_role), enrollment_open=False
        )


def test_operation_cannot_be_relabeled(scenario):
    for before, after in (
        ("rotation", lifecycle.Operation.RECOVER),
        ("recovery", lifecycle.Operation.ROTATE),
    ):
        with pytest.raises(ValueError, match="authority"):
            lifecycle.apply_transition(
                scenario["first"], replace(scenario[before], operation=after), enrollment_open=False
            )


def test_active_authority_cannot_be_used_for_recovery(scenario):
    s = scenario
    message = lifecycle.transition_transcript(
        s["first"], lifecycle.Operation.RECOVER, s["second"], lifecycle.Role.AUTHORITY
    )
    forged = hybrid._sign_transcript(s["first"].active, s["first_keys"][0], message)
    with pytest.raises(ValueError, match="authority"):
        lifecycle.apply_transition(
            s["first"], replace(s["recovery"], authority_proof=forged), enrollment_open=False
        )


def test_transaction_and_lifecycle_domains_are_distinct(scenario):
    s = scenario
    message = lifecycle.transition_transcript(
        s["first"], lifecycle.Operation.ROTATE, s["second"], lifecycle.Role.AUTHORITY
    )
    tx_signature = hybrid.sign(s["first"].active, s["first_keys"][0], message)
    with pytest.raises(ValueError, match="authority"):
        lifecycle.apply_transition(
            s["first"], replace(s["rotation"], authority_proof=tx_signature), enrollment_open=False
        )
    assert not hybrid.verify(s["first"].active, message, s["rotation"].authority_proof)


def test_single_signature_cannot_authorize_recovery(scenario):
    request = scenario["recovery"]
    for proof in (
        request.authority_proof[:91] + bytes(3309),
        request.authority_proof[:27] + bytes(64) + request.authority_proof[91:],
    ):
        with pytest.raises(ValueError, match="authority"):
            lifecycle.apply_transition(
                scenario["first"], replace(request, authority_proof=proof), enrollment_open=False
            )


def test_legacy_cannot_downgrade_or_reenroll_hybrid_state(scenario):
    with pytest.raises(ValueError, match="downgrade"):
        lifecycle.apply_transition(scenario["first"], scenario["enrollment"], enrollment_open=True)
    with pytest.raises(ValueError):
        replace(scenario["rotation"], authority_proof=scenario["enrollment"].authority_proof)
    with pytest.raises(ValueError):
        replace(scenario["rotation"], candidate=scenario["legacy"])


def test_epoch_overflow_fails_closed(scenario):
    current = scenario["first"]
    exhausted = lifecycle.HybridState(
        replace(current.active, key_epoch=2**64 - 1), replace(current.recovery, key_epoch=2**64 - 1)
    )
    with pytest.raises(ValueError, match="exhausted"):
        lifecycle.apply_transition(exhausted, scenario["rotation"], enrollment_open=False)


@pytest.mark.parametrize("operation", [0, 1, 4, True, "rotate", None])
def test_no_inferred_or_unknown_operation(scenario, operation):
    with pytest.raises(ValueError):
        replace(scenario["rotation"], operation=operation)


def test_stale_recovery_authority_cannot_sign_next_recovery(scenario):
    s = scenario
    message = lifecycle.transition_transcript(
        s["second"], lifecycle.Operation.RECOVER, s["third"], lifecycle.Role.AUTHORITY
    )
    stale = hybrid._sign_transcript(s["first"].recovery, s["first_keys"][1], message)
    request = lifecycle.prepare_transition(
        s["second"],
        lifecycle.Operation.RECOVER,
        s["third"],
        authority_keys=s["second_keys"][1],
        active_keys=s["third_keys"][0],
        recovery_keys=s["third_keys"][1],
    )
    # Even rewriting the envelope epoch cannot turn the old recovery key into current authority.
    rewritten = stale[:19] + (1).to_bytes(8, "big") + stale[27:]
    with pytest.raises(ValueError, match="authority"):
        lifecycle.apply_transition(
            s["second"], replace(request, authority_proof=rewritten), enrollment_open=False
        )


def test_concurrent_rotation_and_recovery_cannot_both_commit(scenario):
    registry = lifecycle.LocalRegistry(scenario["first"])

    def submit(request):
        try:
            registry.apply(request)
            return True
        except ValueError:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(submit, [scenario["rotation"], scenario["recovery"]]))
    assert sorted(outcomes) == [False, True]
    assert registry.state == scenario["second"]


def test_current_authority_binds_the_entire_previous_state(scenario):
    # The active key still matches, but its signature must also bind the old
    # recovery policy. A signature over only the new keys would miss this.
    current = scenario["first"]
    changed = replace(
        current,
        recovery=replace(current.recovery, pq_public_key=scenario["third"].recovery.pq_public_key),
    )
    with pytest.raises(ValueError, match="authority"):
        lifecycle.apply_transition(changed, scenario["rotation"], enrollment_open=False)


def test_new_possession_proofs_bind_previous_state_and_operation(scenario):
    # The authority proof is valid for rotation. A candidate possession proof
    # from recovery (same new key and epoch) must not be reusable here.
    request = replace(scenario["rotation"], active_proof=scenario["recovery"].active_proof)
    with pytest.raises(ValueError, match="possession"):
        lifecycle.apply_transition(scenario["first"], request, enrollment_open=False)


def test_gate_and_epoch_fail_before_cryptography(scenario, monkeypatch):
    def forbidden(*args):
        pytest.fail("cryptography reached before policy/epoch checks")

    monkeypatch.setattr(hybrid, "_verify_transcript", forbidden)
    monkeypatch.setattr(lifecycle, "VerifyKey", forbidden)
    with pytest.raises(ValueError, match="closed"):
        lifecycle.apply_transition(
            scenario["legacy"], scenario["enrollment"], enrollment_open=False
        )
    with pytest.raises(ValueError, match="epoch"):
        lifecycle.apply_transition(scenario["second"], scenario["rotation"], enrollment_open=False)


def test_lifecycle_encoding_golden():
    # Independent fixed hex framing, public test inputs only. These structural
    # PQ keys are not used for signing or proof validation.
    legacy_ed = bytes(SigningKey(bytes(32)).verify_key)
    active_ed = bytes(SigningKey(b"\x01" * 32).verify_key)
    recovery_ed = bytes(SigningKey(b"\x02" * 32).verify_key)
    current = lifecycle.LegacyState("local", ACCOUNT, 9, legacy_ed)
    candidate = lifecycle.HybridState(
        hybrid.AccountRecord("local", ACCOUNT, 0, active_ed, b"\x01" * 1952),
        hybrid.AccountRecord("local", ACCOUNT, 0, recovery_ed, b"\x02" * 1952),
    )
    identity = bytes.fromhex("00056c6f63616c0048") + ACCOUNT.encode("ascii")
    before = b"\x00" + identity + bytes.fromhex("0000000000000009") + legacy_ed
    after = (
        b"\x01"
        + identity
        + bytes(8)
        + active_ed
        + b"\x01" * 1952
        + identity
        + bytes(8)
        + recovery_ed
        + b"\x02" * 1952
    )
    assert len(before) == 122 and len(after) == 4147
    prefix = bytes.fromhex("5849414e2d4859425249442d4c4946454359434c450001010103")
    expected = prefix + bytes.fromhex("0000007a") + before + bytes.fromhex("00001033") + after
    assert (
        lifecycle.transition_transcript(
            current, lifecycle.Operation.ENROLL, candidate, lifecycle.Role.NEW_RECOVERY
        )
        == expected
    )


@settings(max_examples=100, deadline=None)
@given(st.sampled_from(["authority_proof", "active_proof", "recovery_proof"]), st.integers(0, 3399))
def test_random_proof_corruption_is_atomic(scenario, name, offset):
    request = scenario["rotation"]
    proof = bytearray(getattr(request, name))
    proof[offset] ^= 1
    registry = lifecycle.LocalRegistry(scenario["first"])
    with pytest.raises(ValueError):
        registry.apply(replace(request, **{name: bytes(proof)}))
    assert registry.state == scenario["first"]
