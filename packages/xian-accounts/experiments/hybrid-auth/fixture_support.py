"""Generated test keys and requests shared by tests and the fixture generator."""

import account_lifecycle as lifecycle
import hybrid_auth as hybrid
from nacl.signing import SigningKey

ACCOUNT = "account:" + "ab" * 32
CHAIN = "local-hybrid"


def new_state(epoch):
    active, active_keys = hybrid.generate_keys(chain_id=CHAIN, account_id=ACCOUNT, key_epoch=epoch)
    recovery, recovery_keys = hybrid.generate_keys(
        chain_id=CHAIN, account_id=ACCOUNT, key_epoch=epoch
    )
    return lifecycle.HybridState(active, recovery), (active_keys, recovery_keys)


def make_scenario():
    legacy_key = SigningKey.generate()
    legacy = lifecycle.LegacyState(CHAIN, ACCOUNT, 9, bytes(legacy_key.verify_key))
    first, first_keys = new_state(0)
    second, second_keys = new_state(1)
    third, third_keys = new_state(2)
    enrollment = lifecycle.prepare_transition(
        legacy,
        lifecycle.Operation.ENROLL,
        first,
        authority_keys=legacy_key,
        active_keys=first_keys[0],
        recovery_keys=first_keys[1],
    )
    rotation = lifecycle.prepare_transition(
        first,
        lifecycle.Operation.ROTATE,
        second,
        authority_keys=first_keys[0],
        active_keys=second_keys[0],
        recovery_keys=second_keys[1],
    )
    recovery = lifecycle.prepare_transition(
        first,
        lifecycle.Operation.RECOVER,
        second,
        authority_keys=first_keys[1],
        active_keys=second_keys[0],
        recovery_keys=second_keys[1],
    )
    return locals()
