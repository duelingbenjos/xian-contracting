import hashlib
import json
from pathlib import Path

import account_lifecycle as lifecycle
import hybrid_auth as hybrid
import pytest
from state_codec import decode_state

VECTORS = json.loads(Path(__file__).with_name("parity_vectors.json").read_text())


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda case: case["name"])
def test_shared_verdicts_and_transcript_hashes(case):
    def blob(field):
        return bytes.fromhex(VECTORS["blobs"][case[field]])

    try:
        state = decode_state(blob("state"))
        if case["kind"] == "decode":
            valid, messages = True, []
        elif case["kind"] == "tx":
            if type(state) is not lifecycle.HybridState:
                raise ValueError("hybrid state required")
            messages = [hybrid.signing_transcript(state.active, blob("payload"))]
            valid = hybrid.verify(state.active, blob("payload"), blob("auth"))
        else:
            candidate = decode_state(blob("candidate"))
            operation = lifecycle.Operation(case["operation"])
            request = lifecycle.Transition(
                operation,
                candidate,
                blob("authority_proof"),
                blob("active_proof"),
                blob("recovery_proof"),
            )
            messages = [
                lifecycle.transition_transcript(state, operation, candidate, role)
                for role in lifecycle.Role
            ]
            lifecycle.apply_transition(state, request, enrollment_open=case["enrollment_open"])
            valid = True
    except ValueError:
        valid = False
    assert valid is case["expected"]
    if "transcripts_sha256" in case:
        assert [hashlib.sha256(message).hexdigest() for message in messages] == case[
            "transcripts_sha256"
        ]
