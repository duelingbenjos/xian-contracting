import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { decodeState, txMessage, verifyCase } from "./verifier.mjs";

const vectors = JSON.parse(
  readFileSync(new URL("../parity_vectors.json", import.meta.url)),
);
assert.equal(vectors.schema, "xian-hybrid-parity-v1");
for (const vector of vectors.cases) {
  test(vector.name, () => {
    const result = verifyCase(vector, vectors.blobs);
    assert.equal(result.accepted, vector.expected);
    if (vector.transcripts_sha256)
      assert.deepEqual(
        result.messages.map((message) =>
          createHash("sha256").update(message).digest("hex"),
        ),
        vector.transcripts_sha256,
      );
  });
}
test("payload bounds are enforced before signing-byte construction", () => {
  const state = decodeState(Buffer.from(vectors.blobs.first, "hex"));
  assert.throws(() => txMessage(state.active, Buffer.alloc(0)));
  assert.throws(() => txMessage(state.active, Buffer.alloc(131073)));
  assert.ok(txMessage(state.active, Buffer.alloc(131072)).length > 131072);
});
