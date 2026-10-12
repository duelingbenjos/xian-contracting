// Independent local conformance verifier. Not exported by any Xian SDK.
import { ed25519 } from "@noble/curves/ed25519.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

const cat = (...parts) => Buffer.concat(parts);
const ascii = (value) => Buffer.from(value, "ascii");
const fail = () => {
  throw new Error("invalid experimental authorization");
};
const same = (a, b) => a.equals(b);
const u16 = (n) => {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n);
  return b;
};
const u32 = (n) => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n);
  return b;
};
const u64 = (n) => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(n);
  return b;
};
const lp16 = (s) => cat(u16(s.length), ascii(s));

function validPoint(bytes) {
  try {
    const point = ed25519.Point.fromBytes(bytes, false);
    return !point.isSmallOrder() && point.isTorsionFree();
  } catch {
    return false;
  }
}

class Reader {
  constructor(bytes) {
    if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > 4265)
      fail();
    this.bytes = bytes;
    this.offset = 0;
  }
  take(n) {
    if (this.offset + n > this.bytes.length) fail();
    const result = this.bytes.subarray(this.offset, this.offset + n);
    this.offset += n;
    return result;
  }
  text(max) {
    const size = this.take(2).readUInt16BE();
    if (size < 1 || size > max) fail();
    const value = this.take(size);
    if (value.some((v) => v > 127)) fail();
    return value.toString("ascii");
  }
  context() {
    const chain = this.text(64),
      account = this.text(72),
      epoch = this.take(8).readBigUInt64BE();
    // Full matching, including rejection of terminal newlines.
    if (!/^[a-z0-9][a-z0-9._-]*$/.test(chain) || chain.includes("\n")) fail();
    if (account.length !== 72 || !/^account:[0-9a-f]{64}$/.test(account))
      fail();
    return { chain, account, epoch };
  }
  record(pq) {
    const result = { ...this.context(), ed: this.take(32) };
    if (!validPoint(result.ed)) fail();
    if (pq) result.pq = this.take(1952);
    return result;
  }
}

function sameContext(a, b) {
  return a.chain === b.chain && a.account === b.account && a.epoch === b.epoch;
}

export function decodeState(bytes) {
  const reader = new Reader(bytes),
    tag = reader.take(1)[0];
  let state;
  if (tag === 0) state = { tag, active: reader.record(false), raw: bytes };
  else if (tag === 1) {
    const active = reader.record(true),
      recovery = reader.record(true);
    if (
      !sameContext(active, recovery) ||
      same(active.ed, recovery.ed) ||
      same(active.pq, recovery.pq)
    )
      fail();
    state = { tag, active, recovery, raw: bytes };
  } else fail();
  if (reader.offset !== bytes.length) fail();
  return state;
}

function edVerify(key, message, signature) {
  // Noble's cofactored check needs subgroup checks for the uncofactored
  // acceptance policy used here. State validation already checks the key.
  return (
    signature.length === 64 &&
    validPoint(signature.subarray(0, 32)) &&
    ed25519.verify(signature, message, key, { zip215: false })
  );
}

function verifyHybrid(record, message, auth) {
  const header = cat(
    ascii("XIAN-HYBRID-AUTH\0"),
    Buffer.from([1, 1]),
    u64(record.epoch),
  );
  return (
    auth.length === 3400 &&
    same(auth.subarray(0, 27), header) &&
    edVerify(record.ed, message, auth.subarray(27, 91)) &&
    ml_dsa65.verify(auth.subarray(91), message, record.pq)
  );
}

export function txMessage(record, payload) {
  if (payload.length < 1 || payload.length > 131072) fail();
  return cat(
    ascii("XIAN-HYBRID-TX\0"),
    Buffer.from([1, 1]),
    lp16(record.chain),
    lp16(record.account),
    u64(record.epoch),
    record.ed,
    record.pq,
    u32(payload.length),
    payload,
  );
}

function transitionMessages(current, candidate, operation) {
  return [1, 2, 3].map((role) =>
    cat(
      ascii("XIAN-HYBRID-LIFECYCLE\0"),
      Buffer.from([1, 1, operation, role]),
      u32(current.raw.length),
      current.raw,
      u32(candidate.raw.length),
      candidate.raw,
    ),
  );
}

export function verifyCase(test, blobs) {
  const blob = (field) => {
    const hex = blobs[test[field]];
    if (typeof hex !== "string" || hex.length % 2 || !/^[0-9a-f]*$/.test(hex))
      fail();
    return Buffer.from(hex, "hex");
  };
  try {
    const state = decodeState(blob("state"));
    if (test.kind === "decode") return { accepted: true, messages: [] };
    if (test.kind === "tx") {
      if (state.tag !== 1) fail();
      const messages = [txMessage(state.active, blob("payload"))];
      return {
        accepted: verifyHybrid(state.active, messages[0], blob("auth")),
        messages,
      };
    }
    if (
      test.kind !== "transition" ||
      ![1, 2, 3].includes(test.operation) ||
      typeof test.enrollment_open !== "boolean"
    )
      fail();
    const candidate = decodeState(blob("candidate")),
      op = test.operation;
    if (
      candidate.tag !== 1 ||
      state.active.chain !== candidate.active.chain ||
      state.active.account !== candidate.active.account
    )
      fail();
    if (state.tag === 0) {
      if (op !== 1 || !test.enrollment_open || candidate.active.epoch !== 0n)
        fail();
    } else if (
      op === 1 ||
      state.active.epoch === 0xffffffffffffffffn ||
      candidate.active.epoch !== state.active.epoch + 1n
    )
      fail();
    const old =
      state.tag === 0 ? [state.active] : [state.active, state.recovery];
    for (const next of [candidate.active, candidate.recovery]) {
      for (const prev of old)
        if (same(next.ed, prev.ed) || (prev.pq && same(next.pq, prev.pq)))
          fail();
    }
    const authority = blob("authority_proof"),
      active = blob("active_proof"),
      recovery = blob("recovery_proof");
    if (
      authority.length !== (op === 1 ? 64 : 3400) ||
      active.length !== 3400 ||
      recovery.length !== 3400
    )
      fail();
    const messages = transitionMessages(state, candidate, op);
    const authorityValid =
      op === 1
        ? edVerify(state.active.ed, messages[0], authority)
        : verifyHybrid(
            op === 2 ? state.active : state.recovery,
            messages[0],
            authority,
          );
    return {
      accepted:
        authorityValid &&
        verifyHybrid(candidate.active, messages[1], active) &&
        verifyHybrid(candidate.recovery, messages[2], recovery),
      messages,
    };
  } catch {
    return { accepted: false, messages: [] };
  }
}
