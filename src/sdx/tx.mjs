// Transaction, script, BEEF (BRC-62/95), BUMP (BRC-74), header and spend primitives for
// the SDX v0.1 anchoring checker (ANC §2, §6, §7). Independent laboratory implementation:
// node builtins only, no wallet, SDK or Toolbox import.
//
// Byte order: every txid, merkle node and block hash handled here is in INTERNAL order
// (the raw SHA-256d output, as serialized in inputs, BUMPs, BEEF and headers). Display
// order is its reverse; displayHex() converts for human-facing output only.

import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto'

export const sha256 = bytes => createHash('sha256').update(bytes).digest()
export const sha256d = bytes => sha256(sha256(bytes))
export const hash160 = bytes => createHash('ripemd160').update(sha256(bytes)).digest()
export const hex = bytes => Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('hex')
export const displayHex = bytes => Buffer.from(bytes).reverse().toString('hex')

export const OP = Object.freeze({
  OP_0: 0x00, OP_PUSHDATA1: 0x4c, OP_PUSHDATA2: 0x4d, OP_PUSHDATA4: 0x4e, OP_1NEGATE: 0x4f,
  OP_1: 0x51, OP_16: 0x60, OP_RETURN: 0x6a, OP_DROP: 0x75, OP_2DROP: 0x6d, OP_DUP: 0x76,
  OP_EQUALVERIFY: 0x88, OP_HASH160: 0xa9, OP_CHECKSIG: 0xac
})

export const MAX_MONEY = 21_000_000 * 100_000_000
const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
const SECP256K1_HALF_N = SECP256K1_N >> 1n
const SPKI_COMPRESSED = Buffer.from('3036301006072a8648ce3d020106052b8104000a032200', 'hex')
const SPKI_UNCOMPRESSED = Buffer.from('3056301006072a8648ce3d020106052b8104000a034200', 'hex')
const BEEF_V1 = '0100beef'
const BEEF_V2 = '0200beef'
const ATOMIC_BEEF = '01010101'

export class ChainDataError extends Error {
  constructor(code, detail) {
    super(detail ? `${code}: ${detail}` : code)
    this.name = 'ChainDataError'
    this.code = code
  }
}

const fail = (code, detail) => { throw new ChainDataError(code, detail) }

export class ByteReader {
  constructor(bytes) {
    this.bytes = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength)
    this.pos = 0
  }
  remaining() { return this.bytes.length - this.pos }
  take(n) {
    if (!Number.isSafeInteger(n) || n < 0 || n > this.remaining()) fail('truncated', 'field extends past the end of the data')
    const out = this.bytes.subarray(this.pos, this.pos + n)
    this.pos += n
    return out
  }
  u8() { return this.take(1)[0] }
  u32() { return this.take(4).readUInt32LE(0) }
  u64() { return this.take(8).readBigUInt64LE(0) }
  // Bitcoin CompactSize; non-canonical forms are refused, as node deserialization does.
  varint() {
    const first = this.u8()
    if (first < 0xfd) return first
    if (first === 0xfd) { const v = this.take(2).readUInt16LE(0); if (v < 0xfd) fail('varint-non-canonical'); return v }
    if (first === 0xfe) { const v = this.u32(); if (v < 0x10000) fail('varint-non-canonical'); return v }
    const v = this.u64()
    if (v < 0x100000000n) fail('varint-non-canonical')
    if (v > BigInt(Number.MAX_SAFE_INTEGER)) fail('varint-range')
    return Number(v)
  }
}

export function writeVarint(n) {
  if (n < 0xfd) return Buffer.from([n])
  if (n <= 0xffff) { const b = Buffer.alloc(3); b[0] = 0xfd; b.writeUInt16LE(n, 1); return b }
  if (n <= 0xffffffff) { const b = Buffer.alloc(5); b[0] = 0xfe; b.writeUInt32LE(n, 1); return b }
  const b = Buffer.alloc(9); b[0] = 0xff; b.writeBigUInt64LE(BigInt(n), 1); return b
}

const u32le = n => { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0, 0); return b }
const u64le = n => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n), 0); return b }

// ---------------------------------------------------------------- transactions

export function readTransaction(reader) {
  const start = reader.pos
  const version = reader.u32()
  const inputCount = reader.varint()
  if (inputCount === 0) fail('tx-no-inputs')
  if (inputCount * 41 > reader.remaining()) fail('truncated', 'declared input count exceeds the data')
  const inputs = []
  for (let i = 0; i < inputCount; i++) {
    const prevTxid = Buffer.from(reader.take(32))
    const vout = reader.u32()
    const script = Buffer.from(reader.take(reader.varint()))
    const sequence = reader.u32()
    inputs.push({ prevTxid, vout, script, sequence })
  }
  const outputCount = reader.varint()
  if (outputCount === 0) fail('tx-no-outputs')
  if (outputCount * 9 > reader.remaining()) fail('truncated', 'declared output count exceeds the data')
  const outputs = []
  for (let i = 0; i < outputCount; i++) {
    const outputStart = reader.pos
    const value = reader.u64()
    if (value > BigInt(MAX_MONEY)) fail('tx-value-range')
    const script = Buffer.from(reader.take(reader.varint()))
    outputs.push({ satoshis: Number(value), script, raw: Buffer.from(reader.bytes.subarray(outputStart, reader.pos)) })
  }
  const lockTime = reader.u32()
  const raw = Buffer.from(reader.bytes.subarray(start, reader.pos))
  return { version, inputs, outputs, lockTime, raw, txid: sha256d(raw) }
}

export function parseTransaction(bytes) {
  const reader = new ByteReader(bytes)
  const tx = readTransaction(reader)
  if (reader.remaining() !== 0) fail('trailing-bytes', 'bytes follow the transaction')
  return tx
}

// ---------------------------------------------------------------- scripts

const isPushOpcode = op => op <= OP.OP_PUSHDATA4

// Chunks a script. A push whose declared length runs past the end of the script makes the
// script malformed.
export function parseScript(script) {
  const bytes = Buffer.from(script)
  const chunks = []
  let pos = 0
  while (pos < bytes.length) {
    const op = bytes[pos]
    const start = pos
    pos += 1
    let data = null
    if (isPushOpcode(op)) {
      let length = op
      let ok = true
      if (op === OP.OP_PUSHDATA1) { ok = pos + 1 <= bytes.length; length = ok ? bytes[pos] : 0; pos += 1 }
      else if (op === OP.OP_PUSHDATA2) { ok = pos + 2 <= bytes.length; length = ok ? bytes.readUInt16LE(pos) : 0; pos += 2 }
      else if (op === OP.OP_PUSHDATA4) { ok = pos + 4 <= bytes.length; length = ok ? bytes.readUInt32LE(pos) : 0; pos += 4 }
      if (!ok || pos + length > bytes.length) return { chunks, malformed: true }
      data = bytes.subarray(pos, pos + length)
      pos += length
    }
    chunks.push({ op, data, start, end: pos })
  }
  return { chunks, malformed: false }
}

export function isMinimalPush(chunk) {
  const { op, data } = chunk
  if (data === null) return false
  if (data.length === 0) return op === OP.OP_0
  if (data.length === 1 && data[0] >= 1 && data[0] <= 16) return false // OP_1..OP_16
  if (data.length === 1 && data[0] === 0x81) return false // OP_1NEGATE
  if (data.length <= 75) return op === data.length
  if (data.length <= 0xff) return op === OP.OP_PUSHDATA1
  if (data.length <= 0xffff) return op === OP.OP_PUSHDATA2
  return op === OP.OP_PUSHDATA4
}

const isStrictPublicKey = key => (key.length === 33 && (key[0] === 0x02 || key[0] === 0x03)) || (key.length === 65 && key[0] === 0x04)

export function isP2PKH(script) {
  return script.length === 25 && script[0] === OP.OP_DUP && script[1] === OP.OP_HASH160 && script[2] === 0x14 &&
    script[23] === OP.OP_EQUALVERIFY && script[24] === OP.OP_CHECKSIG
}

// `<data> DROP <pubkey> CHECKSIG`: the chaining container of ANC §2.1. Returns the parts, or
// null when the script has another form.
export function matchDataDropCheckSig(script) {
  const { chunks, malformed } = parseScript(script)
  if (malformed || chunks.length !== 4) return null
  const [data, drop, key, checksig] = chunks
  if (data.data === null || drop.op !== OP.OP_DROP || key.data === null || checksig.op !== OP.OP_CHECKSIG) return null
  if (!isStrictPublicKey(key.data)) return null
  return { data: data.data, dataChunk: data, publicKey: key.data }
}

// ANC §2.1/§2.2 container shape for a record output: exactly one data field, pushed with the
// minimal opcode, then DROP, then `<key> CHECKSIG`. Returns the record bytes and the commitment
// key, or the reason the shape does not hold.
export function checkContainer(script) {
  const parsed = parseScript(script)
  if (parsed.malformed) return { ok: false, reason: 'container-script-malformed' }
  const { chunks } = parsed
  // Data fields, then the DROP/2DROP opcodes that discard them, then `<key> CHECKSIG`.
  let fields = 0
  while (fields < chunks.length && chunks[fields].data !== null) fields++
  let i = fields
  let dropped = 0
  while (i < chunks.length && (chunks[i].op === OP.OP_DROP || chunks[i].op === OP.OP_2DROP)) {
    dropped += chunks[i].op === OP.OP_DROP ? 1 : 2
    i++
  }
  const keyed = chunks.length === i + 2 && chunks[i].data !== null && isStrictPublicKey(chunks[i].data) && chunks[i + 1].op === OP.OP_CHECKSIG
  if (!keyed || fields === 0 || dropped !== fields) return { ok: false, reason: 'container-template' }
  if (fields !== 1 || chunks[1].op !== OP.OP_DROP) return { ok: false, reason: 'container-field-count' } // ANC §2.2
  if (!isMinimalPush(chunks[0])) return { ok: false, reason: 'container-push-not-minimal' } // ANC §2.1
  return { ok: true, record: chunks[0].data, commitmentKey: chunks[2].data }
}

// ---------------------------------------------------------------- signatures and spends

// BIP 66 strict DER, applied to a signature that carries its trailing sighash byte.
export function isStrictDerSignature(sig) {
  if (sig.length < 9 || sig.length > 73) return false
  if (sig[0] !== 0x30 || sig[1] !== sig.length - 3) return false
  const lenR = sig[3]
  if (5 + lenR >= sig.length) return false
  const lenS = sig[5 + lenR]
  if (lenR + lenS + 7 !== sig.length) return false
  if (sig[2] !== 0x02 || lenR === 0 || (sig[4] & 0x80)) return false
  if (lenR > 1 && sig[4] === 0x00 && !(sig[5] & 0x80)) return false
  if (sig[lenR + 4] !== 0x02 || lenS === 0 || (sig[lenR + 6] & 0x80)) return false
  if (lenS > 1 && sig[lenR + 6] === 0x00 && !(sig[lenR + 7] & 0x80)) return false
  return true
}

const toBigInt = bytes => BigInt(`0x${hex(bytes) || '0'}`)
const to32 = n => Buffer.from(n.toString(16).padStart(64, '0'), 'hex')

export function sighashPreimage(tx, inputIndex, scriptCode, satoshis, sighashType) {
  const base = sighashType & 0x1f
  const anyoneCanPay = (sighashType & 0x80) !== 0
  const zero = Buffer.alloc(32)
  const hashPrevouts = anyoneCanPay ? zero : sha256d(Buffer.concat(tx.inputs.flatMap(input => [input.prevTxid, u32le(input.vout)])))
  const hashSequence = anyoneCanPay || base === 2 || base === 3 ? zero : sha256d(Buffer.concat(tx.inputs.map(input => u32le(input.sequence))))
  let hashOutputs = zero
  if (base !== 2 && base !== 3) hashOutputs = sha256d(Buffer.concat(tx.outputs.map(output => output.raw)))
  else if (base === 3 && inputIndex < tx.outputs.length) hashOutputs = sha256d(tx.outputs[inputIndex].raw)
  const input = tx.inputs[inputIndex]
  return Buffer.concat([
    u32le(tx.version), hashPrevouts, hashSequence, input.prevTxid, u32le(input.vout),
    writeVarint(scriptCode.length), scriptCode, u64le(satoshis), u32le(input.sequence),
    hashOutputs, u32le(tx.lockTime), u32le(sighashType)
  ])
}

function publicKeyObject(key) {
  try { return createPublicKey({ key: Buffer.concat([key.length === 33 ? SPKI_COMPRESSED : SPKI_UNCOMPRESSED, key]), format: 'der', type: 'spki' }) } catch {
    return null
  }
}

const SUPPORTED_SIGHASH = new Set([0x41, 0x42, 0x43, 0xc1, 0xc2, 0xc3])

// Checks one ECDSA script signature (DER + sighash byte) over the BIP 143 SIGHASH_FORKID
// preimage. Returns PASS, FAIL or INCONCLUSIVE with a reason. `strict` also requires low S, as
// the BSV malleability rules do for transactions of version 1 or lower. KEYS §1.8.3 has
// verifiers accept either S, so the SDX v0.1 chain walk passes `strict: false`.
export function checkScriptSignature({ tx, inputIndex, scriptCode, satoshis, signature, publicKey, strict }) {
  if (!isStrictPublicKey(publicKey)) return { result: 'FAIL', reason: 'spends-pubkey-encoding' }
  if (signature.length === 0) return { result: 'FAIL', reason: 'spends-signature-invalid' }
  if (!isStrictDerSignature(signature)) return { result: 'FAIL', reason: 'spends-signature-encoding' }
  const sighashType = signature[signature.length - 1]
  const base = sighashType & 0x1f
  if (base < 1 || base > 3) return { result: 'FAIL', reason: 'spends-signature-encoding' }
  if (!SUPPORTED_SIGHASH.has(sighashType)) return { result: 'INCONCLUSIVE', reason: 'spends-sighash-unsupported' }
  const lenR = signature[3]
  const r = toBigInt(signature.subarray(4, 4 + lenR))
  const s = toBigInt(signature.subarray(6 + lenR, signature.length - 1))
  if (r === 0n || s === 0n || r >= SECP256K1_N || s >= SECP256K1_N) return { result: 'FAIL', reason: 'spends-signature-invalid' }
  if (strict && s > SECP256K1_HALF_N) return { result: 'FAIL', reason: 'spends-signature-encoding' }
  const key = publicKeyObject(publicKey)
  if (key === null) return { result: 'FAIL', reason: 'spends-pubkey-encoding' }
  const preimage = sighashPreimage(tx, inputIndex, scriptCode, satoshis, sighashType)
  // ECDSA over SHA-256d(preimage): node hashes the supplied SHA-256(preimage) once more.
  const valid = verifySignature('sha256', sha256(preimage), { key, dsaEncoding: 'ieee-p1363' }, Buffer.concat([to32(r), to32(s)]))
  return valid ? { result: 'PASS', reason: null } : { result: 'FAIL', reason: 'spends-signature-invalid' }
}

// Evaluates whether input `inputIndex` of `tx` validly spends `prevOutput`, for two templates:
// P2PKH and `<data> DROP <pubkey> CHECKSIG`. Any other locking or unlocking form is INCONCLUSIVE. Transactions of version <= 1 are checked with
// the malleability rules (push-only, minimal pushes, clean stack, low S); later versions use
// the relaxed rules, under which extra items below the template's pushes are ignored.
export function evaluateSpend({ tx, inputIndex, prevTxid, prevOut, prevOutput }) {
  const input = tx.inputs[inputIndex]
  if (!input) return { result: 'FAIL', reason: 'spends-input-missing' }
  if (!input.prevTxid.equals(Buffer.from(prevTxid)) || input.vout !== prevOut) return { result: 'FAIL', reason: 'spends-outpoint-mismatch' }
  if (!prevOutput) return { result: 'FAIL', reason: 'spends-prev-output-missing' }
  const strict = tx.version <= 1
  const lock = Buffer.from(prevOutput.script)
  let template
  let needed
  if (isP2PKH(lock)) { template = 'p2pkh'; needed = 2 }
  else if (matchDataDropCheckSig(lock)) { template = 'data-drop-checksig'; needed = 1 }
  else return { result: 'INCONCLUSIVE', reason: 'spends-template-unsupported', template: null }
  const unlock = parseScript(input.script)
  if (unlock.malformed) return { result: 'FAIL', reason: 'spends-unlocking-malformed', template }
  const stack = []
  for (const chunk of unlock.chunks) {
    if (chunk.data !== null) stack.push({ item: chunk.data, minimal: isMinimalPush(chunk) })
    else if (chunk.op === OP.OP_1NEGATE) stack.push({ item: Buffer.from([0x81]), minimal: true })
    else if (chunk.op >= OP.OP_1 && chunk.op <= OP.OP_16) stack.push({ item: Buffer.from([chunk.op - 0x50]), minimal: true })
    else return strict ? { result: 'FAIL', reason: 'spends-unlocking-not-push-only', template } : { result: 'INCONCLUSIVE', reason: 'spends-unlocking-unsupported', template }
  }
  if (strict && !stack.every(entry => entry.minimal)) return { result: 'FAIL', reason: 'spends-unlocking-not-minimal', template }
  if (stack.length < needed || (strict && stack.length !== needed)) return { result: 'FAIL', reason: 'spends-unlocking-stack', template }
  const items = stack.slice(-needed).map(entry => entry.item)
  let signature
  let publicKey
  if (template === 'p2pkh') {
    [signature, publicKey] = items
    if (!hash160(publicKey).equals(lock.subarray(3, 23))) return { result: 'FAIL', reason: 'spends-pubkey-hash-mismatch', template }
  } else {
    [signature] = items
    publicKey = matchDataDropCheckSig(lock).publicKey
  }
  const checked = checkScriptSignature({ tx, inputIndex, scriptCode: lock, satoshis: prevOutput.satoshis, signature, publicKey, strict })
  return { ...checked, template }
}

// ---------------------------------------------------------------- BUMP (BRC-74)

export function readBump(reader) {
  const blockHeight = reader.varint()
  const treeHeight = reader.u8()
  if (treeHeight === 0 || treeHeight > 64) fail('bump-tree-height')
  const levels = []
  for (let level = 0; level < treeHeight; level++) {
    const count = reader.varint()
    if (count * 2 > reader.remaining()) fail('truncated', 'declared leaf count exceeds the data')
    const leaves = new Map()
    for (let i = 0; i < count; i++) {
      const offset = reader.varint()
      const flags = reader.u8()
      if (flags > 2) fail('bump-flags')
      if (leaves.has(offset)) fail('bump-duplicate-offset')
      if (treeHeight - level < 53 && offset >= 2 ** (treeHeight - level)) fail('bump-offset-range')
      leaves.set(offset, flags === 1 ? { offset, duplicate: true, txid: false, hash: null } : { offset, duplicate: false, txid: flags === 2, hash: Buffer.from(reader.take(32)) })
    }
    levels.push(leaves)
  }
  if (levels[0].size === 0) fail('bump-empty-level-0')
  return { blockHeight, treeHeight, levels }
}

export function parseBump(bytes) {
  const reader = new ByteReader(bytes)
  const bump = readBump(reader)
  if (reader.remaining() !== 0) fail('trailing-bytes', 'bytes follow the BUMP')
  return bump
}

export function bumpIndexOf(bump, txid) {
  for (const leaf of bump.levels[0].values()) if (!leaf.duplicate && leaf.hash.equals(Buffer.from(txid))) return leaf.offset
  return -1
}

const DUPLICATE = Symbol('duplicate')

function bumpNode(bump, height, offset) {
  const leaf = bump.levels[height]?.get(offset)
  if (leaf) return leaf.duplicate ? DUPLICATE : leaf.hash
  if (height === 0) return null
  const left = bumpNode(bump, height - 1, offset * 2)
  if (left === null || left === DUPLICATE) return null
  const right = bumpNode(bump, height - 1, offset * 2 + 1)
  if (right === null) return null
  return sha256d(Buffer.concat([left, right === DUPLICATE ? left : right]))
}

// Merkle root (internal order) a BUMP gives for `txid`, using the Bitcoin SHA-256d tree.
export function bumpRoot(bump, txid) {
  const index = bumpIndexOf(bump, txid)
  if (index < 0) fail('bump-txid-absent')
  if (bump.treeHeight === 1 && bump.levels[0].size === 1 && index === 0) return Buffer.from(txid) // block of one transaction
  let working = Buffer.from(txid)
  for (let height = 0; height < bump.treeHeight; height++) {
    const position = Math.floor(index / 2 ** height)
    const isRight = position % 2 === 1
    const sibling = bumpNode(bump, height, isRight ? position - 1 : position + 1)
    if (sibling === null) fail('bump-missing-node', `height ${height}`)
    if (sibling === DUPLICATE && isRight) fail('bump-invalid-duplicate', `height ${height}`)
    const other = sibling === DUPLICATE ? working : sibling
    working = sha256d(isRight ? Buffer.concat([other, working]) : Buffer.concat([working, other]))
  }
  return working
}

// ---------------------------------------------------------------- BEEF (BRC-62) and Atomic BEEF (BRC-95)

// Parses BEEF V1 or Atomic BEEF wrapping V1. Every transaction must appear once, after any
// in-BEEF parent; each BUMP reference must name a BUMP holding that txid at level 0. An
// Atomic BEEF must hold its subject and only the subject's in-BEEF ancestors.
export function parseBeef(bytes) {
  const reader = new ByteReader(bytes)
  let magic = hex(reader.take(4))
  let subject = null
  if (magic === ATOMIC_BEEF) {
    subject = Buffer.from(reader.take(32))
    magic = hex(reader.take(4))
  }
  if (magic === BEEF_V2) fail('beef-v2-unsupported')
  if (magic !== BEEF_V1) fail('beef-version')
  const bumpCount = reader.varint()
  if (bumpCount > reader.remaining()) fail('truncated', 'declared BUMP count exceeds the data')
  const bumps = []
  for (let i = 0; i < bumpCount; i++) bumps.push(readBump(reader))
  const txCount = reader.varint()
  if (txCount === 0) fail('beef-empty')
  if (txCount * 60 > reader.remaining()) fail('truncated', 'declared transaction count exceeds the data')
  const txs = new Map()
  const order = []
  for (let i = 0; i < txCount; i++) {
    const tx = readTransaction(reader)
    const hasBump = reader.u8()
    if (hasBump > 1) fail('beef-bump-flag')
    const bumpIndex = hasBump === 1 ? reader.varint() : null
    const key = hex(tx.txid)
    if (txs.has(key)) fail('beef-duplicate-tx')
    if (bumpIndex !== null) {
      if (bumpIndex >= bumps.length) fail('beef-bump-index')
      if (bumpIndexOf(bumps[bumpIndex], tx.txid) < 0) fail('beef-bump-mismatch')
    }
    txs.set(key, { tx, bumpIndex, position: i })
    order.push(key)
  }
  if (reader.remaining() !== 0) fail('trailing-bytes', 'bytes follow the BEEF')
  for (const key of order) {
    const entry = txs.get(key)
    for (const input of entry.tx.inputs) {
      const parent = txs.get(hex(input.prevTxid))
      if (parent && parent.position > entry.position) fail('beef-order')
    }
  }
  if (subject) {
    const subjectKey = hex(subject)
    if (!txs.has(subjectKey)) fail('beef-atomic-subject-absent')
    const related = new Set([subjectKey])
    const stack = [subjectKey]
    while (stack.length) {
      for (const input of txs.get(stack.pop()).tx.inputs) {
        const parentKey = hex(input.prevTxid)
        if (txs.has(parentKey) && !related.has(parentKey)) { related.add(parentKey); stack.push(parentKey) }
      }
    }
    if (related.size !== txs.size) fail('beef-atomic-unrelated')
  }
  return { atomic: subject !== null, subject, bumps, txs, order }
}

// ---------------------------------------------------------------- block headers

export function parseHeader(bytes) {
  const b = Buffer.from(bytes)
  if (b.length !== 80) fail('header-length')
  return {
    version: b.readUInt32LE(0), prevHash: b.subarray(4, 36), merkleRoot: b.subarray(36, 68),
    time: b.readUInt32LE(68), bits: b.readUInt32LE(72), nonce: b.readUInt32LE(76), hash: sha256d(b)
  }
}

export function bitsToTarget(bits) {
  const exponent = bits >>> 24
  const mantissa = bits & 0x007fffff
  if (bits & 0x00800000) fail('header-bits-negative')
  if (mantissa === 0) fail('header-bits-zero')
  const target = exponent <= 3 ? BigInt(mantissa >>> (8 * (3 - exponent))) : BigInt(mantissa) << BigInt(8 * (exponent - 3))
  if (target >= 1n << 256n) fail('header-bits-overflow')
  return target
}

// A header client over a pinned, contiguous header list: each header's proof of work meets
// its own bits, and each links to its predecessor. It answers whether a merkle root (internal
// order) belongs to the header at a height. It holds no network connection.
export function createHeaderTracker(entries) {
  const byHeight = new Map()
  let previous = null
  for (const entry of entries) {
    const header = parseHeader(Buffer.from(entry.header, 'hex'))
    if (!Number.isSafeInteger(entry.height) || entry.height < 0) fail('header-height')
    if (previous) {
      if (entry.height !== previous.height + 1) fail('header-gap')
      if (!header.prevHash.equals(previous.header.hash)) fail('header-link')
    }
    if (toBigInt(Buffer.from(header.hash).reverse()) > bitsToTarget(header.bits)) fail('header-pow')
    byHeight.set(entry.height, header)
    previous = { height: entry.height, header }
  }
  if (!previous) fail('header-empty')
  return {
    tipHeight: previous.height,
    headerAt: height => byHeight.get(height) ?? null,
    isValidRootForHeight: (root, height) => byHeight.get(height)?.merkleRoot.equals(Buffer.from(root)) === true
  }
}
