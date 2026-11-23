// SDX v0.1 deterministic encoding profile (ENV §3, published suite `cbor-det-v1`).
// Independent laboratory implementation: node builtins only, no CBOR library.
//
// encode()        the profile's encoder; output is byte-exact with the published suite.
// encodeSuperseded()  the superseded integer shape of ENV §8.3: the same encoder, except that an
//                 integer needing the 8-byte head is written as binary64. Readers rebuild
//                 signed bytes this way once when the current shape verifies nothing.
// decode()        the profile's semantic decoder (ENV §3): rejects tags and indefinite
//                 lengths, accepts non-shortest heads and the historical binary64 integers.
// decodeStrict()  a laboratory choice beyond ENV §3: decode, then require that re-encoding
//                 reproduces the input bytes exactly. The VA-ANC reference map is read this way.
//
// LIMITS are laboratory bounds on nesting depth and input size (ENV §17.6 requires bounds and
// fixes no values). A refusal caused by a laboratory bound is reported as ERROR, never FAIL.

export const PROFILE = 'cbor-det-v1'
export const LIMITS = Object.freeze({ depth: 64, bytes: 16 * 1024 * 1024 })

const MAX_SAFE = Number.MAX_SAFE_INTEGER
const TWO_32 = 2 ** 32
const NAN_BYTES = Buffer.from('fb7ff8000000000000', 'hex')
const UTF8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })

export class CborDetError extends Error {
  constructor(code, detail) {
    super(detail ? `${code}: ${detail}` : code)
    this.name = 'CborDetError'
    this.code = code
  }
}

const fail = (code, detail) => { throw new CborDetError(code, detail) }

export function compareBytes(a, b) {
  return Buffer.compare(Buffer.from(a.buffer, a.byteOffset, a.byteLength), Buffer.from(b.buffer, b.byteOffset, b.byteLength))
}

export function bytesEqual(a, b) {
  return a.byteLength === b.byteLength && compareBytes(a, b) === 0
}

function head(major, value) {
  if (!Number.isSafeInteger(value) || value < 0) fail('internal', 'head argument outside the safe range')
  const m = major << 5
  if (value < 24) return Buffer.from([m | value])
  if (value < 0x100) return Buffer.from([m | 24, value])
  if (value < 0x10000) { const b = Buffer.alloc(3); b[0] = m | 25; b.writeUInt16BE(value, 1); return b }
  if (value < TWO_32) { const b = Buffer.alloc(5); b[0] = m | 26; b.writeUInt32BE(value, 1); return b }
  const b = Buffer.alloc(9)
  b[0] = m | 27
  b.writeUInt32BE(Math.floor(value / TWO_32), 1)
  b.writeUInt32BE(value % TWO_32, 5)
  return b
}

let superseded = false

function encodeNumber(value) {
  if (Number.isSafeInteger(value) && !(superseded && (value >= TWO_32 || value < -TWO_32))) return value >= 0 ? head(0, value) : head(1, -1 - value)
  // Non-integers, and integral values outside ±(2^53-1), are binary64 (published vectors
  // int-above-safe-range-stays-float64, int-far-above-safe-range-stays-float64, float-*).
  if (Number.isNaN(value)) return Buffer.from(NAN_BYTES)
  const b = Buffer.alloc(9)
  b[0] = 0xfb
  b.writeDoubleBE(value, 1)
  return b
}

function isPlainObject(value) {
  const proto = Object.getPrototypeOf(value)
  return proto === Object.prototype || proto === null
}

function sortedEntries(pairs) {
  pairs.sort((a, b) => compareBytes(a[0], b[0]))
  for (let i = 1; i < pairs.length; i++) {
    if (bytesEqual(pairs[i - 1][0], pairs[i][0])) fail('duplicate-key', 'two map keys have the same canonical encoding')
  }
  return pairs
}

function encodeMap(pairs, depth) {
  const encoded = []
  for (const [key, value] of pairs) {
    if (value === undefined) continue // absent map member: elided (ENV §3)
    if (key === undefined) fail('unsupported-type', 'undefined map key')
    encoded.push([encodeItem(key, depth + 1, 'key'), encodeItem(value, depth + 1, 'member')])
  }
  sortedEntries(encoded)
  return Buffer.concat([head(5, encoded.length), ...encoded.flat()])
}

function encodeItem(value, depth, position) {
  if (depth > LIMITS.depth) fail('depth', `nesting deeper than ${LIMITS.depth}`)
  if (value === undefined) {
    if (position === 'top') return Buffer.from([0xf7]) // whole value: CBOR undefined
    if (position === 'element') return Buffer.from([0xf6]) // array element: null
    fail('unsupported-type', 'undefined in this position')
  }
  if (value === null) return Buffer.from([0xf6])
  if (value === true) return Buffer.from([0xf5])
  if (value === false) return Buffer.from([0xf4])
  switch (typeof value) {
    case 'number': return encodeNumber(value)
    case 'bigint': return fail('bigint-input', 'bigint inputs are refused by the profile')
    case 'string': {
      if (!value.isWellFormed()) fail('string-not-well-formed', 'text contains a lone surrogate')
      const bytes = Buffer.from(value, 'utf8')
      return Buffer.concat([head(3, bytes.length), bytes])
    }
    case 'object': break
    default: return fail('unsupported-type', typeof value)
  }
  if (value instanceof Uint8Array) {
    const bytes = Buffer.from(value.buffer, value.byteOffset, value.byteLength)
    return Buffer.concat([head(2, bytes.length), bytes])
  }
  if (ArrayBuffer.isView(value) || value instanceof ArrayBuffer) fail('unsupported-type', 'binary data other than Uint8Array')
  if (Array.isArray(value)) {
    const length = value.length
    const items = []
    for (let i = 0; i < length; i++) items.push(encodeItem(value[i], depth + 1, 'element'))
    return Buffer.concat([head(4, length), ...items])
  }
  if (value instanceof Date) {
    const ms = value.getTime()
    if (!Number.isSafeInteger(ms)) fail('unsupported-type', 'invalid Date')
    return encodeNumber(ms) // timestamps: integer milliseconds, no tag (ENV §3)
  }
  if (value instanceof Set) {
    const items = [...value].map(item => encodeItem(item, depth + 1, 'element'))
    items.sort(compareBytes) // a set is an array sorted by canonical encodings (ENV §3)
    for (let i = 1; i < items.length; i++) {
      if (bytesEqual(items[i - 1], items[i])) fail('duplicate-set-member', 'two set members have the same canonical encoding')
    }
    return Buffer.concat([head(4, items.length), ...items])
  }
  if (value instanceof Map) return encodeMap([...value.entries()], depth)
  if (isPlainObject(value)) {
    if (Object.getOwnPropertySymbols(value).length > 0) fail('unsupported-type', 'symbol-keyed property')
    return encodeMap(Object.keys(value).map(key => [key, value[key]]), depth)
  }
  return fail('unsupported-type', 'object is not a plain object, Map, Set, Date, array or Uint8Array')
}

export function encode(value) {
  return encodeItem(value, 0, 'top')
}

export function encodeSuperseded(value) {
  superseded = true
  try { return encodeItem(value, 0, 'top') } finally { superseded = false }
}

class Reader {
  constructor(bytes) {
    if (!(bytes instanceof Uint8Array)) fail('input', 'decoder input must be a Uint8Array')
    if (bytes.byteLength > LIMITS.bytes) fail('input', 'input exceeds the decoder size bound')
    this.bytes = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength)
    this.pos = 0
  }
  remaining() { return this.bytes.length - this.pos }
  take(n) {
    if (n > this.remaining()) fail('truncated', 'item extends past the end of the input')
    const out = this.bytes.subarray(this.pos, this.pos + n)
    this.pos += n
    return out
  }
  argument(info) {
    if (info < 24) return info
    if (info === 24) return this.take(1)[0]
    if (info === 25) return this.take(2).readUInt16BE(0)
    if (info === 26) return this.take(4).readUInt32BE(0)
    if (info === 27) return this.take(8).readBigUInt64BE(0)
    if (info === 31) fail('indefinite-length', 'indefinite-length items are not part of the profile')
    return fail('not-well-formed', 'reserved additional information value')
  }
}

function lengthArgument(reader, info) {
  const n = reader.argument(info)
  if (typeof n === 'bigint') {
    if (n > BigInt(reader.remaining())) fail('truncated', 'declared length exceeds the input')
    return Number(n)
  }
  return n
}

function halfToNumber(bits) {
  const exponent = (bits >> 10) & 0x1f
  const fraction = bits & 0x3ff
  const sign = bits & 0x8000 ? -1 : 1
  if (exponent === 0) return sign * fraction * 2 ** -24
  if (exponent === 31) return fraction ? NaN : sign * Infinity
  return sign * (1 + fraction / 1024) * 2 ** (exponent - 15)
}

function decodeItem(reader, depth) {
  if (depth > LIMITS.depth) fail('depth', `nesting deeper than ${LIMITS.depth}`)
  const initial = reader.take(1)[0]
  const major = initial >> 5
  const info = initial & 0x1f
  switch (major) {
    case 0:
    case 1: {
      if (info === 31) fail('not-well-formed', 'indefinite integer')
      const n = reader.argument(info)
      // The profile's value domain is ±(2^53-1) (ENV §3); a decoder MAY accept a
      // non-shortest head and return the value it denotes.
      if (major === 0) {
        if (typeof n === 'bigint' && n > BigInt(MAX_SAFE)) fail('integer-out-of-domain', 'unsigned integer above 2^53-1')
        return Number(n)
      }
      if (typeof n === 'bigint' && n > BigInt(MAX_SAFE - 1)) fail('integer-out-of-domain', 'negative integer below -(2^53-1)')
      return -1 - Number(n)
    }
    case 2: {
      const length = lengthArgument(reader, info)
      return Uint8Array.from(reader.take(length))
    }
    case 3: {
      const length = lengthArgument(reader, info)
      try { return UTF8.decode(reader.take(length)) } catch (error) {
        if (error instanceof CborDetError) throw error
        return fail('invalid-utf8', 'text string is not valid UTF-8')
      }
    }
    case 4: {
      const count = lengthArgument(reader, info)
      if (count > reader.remaining()) fail('truncated', 'declared array length exceeds the input')
      const items = []
      for (let i = 0; i < count; i++) items.push(decodeItem(reader, depth + 1))
      return items
    }
    case 5: {
      const count = lengthArgument(reader, info)
      if (count * 2 > reader.remaining()) fail('truncated', 'declared map size exceeds the input')
      const map = new Map()
      const seen = new Set()
      for (let i = 0; i < count; i++) {
        const key = decodeItem(reader, depth + 1)
        const value = decodeItem(reader, depth + 1)
        const keyId = encode(key).toString('hex')
        if (seen.has(keyId)) fail('duplicate-key', 'map carries the same key twice')
        seen.add(keyId)
        map.set(key, value)
      }
      return map
    }
    case 6: return fail('tag', 'tagged items are rejected by the profile')
    default: break
  }
  switch (info) {
    case 20: return false
    case 21: return true
    case 22: return null
    case 23: return undefined
    case 24: {
      const simple = reader.take(1)[0]
      if (simple < 32) fail('not-well-formed', 'two-byte simple value below 32')
      return fail('simple-value', 'unassigned simple value')
    }
    case 25: return halfToNumber(reader.take(2).readUInt16BE(0))
    case 26: return reader.take(4).readFloatBE(0)
    case 27: return reader.take(8).readDoubleBE(0)
    case 31: return fail('not-well-formed', 'break outside an indefinite-length item')
    default:
      if (info < 20) return fail('simple-value', 'unassigned simple value')
      return fail('not-well-formed', 'reserved additional information value')
  }
}

export function decode(bytes) {
  const reader = new Reader(bytes)
  const value = decodeItem(reader, 0)
  if (reader.remaining() !== 0) fail('trailing-bytes', 'bytes follow the top-level item')
  return value
}

export function decodeStrict(bytes) {
  const value = decode(bytes)
  if (!bytesEqual(encode(value), bytes)) fail('non-deterministic', 'input is not the deterministic encoding of its value')
  return value
}

export function isDeterministic(bytes) {
  try { decodeStrict(bytes); return true } catch (error) {
    if (error instanceof CborDetError) return false
    throw error
  }
}
