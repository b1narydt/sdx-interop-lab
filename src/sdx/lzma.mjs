// LZMA decoder for the .lzma "alone" container, written for the laboratory from the LZMA
// specification's reference decoder (LzmaSpec). Node.js has no LZMA, so this file is the
// Node checker's oracle for the ENV §9 compression step. Node built-ins only.
//
// decodeAlone(bytes) returns { properties, dictionarySize, declaredSize, output, marker },
// where `marker` is true when the stream ends with an end-of-stream marker. ENV §9 has
// writers disable the marker; the laboratory's container reading is the alone header with
// the uncompressed size, then the stream with no marker.
//
// The output is bounded at 16 MiB, a laboratory bound (ENV §17.6); a refusal caused by it
// when reading an implementation's output is ERROR, never FAIL.

export const LZMA_LIMIT = 16 * 1024 * 1024
export class LzmaError extends Error {
  constructor(code, detail) { super(detail ? `${code}: ${detail}` : code); this.name = 'LzmaError'; this.code = code }
}
const fail = (code, detail) => { throw new LzmaError(code, detail) }

const PROB_INIT = 1024
const NUM_STATES = 12
const POS_BITS_MAX = 4
const MATCH_MIN_LEN = 2
const END_POS_MODEL_INDEX = 14
const NUM_FULL_DISTANCES = 128
const NUM_ALIGN_BITS = 4
const probs = n => new Uint16Array(n).fill(PROB_INIT)

class RangeDecoder {
  constructor(input, pos) {
    this.input = input
    this.pos = pos
    this.range = 0xffffffff
    this.code = 0
    const first = this.byte()
    for (let i = 0; i < 4; i++) this.code = ((this.code * 256) + this.byte()) >>> 0
    if (first !== 0 || this.code === this.range) fail('corrupt', 'range coder initialisation')
  }
  byte() {
    if (this.pos >= this.input.length) fail('truncated', 'stream ends early')
    return this.input[this.pos++]
  }
  normalize() {
    if (this.range < 0x01000000) {
      this.range = (this.range * 256) >>> 0
      this.code = ((this.code * 256) + this.byte()) >>> 0
    }
  }
  bit(p, i) {
    const v = p[i]
    const bound = (this.range >>> 11) * v
    let symbol
    if (this.code < bound) {
      p[i] = v + ((2048 - v) >>> 5)
      this.range = bound
      symbol = 0
    } else {
      p[i] = v - (v >>> 5)
      this.code = (this.code - bound) >>> 0
      this.range = (this.range - bound) >>> 0
      symbol = 1
    }
    this.normalize()
    return symbol
  }
  direct(count) {
    let result = 0
    for (let i = 0; i < count; i++) {
      this.range = this.range >>> 1
      let bit = 0
      if (this.code >= this.range) { this.code = (this.code - this.range) >>> 0; bit = 1 }
      if (this.code === this.range) fail('corrupt', 'direct bits')
      this.normalize()
      result = result * 2 + bit
    }
    return result
  }
  tree(p, offset, bits) {
    let m = 1
    for (let i = 0; i < bits; i++) m = (m << 1) + this.bit(p, offset + m)
    return m - (1 << bits)
  }
  reverse(p, offset, bits) {
    let m = 1, symbol = 0
    for (let i = 0; i < bits; i++) {
      const b = this.bit(p, offset + m)
      m = (m << 1) + b
      symbol |= b << i
    }
    return symbol
  }
}

class LenDecoder {
  constructor() {
    this.choice = probs(2)
    this.low = probs(16 << 3)
    this.mid = probs(16 << 3)
    this.high = probs(256)
  }
  decode(rc, posState) {
    if (rc.bit(this.choice, 0) === 0) return rc.tree(this.low, posState << 3, 3)
    if (rc.bit(this.choice, 1) === 0) return 8 + rc.tree(this.mid, posState << 3, 3)
    return 16 + rc.tree(this.high, 0, 8)
  }
}

export function decodeAlone(bytes, limit = LZMA_LIMIT) {
  const input = Uint8Array.from(bytes)
  if (input.length < 13) fail('truncated', 'header shorter than 13 bytes')
  let d = input[0]
  if (d >= 9 * 5 * 5) fail('properties', 'properties byte out of range')
  const lc = d % 9; d = Math.floor(d / 9)
  const lp = d % 5
  const pb = Math.floor(d / 5)
  const dictionarySize = (input[1] | (input[2] << 8) | (input[3] << 16) | (input[4] << 24)) >>> 0
  const dict = Math.max(dictionarySize, 4096)
  let sizeKnown = false
  let declared = 0n
  for (let i = 0; i < 8; i++) declared |= BigInt(input[5 + i]) << BigInt(8 * i)
  if (declared !== 0xffffffffffffffffn) sizeKnown = true
  if (sizeKnown && declared > BigInt(limit)) fail('limit', 'declared size exceeds the laboratory bound')
  let remaining = sizeKnown ? Number(declared) : Infinity
  const out = sizeKnown ? new Uint8Array(remaining) : new Uint8Array(Math.min(limit, 1 << 16))
  let buffer = out
  let total = 0
  const put = byte => {
    if (total >= buffer.length) {
      if (sizeKnown || buffer.length >= limit) fail('limit', 'output exceeds the bound')
      const grown = new Uint8Array(Math.min(limit, buffer.length * 2)); grown.set(buffer); buffer = grown
    }
    buffer[total++] = byte
  }
  const get = dist => buffer[total - dist]

  const rc = new RangeDecoder(input, 13)
  const literal = probs(0x300 << (lc + lp))
  const posSlot = [0, 1, 2, 3].map(() => probs(1 << 6))
  const posDecoders = probs(1 + NUM_FULL_DISTANCES - END_POS_MODEL_INDEX)
  const align = probs(1 << NUM_ALIGN_BITS)
  const isMatch = probs(NUM_STATES << POS_BITS_MAX)
  const isRep = probs(NUM_STATES), isRepG0 = probs(NUM_STATES), isRepG1 = probs(NUM_STATES), isRepG2 = probs(NUM_STATES)
  const isRep0Long = probs(NUM_STATES << POS_BITS_MAX)
  const lenDecoder = new LenDecoder(), repLenDecoder = new LenDecoder()
  let state = 0, rep0 = 0, rep1 = 0, rep2 = 0, rep3 = 0
  const pbMask = (1 << pb) - 1, lpMask = (1 << lp) - 1

  const decodeLiteral = () => {
    const prev = total > 0 ? get(1) : 0
    const litState = ((total & lpMask) << lc) + (prev >> (8 - lc))
    const base = 0x300 * litState
    let symbol = 1
    if (state >= 7) {
      let matchByte = get(rep0 + 1)
      do {
        const matchBit = (matchByte >> 7) & 1
        matchByte <<= 1
        const b = rc.bit(literal, base + ((1 + matchBit) << 8) + symbol)
        symbol = (symbol << 1) | b
        if (matchBit !== b) break
      } while (symbol < 0x100)
    }
    while (symbol < 0x100) symbol = (symbol << 1) | rc.bit(literal, base + symbol)
    put(symbol - 0x100)
  }
  const decodeDistance = len => {
    const lenState = Math.min(len, 3)
    const slot = rc.tree(posSlot[lenState], 0, 6)
    if (slot < 4) return slot
    const directBits = (slot >> 1) - 1
    let dist = (2 | (slot & 1)) * 2 ** directBits
    if (slot < END_POS_MODEL_INDEX) dist += rc.reverse(posDecoders, dist - slot, directBits)
    else dist += rc.direct(directBits - NUM_ALIGN_BITS) * 16 + rc.reverse(align, 0, NUM_ALIGN_BITS)
    return dist
  }

  for (;;) {
    if (sizeKnown && remaining === 0 && rc.code === 0) {
      return finish(false)
    }
    const posState = total & pbMask
    if (rc.bit(isMatch, (state << POS_BITS_MAX) + posState) === 0) {
      if (sizeKnown && remaining === 0) fail('corrupt', 'data after the declared size')
      decodeLiteral()
      state = state < 4 ? 0 : state < 10 ? state - 3 : state - 6
      remaining--
      continue
    }
    let len
    if (rc.bit(isRep, state) !== 0) {
      if (sizeKnown && remaining === 0) fail('corrupt', 'data after the declared size')
      if (total === 0) fail('corrupt', 'repeat match before any output')
      if (rc.bit(isRepG0, state) === 0) {
        if (rc.bit(isRep0Long, (state << POS_BITS_MAX) + posState) === 0) {
          state = state < 7 ? 9 : 11
          put(get(rep0 + 1))
          remaining--
          continue
        }
      } else {
        let dist
        if (rc.bit(isRepG1, state) === 0) dist = rep1
        else {
          if (rc.bit(isRepG2, state) === 0) dist = rep2
          else { dist = rep3; rep3 = rep2 }
          rep2 = rep1
        }
        rep1 = rep0
        rep0 = dist
      }
      len = repLenDecoder.decode(rc, posState)
      state = state < 7 ? 8 : 11
    } else {
      rep3 = rep2; rep2 = rep1; rep1 = rep0
      len = lenDecoder.decode(rc, posState)
      state = state < 7 ? 7 : 10
      rep0 = decodeDistance(len)
      if (rep0 === 0xffffffff) {
        if (rc.code !== 0) fail('corrupt', 'end marker with a non-zero range code')
        if (sizeKnown && remaining !== 0) fail('corrupt', 'end marker before the declared size')
        return finish(true)
      }
      if (sizeKnown && remaining === 0) fail('corrupt', 'data after the declared size')
      if (rep0 >= dict || rep0 >= total) fail('corrupt', 'match distance beyond the output')
    }
    len += MATCH_MIN_LEN
    if (sizeKnown && remaining < len) fail('corrupt', 'match runs past the declared size')
    for (let i = 0; i < len; i++) put(get(rep0 + 1))
    remaining -= len
  }

  function finish(marker) {
    if (rc.pos !== input.length) fail('trailing-bytes', `${input.length - rc.pos} bytes follow the stream`)
    return {
      properties: { lc, lp, pb, byte: input[0] },
      dictionarySize,
      declaredSize: sizeKnown ? Number(declared) : null,
      output: buffer.slice(0, total),
      marker
    }
  }
}
