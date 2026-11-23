// Deterministic CBOR for the generators (cborg 6.2.1 with its RFC 8949 options), the ENV §8.3
// superseded integer shape, and the driver contract's JSON value model. The checkers carry
// their own encoders and do not import this file.
import { Token, Type, decode as cborgDecode, encode as cborgEncode, rfc8949EncodeOptions } from 'cborg'
import { fail, hex, unhex } from './lab.mjs'

const TWO_32 = 2 ** 32
const strip = value => {
  if (value === undefined) fail('undefined value reached the encoder')
  if (value instanceof Uint8Array || value === null || typeof value !== 'object') return value
  if (Array.isArray(value)) return value.map(strip)
  if (value instanceof Map) return value
  return Object.fromEntries(Object.entries(value).filter(([, v]) => v !== undefined).map(([k, v]) => [k, strip(v)]))
}

// ENV §3 under cborg: bytewise-sorted map keys, shortest integer heads, no tags. The values
// the generators encode are text, safe integers, booleans, null, byte strings, arrays and maps.
export const encode = value => cborgEncode(strip(value), rfc8949EncodeOptions)

// ENV §8.3: before the fix, integers that need the 8-byte head were written as binary64.
const SUPERSEDED = {
  ...rfc8949EncodeOptions,
  float64: true,
  typeEncoders: { number: n => (Number.isSafeInteger(n) && (n >= TWO_32 || n < -TWO_32)) ? [new Token(Type.float, n)] : null }
}
export const encodeSuperseded = value => cborgEncode(strip(value), SUPERSEDED)
export const decode = bytes => cborgDecode(bytes, { useMaps: false })

// The driver contract's JSON value model: text, safe integers, booleans and null as JSON;
// a byte string as {"$bytes": "<hex>"}; arrays and maps as JSON arrays and objects.
export function fromJson(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value
  if (typeof value === 'number') { if (!Number.isSafeInteger(value)) fail('JSON value outside the safe integers'); return value }
  if (Array.isArray(value)) return value.map(fromJson)
  const keys = Object.keys(value)
  if (keys.length === 1 && keys[0] === '$bytes') return unhex(value.$bytes)
  return Object.fromEntries(keys.map(key => [key, fromJson(value[key])]))
}
export function toJson(value) {
  if (value instanceof Uint8Array) return { $bytes: hex(value) }
  if (value === null || typeof value !== 'object') return value
  if (Array.isArray(value)) return value.map(toJson)
  return Object.fromEntries(Object.keys(value).sort().map(key => [key, toJson(value[key])]))
}

// Hand-assembled CBOR for refusal cases that no conforming encoder emits.
export const head = (major, n) => {
  if (n < 24) return Uint8Array.of((major << 5) | n)
  if (n < 0x100) return Uint8Array.of((major << 5) | 24, n)
  if (n < 0x10000) return Uint8Array.of((major << 5) | 25, n >> 8, n & 0xff)
  return Uint8Array.of((major << 5) | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff)
}
