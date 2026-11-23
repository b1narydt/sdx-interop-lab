// Deterministic CBOR for the generator. Every map is encoded with cborg (RFC 8949 §4.2.1
// bytewise key order) and, independently, with the laboratory encoder of
// src/sdx/cbor-det.mjs; the two must agree byte for byte.

import * as cborg from 'cborg'
import { encode as labEncode } from '../../../../src/sdx/cbor-det.mjs'

export const agreement = { encoded: 0 }

const plain = value => {
  if (value instanceof Uint8Array) return new Uint8Array(value)
  if (Array.isArray(value)) return value.map(plain)
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, plain(v)]))
  return value
}

export function det(value) {
  const input = plain(value)
  const viaCborg = Buffer.from(cborg.encode(input, cborg.rfc8949EncodeOptions))
  const viaLab = labEncode(input)
  if (!viaCborg.equals(viaLab)) throw new Error(`cborg and src/sdx/cbor-det.mjs disagree: ${viaCborg.toString('hex')} != ${viaLab.toString('hex')}`)
  agreement.encoded++
  return viaCborg
}

// Insertion-order encoding: the map keys in the order the value lists them, not in deterministic
// order. Used only to build the non-deterministic negative case.
export function insertionOrder(value) {
  return Buffer.from(cborg.encode(plain(value), { mapSorter: () => 0 }))
}

export function cborgDecode(bytes) {
  return cborg.decode(bytes, { useMaps: true, strict: true, rejectDuplicateMapKeys: true })
}

export { cborg }
