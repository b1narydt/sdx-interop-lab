// ENV §9: LZMA at level 9 with the end-of-stream marker disabled. SDX names no container.
// Laboratory reading: the .lzma "alone" container, a 13-byte header (properties byte,
// 4-byte little-endian dictionary size, 8-byte little-endian uncompressed size, here known)
// followed by the raw stream, with no end-of-stream marker. The encoder is LZMA-JS 2.3.2
// (npm `lzma`) in mode 9 with its `disableEndMark` switch: lc 3, lp 0, pb 2, a 32 MiB
// dictionary and 255 fast bytes. Other encoders at "level 9" choose other dictionary sizes
// and match finders, so compressed bytes are encoder-specific (a source finding); readers
// compare the decompressed bytes.
import { createRequire } from 'node:module'
import { fail } from './lab.mjs'

const require = createRequire(import.meta.url)
const LZMA = require('lzma').LZMA()

export function compress(plaintext) {
  LZMA.disableEndMark = true
  const out = Uint8Array.from(LZMA.compress(Array.from(plaintext), 9).map(b => b & 0xff))
  if (out[0] !== 0x5d) fail('LZMA properties byte')
  const size = Buffer.from(out.subarray(5, 13)).readBigUInt64LE(0)
  if (size !== BigInt(plaintext.length)) fail('LZMA header size')
  return out
}

// The same stream with the end-of-stream marker written, for the reader-leniency case.
export function compressWithMarker(plaintext) {
  delete LZMA.disableEndMark
  try { return Uint8Array.from(LZMA.compress(Array.from(plaintext), 9).map(b => b & 0xff)) } finally { LZMA.disableEndMark = true }
}

export function decompress(bytes) {
  const out = LZMA.decompress(Array.from(bytes))
  return typeof out === 'string' ? new TextEncoder().encode(out) : Uint8Array.from(out.map(b => b & 0xff))
}
