// Loads the generator's oracle libraries.
//
// @bsv/sdk 4.0.1 resolves node:crypto through process.getBuiltinModule when its modules load
// and then uses it for AES-GCM, SHA-256 and HMAC. The checkers in src/ use node:crypto, so
// the SDK is loaded with getBuiltinModule hidden: its pure-TypeScript AES-GCM, SHA-256,
// HMAC and secp256k1/P-256 arithmetic produce every SDK-derived vector value. The test
// "SDK oracle shares no node:crypto code" confirms this by counting node:crypto calls.
//
// @noble/ciphers 2.4.0 (AES-256-GCM with additional authenticated data, which @bsv/sdk 4.0.1
// does not expose) is loaded normally.

const saved = process.getBuiltinModule
let sdk
try {
  process.getBuiltinModule = undefined
  sdk = await import('@bsv/sdk')
} finally {
  process.getBuiltinModule = saved
}
export { sdk }
export { gcm } from '@noble/ciphers/aes.js'
