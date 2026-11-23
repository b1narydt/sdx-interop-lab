import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'
import { CheckError, publicKeyFromPrivate, toBytes } from '../sdx/brc42.mjs'
import { brc78Decrypt, brc78Encrypt, parseBrc78 } from '../sdx/brc2.mjs'

// Independent oracle for the BRC-39 recipient protector draft (protector type 0x02). It
// imports no wallet, SDK or Toolbox code, and does not reuse the password-protector oracle
// in brc39.mjs. Laboratory layout, recorded in fixtures/sdx/v1/vc-b39r/vectors.json:
//
//   offset  bytes  field
//   0       4      Magic "WDAT"
//   4       1      Format Version 0x02
//   5       1      Protector Type 0x02 (recipient)
//   6       1      Inner Format (0x26 = BRC-38 wallet data)
//   7       1      KDF Type 0x00 (none)
//   8       1      Flags 0x00
//   9       1      Salt Length 0x00
//   10      1      Nonce Length 0x20
//   11      4      Argon2id Iterations 0
//   15      4      Argon2id Memory KiB 0
//   19      1      Argon2id Parallelism 0
//   20      1      Argon2id Hash Length 0
//   21      12     Reserved, zero
//   33      2      Wrapped Key Length L, big-endian, 1..1024
//   35      L      Wrapped Key: BRC-78 message whose plaintext is the 32-byte content key K
//   35+L    0      Salt (absent)
//   35+L    32     Nonce
//   67+L    *      AES-256-GCM ciphertext of the inner payload under K, then a 16-byte tag
//
// The additional authenticated data is bytes 0 .. 35+L (Magic through Wrapped Key).
// Format Version 0x02 keeps BRC-39 §14.3's Format Version 0x01 refusal of protector type 2
// unchanged.

export const MAGIC = Buffer.from('WDAT', 'ascii')
export const FORMAT_VERSION = 0x02
export const PROTECTOR_RECIPIENT = 0x02
export const INNER_FORMATS = Object.freeze({ 0x26: 'BRC-38 wallet data' })
export const NONCE_BYTES = 32
export const TAG_BYTES = 16
export const KEY_BYTES = 32
export const FIXED_HEADER_BYTES = 35
export const LIMITS = Object.freeze({ fileBytes: 64 * 1024 * 1024, wrappedKeyBytes: 1024 })

function refuse(stage, code, message) { throw new CheckError(code, message, { stage }) }

/** Validate everything that can be validated before unwrapping (draft §3, except the
 * recipient check, which needs the importer's key). */
export function inspectRecipientHeader(file) {
  if (!(file instanceof Uint8Array) || file.length < FIXED_HEADER_BYTES || file.length > LIMITS.fileBytes) refuse('header', 'ERR_FILE_SIZE', 'file is shorter than the fixed header or above the size limit')
  const bytes = Buffer.from(file.buffer, file.byteOffset, file.byteLength)
  if (!bytes.subarray(0, 4).equals(MAGIC)) refuse('header', 'ERR_MAGIC', 'magic is not WDAT')
  if (bytes[4] !== FORMAT_VERSION) refuse('header', 'ERR_FORMAT_VERSION', `format version ${bytes[4]} is not 2`)
  if (bytes[5] !== PROTECTOR_RECIPIENT) refuse('header', 'ERR_PROTECTOR_TYPE', `protector type ${bytes[5]} is not 2`)
  if (!Object.hasOwn(INNER_FORMATS, bytes[6])) refuse('header', 'ERR_INNER_FORMAT', `inner format ${bytes[6]} is unknown`)
  if (bytes[7] !== 0) refuse('header', 'ERR_KDF_TYPE', 'KDF type must be 0x00 for protector 0x02')
  if (bytes[8] !== 0) refuse('header', 'ERR_FLAGS', 'flags must be zero')
  if (bytes[9] !== 0) refuse('header', 'ERR_SALT_LENGTH', 'salt length must be 0')
  if (bytes[10] !== NONCE_BYTES) refuse('header', 'ERR_NONCE_LENGTH', 'nonce length must be 32')
  if (bytes.subarray(11, 21).some(byte => byte !== 0)) refuse('header', 'ERR_ARGON2_FIELDS', 'Argon2id fields must be zero')
  if (bytes.subarray(21, 33).some(byte => byte !== 0)) refuse('header', 'ERR_RESERVED', 'reserved bytes must be zero')
  const wrappedKeyLength = bytes.readUInt16BE(33)
  if (wrappedKeyLength === 0 || wrappedKeyLength > LIMITS.wrappedKeyBytes) refuse('header', 'ERR_WRAPPED_KEY_LENGTH', `wrapped key length ${wrappedKeyLength} is outside 1..1024`)
  const aadEnd = FIXED_HEADER_BYTES + wrappedKeyLength
  if (bytes.length < aadEnd + NONCE_BYTES + TAG_BYTES) refuse('header', 'ERR_FILE_SIZE', 'file is shorter than its header, nonce and tag')
  const wrappedKey = bytes.subarray(FIXED_HEADER_BYTES, aadEnd)
  let message
  try { message = parseBrc78(wrappedKey) } catch (error) { refuse('header', 'ERR_WRAPPED_KEY_FORMAT', error.message) }
  return {
    innerFormat: bytes[6], wrappedKey, sender: message.sender, recipient: message.recipient,
    aad: bytes.subarray(0, aadEnd), nonce: bytes.subarray(aadEnd, aadEnd + NONCE_BYTES),
    ciphertext: bytes.subarray(aadEnd + NONCE_BYTES, -TAG_BYTES), tag: bytes.subarray(-TAG_BYTES)
  }
}

function innerPayload(innerFormat, plaintext) {
  if (innerFormat === 0x26) {
    let document
    try { document = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext)) } catch { refuse('inner', 'ERR_INNER_PAYLOAD', 'inner payload is not UTF-8 JSON') }
    if (document === null || typeof document !== 'object' || document.brc !== 38 || document.formatVersion !== 1) refuse('inner', 'ERR_INNER_PAYLOAD', 'inner payload is not a BRC-38 document')
  }
  return plaintext
}

/** Import: header validation, recipient check, BRC-78 unwrap, AES-256-GCM with the header as
 * AAD, then the inner-format check. Every refusal carries its stage. */
export function decryptRecipientFile(file, importerPrivateKey) {
  const parsed = inspectRecipientHeader(file)
  const importer = publicKeyFromPrivate(toBytes(importerPrivateKey, 32, 'ERR_PRIVATE_KEY', 'importer key'))
  if (!parsed.recipient.equals(importer)) refuse('recipient', 'ERR_RECIPIENT', 'the BRC-78 recipient is not the importer identity key')
  let contentKey
  try { contentKey = brc78Decrypt(parsed.wrappedKey, importerPrivateKey) } catch { refuse('unwrap', 'ERR_UNWRAP', 'BRC-78 unwrapping failed') }
  if (contentKey.length !== KEY_BYTES) refuse('unwrap', 'ERR_CONTENT_KEY_LENGTH', 'the content key is not 32 bytes')
  let plaintext
  try {
    const decipher = createDecipheriv('aes-256-gcm', contentKey, parsed.nonce, { authTagLength: TAG_BYTES })
    decipher.setAAD(parsed.aad)
    decipher.setAuthTag(parsed.tag)
    plaintext = Buffer.concat([decipher.update(parsed.ciphertext), decipher.final()])
  } catch { refuse('decrypt', 'ERR_DECRYPT', 'AES-256-GCM authentication failed') }
  finally { contentKey.fill(0) }
  return innerPayload(parsed.innerFormat, plaintext)
}

/** Export with injected randomness, so tests can build files independently of any SDK. */
export function encryptRecipientFile(plaintext, { senderPrivateKey, recipientPublicKey, innerFormat = 0x26, randomness = randomBytes }) {
  if (!Object.hasOwn(INNER_FORMATS, innerFormat)) throw new CheckError('ERR_INNER_FORMAT', 'unknown inner format', { stage: 'header' })
  const contentKey = Buffer.from(randomness(KEY_BYTES)), nonce = Buffer.from(randomness(NONCE_BYTES))
  if (contentKey.length !== KEY_BYTES || nonce.length !== NONCE_BYTES) throw new RangeError('randomness-size')
  const wrappedKey = brc78Encrypt(contentKey, senderPrivateKey, recipientPublicKey, { keyID: randomness(32), iv: randomness(32) })
  const header = Buffer.alloc(FIXED_HEADER_BYTES)
  MAGIC.copy(header); header[4] = FORMAT_VERSION; header[5] = PROTECTOR_RECIPIENT; header[6] = innerFormat; header[10] = NONCE_BYTES
  header.writeUInt16BE(wrappedKey.length, 33)
  const aad = Buffer.concat([header, wrappedKey])
  try {
    const cipher = createCipheriv('aes-256-gcm', contentKey, nonce, { authTagLength: TAG_BYTES })
    cipher.setAAD(aad)
    return Buffer.concat([aad, nonce, cipher.update(toBytes(plaintext)), cipher.final(), cipher.getAuthTag()])
  } finally { contentKey.fill(0) }
}
