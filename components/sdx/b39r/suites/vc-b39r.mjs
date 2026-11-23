import { sdk, gcm } from '../oracle.mjs'
import { SCHEMA, CLAIM, STATUS, hex, fromHex, utf8, pick, pub, priv, wallet, cite, citeBrc, generatorRecord, assert, rejects } from '../common.mjs'

const { PrivateKey, PublicKey, EncryptedMessage, Hash, Utils } = sdk

// BRC-39 §14 canonical BRC-38 document (874 bytes, SHA-256 e76c1eb7…).
export const BRC38_DOCUMENT = '{"brc":38,"exportedAt":"2026-01-02T03:04:05.006Z","formatVersion":1,"sourceStorage":{"chain":"test","created_at":"2026-01-02T03:04:05.006Z","dbtype":"SQLite","maxOutputScript":1024,"storageIdentityKey":"021111111111111111111111111111111111111111111111111111111111111111","storageName":"synthetic","updated_at":"2026-01-02T03:04:05.006Z"},"tables":{"certificateFields":[],"certificates":[],"commissions":[],"outputBaskets":[],"outputTagMaps":[],"outputTags":[],"outputs":[],"provenTxReqs":[],"provenTxs":[],"syncStates":[],"transactions":[],"txLabelMaps":[],"txLabels":[]},"title":"User Wallet Data Format","user":{"activeStorage":"021111111111111111111111111111111111111111111111111111111111111111","created_at":"2026-01-02T03:04:05.006Z","identityKey":"032222222222222222222222222222222222222222222222222222222222222222","updated_at":"2026-01-02T03:04:05.006Z","userId":1}}'
const BRC38_SHA256 = 'e76c1eb7a57cdf87e8d8a9c50b783e50decffb54c586bb86fa63186d7a31e48c'

export const LAYOUT = Object.freeze([
  { offset: 0, length: 4, field: 'Magic', value: '57444154 ("WDAT")' },
  { offset: 4, length: 1, field: 'Format Version', value: '02' },
  { offset: 5, length: 1, field: 'Protector Type', value: '02 (recipient)' },
  { offset: 6, length: 1, field: 'Inner Format', value: '26 (BRC-38); the SDX account package code is to be assigned' },
  { offset: 7, length: 1, field: 'KDF Type', value: '00 (none)' },
  { offset: 8, length: 1, field: 'Flags', value: '00' },
  { offset: 9, length: 1, field: 'Salt Length', value: '00' },
  { offset: 10, length: 1, field: 'Nonce Length', value: '20' },
  { offset: 11, length: 4, field: 'Argon2id Iterations', value: '00000000' },
  { offset: 15, length: 4, field: 'Argon2id Memory KiB', value: '00000000' },
  { offset: 19, length: 1, field: 'Argon2id Parallelism', value: '00' },
  { offset: 20, length: 1, field: 'Argon2id Hash Length', value: '00' },
  { offset: 21, length: 12, field: 'Reserved', value: 'zero' },
  { offset: 33, length: 2, field: 'Wrapped Key Length L', value: 'big-endian, 1..1024; 182 (00b6) for a 32-byte K' },
  { offset: 35, length: 'L', field: 'Wrapped Key', value: 'BRC-78 message (42421033 ‖ sender 33 ‖ recipient 33 ‖ keyID 32 ‖ IV 32 ‖ AES-256-GCM(K) 32 ‖ tag 16) whose plaintext is the 32-byte content key K' },
  { offset: '35+L', length: 0, field: 'Salt', value: 'absent' },
  { offset: '35+L', length: 32, field: 'Nonce', value: 'random' },
  { offset: '67+L', length: 'rest', field: 'CiphertextAndTag', value: 'AES-256-GCM(K, Nonce, AAD = bytes 0 .. 35+L, inner payload) followed by the 16-byte tag' }
])

export const DECISIONS = [
  { id: "D-B39R-VERSION", decision: "Protector type 0x02 files use Format Version 0x02.", basis: "brc-draft-brc39-recipient-protector.md §1 \"Format Version\": BRC-39 §14.3 lists protector type 2 as a file an importer must refuse under Format Version 0x01, so a version-1 importer refuses these files by their version, before it reads any new field." },
  { id: "D-B39R-LAYOUT", decision: "Byte layout (see \"layout\"): Magic, Format Version 0x02, Protector Type 0x02, Inner Format, KDF Type 0x00, Flags 0x00, Salt Length 0x00, Nonce Length 0x20, Argon2id Iterations, Memory, Parallelism and Hash Length all zero, 12 reserved zero bytes, Wrapped Key Length (u16 big-endian), Wrapped Key (BRC-78), no Salt, Nonce (32), CiphertextAndTag. The fixed header is 35 bytes; a 32-byte K wraps to 182 bytes, so a file is 249 bytes plus the inner payload.", basis: "brc-draft-brc39-recipient-protector.md §1 \"Header\" (offset table) and \"Sizes\"; BRC-39 §5 field order up to the reserved bytes." },
  { id: "D-B39R-AAD", decision: "The AES-256-GCM additional authenticated data is the header from Magic through the Wrapped Key (bytes 0 .. 35+L). The nonce is GCM's IV and is authenticated through the tag.", basis: "brc-draft-brc39-recipient-protector.md §1 \"Export\" step 2, \"Additional authenticated data\": bytes 0 up to 35+L." },
  { id: "D-B39R-ORDER", decision: "Import order: header validation before any unwrapping; the BRC-78 recipient must equal the importer identity key; BRC-78 unwrap (K must be 32 bytes); GCM; then the inner-format check. Each refusal reports its stage: header, recipient, unwrap, decrypt or inner.", basis: "brc-draft-brc39-recipient-protector.md §1 \"Import\" and §3." },
  { id: "D-B39R-INNER", decision: "Known inner formats: 0x26 (BRC-38 wallet data), checked as UTF-8 JSON with brc 38 and formatVersion 1. The SDX account package code is still to be assigned and has no vector; an unknown code is refused at the header.", basis: "brc-draft-brc39-recipient-protector.md §1 \"Import\" step 5, §2, §3; BRC-39 §6.4." },
  { id: "D-B39R-LENGTH", decision: "A Wrapped Key Length inside 1..1024 that does not match the BRC-78 message makes unwrapping fail, because the BRC-78 ciphertext then absorbs or loses bytes.", basis: "brc-draft-brc39-recipient-protector.md §3 (\"the unwrapped K is not exactly 32 bytes\"; \"the Wrapped Key Length does not match the length of the BRC-78 message. Unwrapping then fails.\"); BRC-78." },
  { id: "D-B39R-RANDOM", decision: "BRC-78 draws a random key ID and IV, so every file is decrypt-direction: generated once and frozen in components/sdx/b39r/frozen-random.json. K and the nonce are fixed laboratory values so the rest of each file reproduces.", basis: "BRC-78; BRC-2." },
  { id: "D-B39R-BRC100", decision: "Unwrapping K is reachable through BRC-100 decrypt with protocol [2, \"message encryption\"], key ID = base64 of the BRC-78 key ID and counterparty = the BRC-78 sender. VC-B39R-003 is a file whose wrapped key was written through BRC-100 encrypt.", basis: "brc-draft-brc39-recipient-protector.md open item 3 (resolved, citing VC-B39R-003); BRC-78; @bsv/sdk 4.0.1." }
]

function headerBytes({ innerFormat = 0x26, wrappedKeyLength }) {
  const header = Buffer.alloc(35)
  header.write('WDAT', 0, 'ascii'); header[4] = 2; header[5] = 2; header[6] = innerFormat; header[10] = 32
  header.writeUInt16BE(wrappedKeyLength, 33)
  return header
}

function buildFile({ wrappedKey, contentKey, nonce, plaintext, innerFormat }) {
  const aad = Buffer.concat([headerBytes({ innerFormat, wrappedKeyLength: wrappedKey.length }), wrappedKey])
  const sealed = gcm(Uint8Array.from(contentKey), Uint8Array.from(nonce), Uint8Array.from(aad)).encrypt(Uint8Array.from(plaintext))
  return Buffer.concat([aad, Buffer.from(nonce), Buffer.from(sealed)])
}

async function openFile(file, importer) {
  const L = file.readUInt16BE(33)
  const wrapped = Array.from(file.subarray(35, 35 + L))
  const K = EncryptedMessage.decrypt(wrapped, PrivateKey.fromHex(priv(importer)))
  const sender = Utils.toHex(wrapped.slice(4, 37)), keyID = Utils.toBase64(wrapped.slice(70, 102))
  const viaWallet = (await wallet(importer).decrypt({ protocolID: [2, 'message encryption'], keyID, counterparty: sender, ciphertext: wrapped.slice(102) })).plaintext
  assert(hex(viaWallet) === hex(K), 'BRC-100 decrypt unwraps the BRC-78 key')
  const aad = file.subarray(0, 35 + L), nonce = file.subarray(35 + L, 67 + L)
  return Buffer.from(gcm(Uint8Array.from(K), Uint8Array.from(nonce), Uint8Array.from(aad)).decrypt(Uint8Array.from(file.subarray(67 + L))))
}

export async function build({ random }) {
  const cases = []
  const add = entry => { cases.push({ id: `VC-B39R-${String(cases.length + 1).padStart(3, '0')}`, ...entry }); return cases.at(-1) }
  const plaintext = utf8(BRC38_DOCUMENT)
  assert(plaintext.length === 874 && hex(Hash.sha256(plaintext)) === BRC38_SHA256, 'BRC-39 §14 document')
  const fixed = label => Hash.sha256(utf8(`LAB_SELF_TEST_ONLY VC-B39R ${label}`))
  const wrapWithSdk = (slot, K, sender, recipient) => random.take(slot, async () => hex(EncryptedMessage.encrypt(K, PrivateKey.fromHex(priv(sender)), PublicKey.fromString(pub(recipient)))))
  const randomized = ['input.file']

  const files = {}
  const positives = [
    ['handover', 'accountA', 'accountB', 'Handover: account A exports to account B. B imports it to the exact BRC-38 document.'],
    ['backup', 'accountB', 'accountB', 'Backup to self: account B wraps the content key to its own identity key, and B restores it.']
  ]
  for (const [name, sender, recipient, description] of positives) {
    const contentKey = fixed(`content key ${name}`), nonce = fixed(`nonce ${name}`)
    const wrappedKey = Buffer.from(await wrapWithSdk(`vc-b39r/${name}/wrapped-key`, contentKey, sender, recipient), 'hex')
    assert(wrappedKey.length === 182, 'BRC-78 of a 32-byte K is 182 bytes')
    const file = buildFile({ wrappedKey, contentKey, nonce, plaintext })
    assert(hex(await openFile(file, recipient)) === hex(plaintext), `${name} opens`)
    files[name] = file
    add({ requirement: 'B39R-01', kind: 'brc39-recipient-file', direction: 'decrypt', randomized, description,
      input: { importer: recipient, file: file.toString('hex') },
      expected: { plaintext: hex(plaintext), plaintextSha256: BRC38_SHA256, innerFormat: 0x26, wrappedKeyLength: 182, sender: pub(sender), recipient: pub(recipient) } })
  }
  // Wrapped key written through BRC-100 encrypt rather than EncryptedMessage.
  {
    const contentKey = fixed('content key brc100'), nonce = fixed('nonce brc100')
    const wrappedKey = Buffer.from(await random.take('vc-b39r/brc100/wrapped-key', async () => {
      const keyID = sdk.Random(32)
      const { ciphertext } = await wallet('accountA').encrypt({ protocolID: [2, 'message encryption'], keyID: Utils.toBase64(keyID), counterparty: pub('accountB'), plaintext: contentKey })
      return hex([...fromHex('42421033'), ...fromHex(pub('accountA')), ...fromHex(pub('accountB')), ...keyID, ...ciphertext])
    }), 'hex')
    const file = buildFile({ wrappedKey, contentKey, nonce, plaintext })
    assert(hex(await openFile(file, 'accountB')) === hex(plaintext), 'BRC-100-written file opens')
    add({ requirement: 'B39R-01', kind: 'brc39-recipient-file', direction: 'decrypt', randomized,
      description: 'Handover whose BRC-78 wrapped key was assembled from BRC-100 encrypt (protocol [2, "message encryption"]), with no raw key access.',
      input: { importer: 'accountB', file: file.toString('hex') },
      expected: { plaintext: hex(plaintext), plaintextSha256: BRC38_SHA256, innerFormat: 0x26, wrappedKeyLength: 182, sender: pub('accountA'), recipient: pub('accountB') } })
  }

  const base = files.handover
  const L = 182, nonceAt = 35 + L, payloadAt = nonceAt + 32
  // Bytes that differ between generations: the BRC-78 wrapped key (random key ID and IV) and
  // the GCM tag (its AAD contains the wrapped key). An edit that copies such a byte is itself
  // decrypt-direction.
  const randomRegion = offset => (offset >= 35 && offset < 35 + L) || offset >= base.length - 16
  const edit = (description, edits, error, stage, importer = 'accountB', requirement = 'B39R-02') => {
    const randomized = ['input.base', ...edits.flatMap((e, i) => e.derived ? [`input.edits[${i}].value`] : [])]
    const plain = edits.map(({ offset, value }) => ({ offset, value }))
    return add({ requirement, kind: 'brc39-recipient-file', direction: 'decrypt', randomized, description,
      input: { importer, base: 'VC-B39R-001', edits: plain }, expectedError: error, expectedStage: stage })
  }
  const byte = (offset, value, derived = false) => [{ offset, value, derived }]
  const xor = (offset, mask = 0x01) => byte(offset, (base[offset] ^ mask).toString(16).padStart(2, '0'), randomRegion(offset))

  edit('Refused: magic "WDAX".', byte(3, '58'), 'ERR_MAGIC', 'header')
  edit('Refused: Format Version 0x01 with protector 0x02 (the BRC-39 v1 refusal, unchanged).', byte(4, '01'), 'ERR_FORMAT_VERSION', 'header')
  edit('Refused: Format Version 0x03.', byte(4, '03'), 'ERR_FORMAT_VERSION', 'header')
  edit('Refused: protector type 0x01 under Format Version 0x02.', byte(5, '01'), 'ERR_PROTECTOR_TYPE', 'header')
  edit('Refused: protector type 0x03.', byte(5, '03'), 'ERR_PROTECTOR_TYPE', 'header')
  edit('Refused: unknown inner format 0x27.', byte(6, '27'), 'ERR_INNER_FORMAT', 'header')
  edit('Refused: KDF type 0x01 (Argon2id) with protector 0x02.', byte(7, '01'), 'ERR_KDF_TYPE', 'header')
  edit('Refused: flags 0x01.', byte(8, '01'), 'ERR_FLAGS', 'header')
  edit('Refused: salt length 32.', byte(9, '20'), 'ERR_SALT_LENGTH', 'header')
  edit('Refused: nonce length 12.', byte(10, '0c'), 'ERR_NONCE_LENGTH', 'header')
  edit('Refused: Argon2id iterations 7.', byte(11, '00000007'), 'ERR_ARGON2_FIELDS', 'header')
  edit('Refused: Argon2id memory 131072 KiB.', byte(15, '00020000'), 'ERR_ARGON2_FIELDS', 'header')
  edit('Refused: Argon2id parallelism 1.', byte(19, '01'), 'ERR_ARGON2_FIELDS', 'header')
  edit('Refused: Argon2id hash length 32.', byte(20, '20'), 'ERR_ARGON2_FIELDS', 'header')
  edit('Refused: first reserved byte 0x01.', byte(21, '01'), 'ERR_RESERVED', 'header')
  edit('Refused: last reserved byte 0x01.', byte(32, '01'), 'ERR_RESERVED', 'header')
  edit('Refused: wrapped key length 0.', byte(33, '0000'), 'ERR_WRAPPED_KEY_LENGTH', 'header')
  edit('Refused: wrapped key length 1025.', byte(33, '0401'), 'ERR_WRAPPED_KEY_LENGTH', 'header')
  edit('Refused: BRC-78 version byte altered inside the wrapped key.', byte(35, '43'), 'ERR_WRAPPED_KEY_FORMAT', 'header')
  edit('Refused before unwrapping: a header defect (flags 0x01) wins over a wrong importer.', byte(8, '01'), 'ERR_FLAGS', 'header', 'partyM')
  edit('Refused: imported by account A, the sender; the BRC-78 recipient is not the importer identity key.', [], 'ERR_RECIPIENT', 'recipient', 'accountA')
  edit('Refused: imported by party M, which is not the BRC-78 recipient.', [], 'ERR_RECIPIENT', 'recipient', 'partyM')
  edit('Refused: wrapped key length 183, one byte more than the BRC-78 message.', byte(33, '00b7'), 'ERR_UNWRAP', 'unwrap')
  edit('Refused: one byte of the BRC-78 key ID flipped.', xor(35 + 70 + 3), 'ERR_UNWRAP', 'unwrap')
  edit('Refused: the BRC-78 sender key replaced by party M\'s key.', byte(35 + 4, pub('partyM')), 'ERR_UNWRAP', 'unwrap')
  edit('Refused: one nonce byte flipped (GCM tag fails).', xor(nonceAt), 'ERR_DECRYPT', 'decrypt')
  edit('Refused: the first ciphertext byte flipped.', xor(payloadAt), 'ERR_DECRYPT', 'decrypt')
  edit('Refused: the last tag byte flipped.', xor(base.length - 1), 'ERR_DECRYPT', 'decrypt')

  // The wrapped key replaced by a fresh BRC-78 wrap of the same K: unwrapping succeeds, but the
  // header is the AAD, so content authentication fails.
  const rewrapped = await wrapWithSdk('vc-b39r/handover/rewrapped-key', fixed('content key handover'), 'accountA', 'accountB')
  assert(rewrapped.length === 364 && rewrapped !== hex(base.subarray(35, 35 + L)), 'fresh wrap of the same K')
  assert(hex(EncryptedMessage.decrypt(fromHex(rewrapped), PrivateKey.fromHex(priv('accountB')))) === hex(fixed('content key handover')), 'rewrap unwraps to K')
  await rejects(openFile(Buffer.concat([base.subarray(0, 35), Buffer.from(rewrapped, 'hex'), base.subarray(35 + L)]), 'accountB'), 'swapped wrapped key')
  edit('Refused: the Wrapped Key swapped for a fresh BRC-78 wrap of the same K. Unwrapping succeeds; the header AAD makes GCM fail.', byte(35, rewrapped, true), 'ERR_DECRYPT', 'decrypt')

  const truncated = (description, length, error, stage) => add({ requirement: 'B39R-02', kind: 'brc39-recipient-file', direction: 'decrypt', randomized: ['input.base'], description,
    input: { importer: 'accountB', base: 'VC-B39R-001', edits: [], length }, expectedError: error, expectedStage: stage })
  truncated('Refused: 34 bytes, shorter than the fixed header.', 34, 'ERR_FILE_SIZE', 'header')
  truncated('Refused: shorter than header, wrapped key, nonce and tag.', 35 + L + 47, 'ERR_FILE_SIZE', 'header')
  truncated('Refused: the final byte removed (GCM tag fails).', base.length - 1, 'ERR_DECRYPT', 'decrypt')

  // Separately written files for the unwrap and inner-format refusals.
  {
    const shortKey = fixed('content key 31').slice(0, 31), nonce = fixed('nonce 31')
    const wrappedKey = Buffer.from(await wrapWithSdk('vc-b39r/short-key/wrapped-key', shortKey, 'accountA', 'accountB'), 'hex')
    assert(wrappedKey.length === 181, 'BRC-78 of a 31-byte K is 181 bytes')
    const aad = Buffer.concat([headerBytes({ wrappedKeyLength: 181 }), wrappedKey])
    const file = Buffer.concat([aad, Buffer.from(nonce), Buffer.from(fixed('payload 31')), Buffer.alloc(16)])
    add({ requirement: 'B39R-02', kind: 'brc39-recipient-file', direction: 'decrypt', randomized, description: 'Refused: the wrapped content key is 31 bytes, not 32.',
      input: { importer: 'accountB', file: file.toString('hex') }, expectedError: 'ERR_CONTENT_KEY_LENGTH', expectedStage: 'unwrap' })
  }
  {
    const contentKey = fixed('content key inner'), nonce = fixed('nonce inner')
    const wrappedKey = Buffer.from(await wrapWithSdk('vc-b39r/inner/wrapped-key', contentKey, 'accountA', 'accountB'), 'hex')
    const inner = utf8('{"brc":39,"formatVersion":1,"note":"LAB_SELF_TEST_ONLY not a BRC-38 document"}')
    const file = buildFile({ wrappedKey, contentKey, nonce, plaintext: inner })
    assert(hex(await openFile(file, 'accountB')) === hex(inner), 'inner-format file decrypts')
    add({ requirement: 'B39R-01', kind: 'brc39-recipient-file', direction: 'decrypt', randomized, description: 'Refused after decryption: inner format 0x26 labels a payload that is not a BRC-38 document.',
      input: { importer: 'accountB', file: file.toString('hex') }, expectedError: 'ERR_INNER_PAYLOAD', expectedStage: 'inner' })
  }

  return {
    schema: SCHEMA, suite: 'VC-B39R', claim: CLAIM, status: STATUS,
    title: 'BRC-39 recipient protector (protector type 0x02) files and refusals',
    requirements: ['B39R-01', 'B39R-02'],
    citations: [cite('b39rDraft', '§1, §3'), cite('program', 'requirements B39R-01, B39R-02'),
      citeBrc(39, '§5 File Layout, §6, §11, §14.3'), citeBrc(78, 'Specification'), citeBrc(2, 'Specification'), citeBrc(42, 'Specification')],
    decisions: DECISIONS,
    layout: LAYOUT,
    testKeys: pick('accountA', 'accountB', 'partyM'),
    generator: generatorRecord({ '@bsv/sdk': '4.0.1', '@noble/ciphers': '2.4.0' }),
    oracles: [
      { path: 'src/portability/brc39-recipient.mjs', basis: 'node:crypto (ECDH secp256k1, HMAC-SHA-256, AES-256-GCM) and BigInt point arithmetic; independent of src/portability/brc39.mjs' },
      { path: 'components/sdx/b39r/suites/vc-b39r.mjs', basis: '@bsv/sdk 4.0.1 EncryptedMessage and BRC-100 encrypt/decrypt (pure TypeScript paths); @noble/ciphers 2.4.0 AES-256-GCM with AAD' }
    ],
    cases
  }
}
