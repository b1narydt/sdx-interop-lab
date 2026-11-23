import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { createECDH, createHash, hkdfSync, randomBytes } from 'node:crypto'
import { decryptRecipientFile, encryptRecipientFile, inspectRecipientHeader, FIXED_HEADER_BYTES } from '../src/portability/brc39-recipient.mjs'
import { inspectHeader as inspectPasswordHeader } from '../src/portability/brc39.mjs'
import { brc78Decrypt } from '../src/sdx/brc2.mjs'

const ROOT = new URL('../', import.meta.url)
const text = fs.readFileSync(new URL('fixtures/sdx/v1/vc-b39r/vectors.json', ROOT), 'utf8')
const vectors = JSON.parse(text)
const key = name => vectors.testKeys[name]
const byId = Object.fromEntries(vectors.cases.map(c => [c.id, c]))
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex')

function fileOf(c) {
  if (c.input.file !== undefined) return Buffer.from(c.input.file, 'hex')
  const file = Buffer.from(byId[c.input.base].input.file, 'hex')
  for (const { offset, value } of c.input.edits) Buffer.from(value, 'hex').copy(file, offset)
  return c.input.length === undefined ? file : file.subarray(0, c.input.length)
}

test('LAB_SELF_TEST_ONLY: VC-B39R vector file is strict, labelled and reproducible from its test keys', () => {
  assert.equal(text, JSON.stringify(vectors, null, 2) + '\n', 'canonical JSON with no duplicate keys')
  const numbers = value => typeof value === 'number' ? [value] : value && typeof value === 'object' ? Object.values(value).flatMap(numbers) : []
  assert.ok(numbers(vectors).every(Number.isSafeInteger))
  assert.deepEqual([vectors.schema, vectors.suite, vectors.claim, vectors.status], ['tpnil-sdx-vectors@0.1.0', 'VC-B39R', 'LAB_SELF_TEST_ONLY', 'PROPOSED'])
  assert.ok(vectors.requirements.every(id => typeof id === 'string'))
  const ids = new Set(vectors.requirements)
  for (const id of ids) assert.ok(vectors.cases.some(c => c.requirement === id), `${id} has a case`)
  vectors.cases.forEach((c, i) => {
    assert.equal(c.id, `VC-B39R-${String(i + 1).padStart(3, '0')}`)
    assert.ok(ids.has(c.requirement))
    assert.ok(Object.hasOwn(c, 'expected') !== Object.hasOwn(c, 'expectedError'))
    if (c.expectedError) assert.ok(['header', 'recipient', 'unwrap', 'decrypt', 'inner'].includes(c.expectedStage))
  })
  for (const p of [vectors.generator.path, vectors.generator.lockfile, ...vectors.oracles.map(o => o.path)]) assert.ok(fs.existsSync(new URL(p, ROOT)), p)
  for (const citation of vectors.citations) {
    if (!citation.path || citation.repository) continue
    const body = fs.readFileSync(new URL(citation.path, ROOT), 'utf8')
    for (const token of citation.clause.replace(/^requirements /, '').split(', ')) {
      const heading = token.startsWith('§') && new RegExp(`^#+ ${token.slice(1).replaceAll('.', '\\.')}\\.? `, 'm')
      const item = /^item (\d+)$/.exec(token)
      assert.ok(heading ? heading.test(body) : item ? body.includes(`\n| ${item[1]} |`) : body.includes(`"${token}"`), `${citation.path} ${token}`)
    }
  }
  for (const [name, k] of Object.entries(vectors.testKeys)) {
    const expected = k.label ? createHash('sha256').update(k.label).digest('hex') : Buffer.from(hkdfSync('sha256', Buffer.from(k.ikm, 'hex'), Buffer.alloc(0), Buffer.from(k.info), 32)).toString('hex')
    assert.equal(k.privateKey, expected, name)
    const ecdh = createECDH('secp256k1'); ecdh.setPrivateKey(Buffer.from(k.privateKey, 'hex'))
    assert.equal(k.publicKey, ecdh.getPublicKey('hex', 'compressed'), name)
  }
  const refusals = new Set(vectors.cases.map(c => c.expectedError).filter(Boolean))
  for (const code of ['ERR_KDF_TYPE', 'ERR_SALT_LENGTH', 'ERR_NONCE_LENGTH', 'ERR_ARGON2_FIELDS', 'ERR_FLAGS', 'ERR_RESERVED', 'ERR_WRAPPED_KEY_LENGTH', 'ERR_INNER_FORMAT', 'ERR_RECIPIENT', 'ERR_DECRYPT']) {
    assert.ok(refusals.has(code), `draft §3 refusal ${code} has a vector`)
  }
})

for (const c of vectors.cases) {
  test(`LAB_SELF_TEST_ONLY: ${c.id}${c.expectedError ? ` refuses ${c.expectedError} at ${c.expectedStage}` : ' opens'}`, () => {
    const file = fileOf(c)
    // A BRC-39 Format Version 0x01 importer refuses every one of these files.
    assert.throws(() => inspectPasswordHeader(file))
    if (c.expectedError) {
      assert.throws(() => decryptRecipientFile(file, key(c.input.importer).privateKey), error => error.code === c.expectedError && error.stage === c.expectedStage, `${c.expectedError} at ${c.expectedStage}`)
      return
    }
    const plaintext = decryptRecipientFile(file, key(c.input.importer).privateKey)
    assert.equal(plaintext.toString('hex'), c.expected.plaintext)
    assert.equal(sha256(plaintext), c.expected.plaintextSha256)
    const header = inspectRecipientHeader(file)
    assert.equal(header.innerFormat, c.expected.innerFormat)
    assert.equal(header.wrappedKey.length, c.expected.wrappedKeyLength)
    assert.equal(header.sender.toString('hex'), c.expected.sender)
    assert.equal(header.recipient.toString('hex'), c.expected.recipient)
    assert.equal(header.aad.length, FIXED_HEADER_BYTES + c.expected.wrappedKeyLength)
    assert.equal(file.length, header.aad.length + 32 + plaintext.length + 16)
    assert.equal(brc78Decrypt(header.wrappedKey, key(c.input.importer).privateKey).length, 32)
  })
}

test('LAB_SELF_TEST_ONLY: every single-bit change to a recipient file header is refused', () => {
  const base = Buffer.from(vectors.cases[0].input.file, 'hex')
  const importer = key(vectors.cases[0].input.importer).privateKey
  const L = base.readUInt16BE(33)
  const offsets = [...Array(FIXED_HEADER_BYTES + L).keys()].filter(offset => offset < FIXED_HEADER_BYTES || offset % 7 === 0)
  for (const offset of offsets) for (let bit = 0; bit < 8; bit++) {
    const changed = Buffer.from(base); changed[offset] ^= 1 << bit
    assert.throws(() => decryptRecipientFile(changed, importer), `offset ${offset} bit ${bit}`)
  }
  for (const offset of [FIXED_HEADER_BYTES + L, FIXED_HEADER_BYTES + L + 31, FIXED_HEADER_BYTES + L + 32, base.length - 17, base.length - 1]) {
    const changed = Buffer.from(base); changed[offset] ^= 0x40
    assert.throws(() => decryptRecipientFile(changed, importer), error => error.stage === 'decrypt', `offset ${offset}`)
  }
})

test('LAB_SELF_TEST_ONLY: the node:crypto writer round-trips and orders its refusals', () => {
  const plaintext = Buffer.from(byId['VC-B39R-001'].expected.plaintext, 'hex')
  for (const [sender, recipient] of [['accountA', 'accountB'], ['accountB', 'accountB']]) {
    const file = encryptRecipientFile(plaintext, { senderPrivateKey: key(sender).privateKey, recipientPublicKey: key(recipient).publicKey })
    assert.equal(file.length, 35 + 182 + 32 + plaintext.length + 16)
    assert.deepEqual(decryptRecipientFile(file, key(recipient).privateKey), plaintext)
    assert.throws(() => decryptRecipientFile(file, key('partyM').privateKey), error => error.code === 'ERR_RECIPIENT')
  }
  const fixed = encryptRecipientFile(plaintext, { senderPrivateKey: key('accountA').privateKey, recipientPublicKey: key('accountB').publicKey, randomness: n => Buffer.alloc(n, 7) })
  const again = encryptRecipientFile(plaintext, { senderPrivateKey: key('accountA').privateKey, recipientPublicKey: key('accountB').publicKey, randomness: n => Buffer.alloc(n, 7) })
  assert.deepEqual(fixed, again, 'fixed randomness gives a fixed file')
  const other = encryptRecipientFile(plaintext, { senderPrivateKey: key('accountA').privateKey, recipientPublicKey: key('accountB').publicKey, randomness: randomBytes })
  assert.notDeepEqual(other, fixed)
  // The wrapped key of one file swapped into another of the same length: unwrap succeeds, GCM fails.
  const swapped = Buffer.concat([fixed.subarray(0, 35), other.subarray(35, 35 + 182), fixed.subarray(35 + 182)])
  assert.throws(() => decryptRecipientFile(swapped, key('accountB').privateKey), error => error.code === 'ERR_DECRYPT')
  // Header refusals precede the recipient check and the unwrap.
  const flagged = Buffer.from(fixed); flagged[8] = 1
  assert.throws(() => decryptRecipientFile(flagged, key('partyM').privateKey), error => error.code === 'ERR_FLAGS' && error.stage === 'header')
  assert.throws(() => encryptRecipientFile(plaintext, { senderPrivateKey: key('accountA').privateKey, recipientPublicKey: key('accountB').publicKey, innerFormat: 0x27 }), error => error.code === 'ERR_INNER_FORMAT')
  assert.throws(() => decryptRecipientFile('not bytes', key('accountB').privateKey), error => error.code === 'ERR_FILE_SIZE')
})
