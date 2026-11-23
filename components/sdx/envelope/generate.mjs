#!/usr/bin/env node
// LAB_SELF_TEST_ONLY generator for the VA-ENV and VA-SIG vector suites: SDX v0.1 record
// envelopes and record signatures under the laboratory deployment profile.
//
// Libraries: @noble/curves, @noble/hashes and @noble/ciphers (P-256 and secp256k1, HKDF,
// HMAC, PBKDF2, AES-GCM, AES key wrap, RFC 6979 ES256), cborg 6.2.1 (deterministic CBOR),
// LZMA-JS 2.3.2 (npm `lzma`, the ENV §9 compression) and jose 6.2.17, a JOSE implementation,
// which must open every JWE of every known-answer record through every recipient and verify
// every known-answer signature. The checkers (src/sdx/env.mjs with src/sdx/cbor-det.mjs,
// src/sdx/ec-p256.mjs and src/sdx/lzma.mjs; test/sdx_env.py) import none of them.
//
//   node generate.mjs --write   regenerate fixtures/sdx/v1/va-env and va-sig, and frozen.json
//   node generate.mjs --check   regenerate in memory and require identical bytes
//
// Random values (content-encryption keys, IVs, ephemeral keys, key-wrap IVs and the random
// part of each record identifier) were drawn once from node:crypto and are frozen in
// frozen.json. Signatures use RFC 6979 nonces, so every output is reproducible.
import fs from 'node:fs'
import path from 'node:path'
import { randomBytes } from 'node:crypto'
import { sha256 } from '@noble/hashes/sha2.js'
import { IDENTITIES, PROFILE, PROFILE_BYTES, PROFILE_PATH, REPO, HERE, TM, fail, hex, ulid, unhex, utf8, signId } from './lib/lab.mjs'
import { calculateSecrets, p256Public, p256Self, split, N } from './lib/keys.mjs'
import { WriterRefusal, privateTuple, writeRecord } from './lib/envelope.mjs'
import { encode } from './lib/cbor.mjs'
import { joseOpens, joseVerifies, unb64u } from './lib/jwe.mjs'
import { vaEnv } from './suites/va-env.mjs'
import { vaSig } from './suites/va-sig.mjs'
import * as checker from '../../../src/sdx/env.mjs'

const mode = process.argv[2]
if (process.argv.length !== 3 || !['--write', '--check'].includes(mode)) {
  console.error('usage: node generate.mjs --write | --check')
  process.exit(2)
}
const OUTPUTS = { env: 'fixtures/sdx/v1/va-env/vectors.json', sig: 'fixtures/sdx/v1/va-sig/vectors.json' }
const FROZEN_FILE = path.join(HERE, 'frozen.json')
const FROZEN_NOTE = 'LAB_SELF_TEST_ONLY. The random inputs of every VA-ENV and VA-SIG record: content-encryption keys, IVs, ephemeral private keys and key-wrap IVs per JWE, and the 80 random bits of each record identifier. Drawn once from node:crypto randomBytes and frozen; a writer given a case\'s `random` member reproduces its key-management bytes.'
const stored = fs.existsSync(FROZEN_FILE) ? JSON.parse(fs.readFileSync(FROZEN_FILE, 'utf8')) : { records: {} }
const frozen = { records: { ...stored.records }, used: new Set(), changed: false }

// ---- identities -----------------------------------------------------------------------------
const LETTER = { W: 'writer', A: 'readerA', B: 'readerB', O: 'outsider' }
const ID = Object.fromEntries(Object.entries(LETTER).map(([k, name]) => {
  const who = IDENTITIES[name]
  const keys = split(who.rootIkm)
  return [k, { ...who, keys, R: hex(keys.R) }]
}))
const W = ID.W
const labelKey = label => { const d = sha256(utf8(`TPNIL SDX v1 LAB_SELF_TEST_ONLY public test key: ${label}`)); if (BigInt('0x' + hex(d)) >= N) fail(label); return { d, pub: p256Public(d) } }
const OTHER_AID = ulid(TM, sha256(utf8('TPNIL SDX v1 LAB_SELF_TEST_ONLY other record identifier')).subarray(0, 10))
const EXTRA = {
  strayKey: labelKey('stray signer'),
  actor: labelKey('delegate actor'),
  otherKey: labelKey('other key').pub,
  otherRecordKey: p256Self(W.keys.p256Seed, signId(W.acct, W.rid, OTHER_AID)),
  delId: sha256(utf8('TPNIL SDX v1 LAB_SELF_TEST_ONLY grant 1')).subarray(0, 16),
  delId2: sha256(utf8('TPNIL SDX v1 LAB_SELF_TEST_ONLY grant 2')).subarray(0, 16)
}

// ---- frozen randomness ------------------------------------------------------------------------
function frozenFor(name, shape) {
  const want = JSON.stringify(shape)
  let entry = frozen.records[name]
  if (!entry || entry.shape !== want) {
    if (mode !== '--write') fail(`frozen randomness for ${name} is missing or was drawn for another shape; run --write`)
    const jwe = s => ({ cek: hex(randomBytes(32)), iv: hex(randomBytes(12)), epk: Array.from({ length: s.epk }, () => { for (;;) { const k = randomBytes(32); if (BigInt('0x' + hex(k)) > 0n && BigInt('0x' + hex(k)) < N) return hex(k) } }), ...(s.kw ? { kwiv: hex(randomBytes(12)) } : {}) })
    entry = { shape: want, aid: hex(randomBytes(10)), ...(shape.outer ? { outer: jwe(shape.outer) } : {}), fields: Object.fromEntries(Object.entries(shape.fields ?? {}).map(([n, s]) => [n, jwe(s)])) }
    frozen.records[name] = entry
    frozen.changed = true
  }
  frozen.used.add(name)
  return entry
}

// ---- the kit the suites build with --------------------------------------------------------------
const cases = []
let counter = 0
const canon = value => {
  if (value === null || typeof value !== 'object') return value
  if (Array.isArray(value)) return value.map(canon)
  return Object.fromEntries(Object.keys(value).sort().map(k => [k, canon(value[k])]))
}
const kit = {
  otherAid: OTHER_AID,
  count: () => ++counter,
  label: (who, as) => ({ W: 'the writer, holding only its root', A: 'reader A', B: 'reader B', O: 'outsider O' })[who] + (as === 'writer' && who !== 'W' ? ' (as writer)' : ''),
  add(c) {
    const suite = c.suite ?? kit.suite
    const list = cases.filter(x => x.suite === suite)
    const id = `${suite}-${String(list.length + 1).padStart(3, '0')}`
    cases.push({ suite, id, ...c })
    return id
  },
  record(name, spec, opts = {}) {
    const fields = spec.fields.map(f => ({ ...f }))
    const fieldRecipients = Object.fromEntries(Object.entries(spec.fieldRecipients ?? {}).map(([n, list]) => [n, list.map(w => ID[w].R)]))
    const shape = {
      outer: { epk: 1 + spec.auditRecipients.length, kw: fields.some(f => f.sn === 'pr' && f.cv === true) },
      fields: Object.fromEntries(fields.filter(f => f.sn === 'pr' && 'value' in f).map(f => [f.n.normalize('NFC'), { epk: (f.blind === true ? 0 : 1) + (spec.fieldRecipients?.[f.n] ?? []).length, kw: f.cv === true }]))
    }
    const entry = frozenFor(name, opts.noRandom ? { fields: {} } : shape)
    return {
      op: 'write',
      profile: PROFILE_PATH,
      writer: { acct: W.acct, rid: W.rid, ep: W.ep, rootIkm: hex(W.rootIkm) },
      record: { aid: ulid(TM, unhex(entry.aid)), f: spec.f, mv: spec.mv, tm: TM, fields },
      auditRecipients: spec.auditRecipients.map(w => ID[w].R),
      fieldRecipients,
      ...(opts.noRandom ? {} : { random: { outer: entry.outer, fields: entry.fields } })
    }
  },
  build(req, hooks = {}) {
    return writeRecord(req, { ...hooks, extra: EXTRA })
  },
  readReq(who, as, envelope) {
    const r = ID[who]
    return { op: 'read', profile: PROFILE_PATH, reader: { acct: r.acct, rid: r.rid, ep: r.ep, rootIkm: hex(r.rootIkm) }, as, writer: { acct: W.acct, rid: W.rid, R: W.R }, envelope }
  },
  // The projection a reader must reach, computed from the request: who holds which slot.
  expectRead(req, res, who) {
    const fields = req.record.fields.map(f => ({ ...f, n: f.n.normalize('NFC') }))
    const root = ID[who].R
    const recipientsOf = n => Object.entries(req.fieldRecipients).find(([k]) => k.normalize('NFC') === n)?.[1] ?? []
    const plainField = f => ('value' in f ? { n: f.n, sn: f.sn, state: 'value', value: canon(f.value) } : { n: f.n, sn: f.sn, state: 'unset' })
    if (who !== 'W' && !req.auditRecipients.includes(root)) {
      return { tier: 'nothing', verdict: 'accepted', aid: req.record.aid, fields: fields.filter(f => f.sn === 'pu').map(plainField) }
    }
    const project = f => {
      if (f.sn !== 'pr' || !('value' in f)) return plainField(f)
      const reads = who === 'W' ? f.blind !== true : recipientsOf(f.n).includes(root)
      if (!reads) return { n: f.n, sn: f.sn, state: 'redacted' }
      const out = { n: f.n, sn: f.sn, state: 'value', value: canon(f.value) }
      for (const k of ['filename', 'mediaType', 'meta']) if (k in f && f[k] !== null) out[k] = canon(f[k])
      return out
    }
    return {
      tier: 'audit', verdict: 'accepted', aid: req.record.aid,
      hdr: { f: req.record.f, mv: req.record.mv, ep: req.writer.ep, tm: req.record.tm, pks: 'root', pk: res.derived.signing, dref: [] },
      fields: fields.map(project),
      signature: { kid: res.derived.signing, shape: 'current' }
    }
  },
  refused: (cls, detail) => ({ verdict: 'refused', refusal: { class: cls, detail } }),
  deterministic(req, res) {
    return {
      signingKid: res.derived.signing,
      outer: { iv: res.outer.iv, recipientKids: res.derived.outer.map(x => x.kid), encryptedKeys: res.outer.recipients.map(r => r.encrypted_key) },
      fields: Object.fromEntries(Object.entries(res.fieldParts).map(([n, p]) => [n, { iv: p.jwe.iv, recipientKids: (res.derived.fields[n] ?? []).map(x => x.kid), encryptedKeys: p.jwe.recipients.map(r => r.encrypted_key) }]))
    }
  }
}

// A JOSE implementation must open every JWE of a known-answer record through every recipient
// and verify its signature (ENV §16).
async function joseWitness(req, res) {
  const writer = split(unhex(req.writer.rootIkm))
  const keyFor = (who, id) => {
    if (who === 'self') return p256Self(writer.p256Seed, id).d
    const holder = Object.values(ID).find(x => x.R === who)
    const { p256Own } = keysModule
    return p256Own(holder.keys.p256Seed, writer.R, id).d
  }
  const { outerId, fieldId } = labModule
  const oid = outerId(req.writer.acct, req.writer.rid, req.record.aid)
  let i = 0
  for (const r of res.outer.recipients) {
    if (r.header.alg === 'A256GCMKW') await joseOpens(res.outer, i, res.recordSecrets.s1, res.auditLayer)
    else await joseOpens(res.outer, i, keyFor(res.derived.outer.find(x => x.kid === r.header.kid).who, oid), res.auditLayer)
    i++
  }
  for (const [n, part] of Object.entries(res.fieldParts)) {
    const fid = fieldId(req.writer.acct, req.writer.rid, req.record.aid, n)
    let j = 0
    for (const r of part.jwe.recipients) {
      if (r.header.alg === 'A256GCMKW') await joseOpens(part.jwe, j, part.secrets.cek, part.compressed)
      else await joseOpens(part.jwe, j, keyFor(res.derived.fields[n].find(x => x.kid === r.header.kid).who, fid), part.compressed)
      j++
    }
    // The field plaintext is the deterministic encoding of the tuple (ENV §9).
    const field = req.record.fields.find(f => f.n.normalize('NFC') === n)
    if (hex(part.plaintext) !== hex(encode(privateTuple(field)))) fail(`field ${n} plaintext`)
  }
  if (!(await joseVerifies(res.protectedB64, Buffer.from(res.signedBytes).toString('base64url'), res.signature, unhex(res.derived.signing)))) fail('jose rejects a known-answer signature')
}
const keysModule = await import('./lib/keys.mjs')
const labModule = await import('./lib/lab.mjs')

// ---- build ------------------------------------------------------------------------------------
kit.suite = 'VA-ENV'
vaEnv(kit)
kit.suite = 'VA-SIG'
vaSig(kit)

// Every known-answer record through jose; every case through the Node checker, including the
// laboratory's refusal detail, which tells that the refusal came from the intended rule.
for (const c of cases.filter(x => x.direction === 'write' && x.expect.envelope)) {
  await joseWitness(c.request, kit.build(c.request))
}
for (const c of cases) {
  const result = checker.runCase(PROFILE, c)
  if (!result.ok) fail(`${c.id} (${c.title}): ${result.failures.join('; ')}`)
  if (c.expect.verdict === 'refused' && result.actual.refusal.detail !== c.expect.refusal.detail) fail(`${c.id}: checker refused with ${result.actual.refusal.detail}, expected ${c.expect.refusal.detail}`)
}

// ---- write-check qualification ------------------------------------------------------------------
// Writer outputs that break one rule each, for the same requests and frozen values as a
// known-answer case: the write checks must fail exactly where stated, so they are not vacuous.
const { compressWithMarker } = await import('./lib/lzma.mjs')
const { encodeSuperseded } = await import('./lib/cbor.mjs')
const kat = prefix => cases.find(c => c.direction === 'write' && c.expect.envelope && c.title.startsWith(prefix))
const qualification = []
function qualify(suite, prefix, title, hooks, failing) {
  const c = kat(prefix)
  const res = kit.build(c.request, hooks)
  const results = checker.checkWrite(PROFILE, c, hex(res.envelope))
  const got = results.filter(r => !r.ok).map(r => r.check).sort()
  if (got.join() !== [...failing].sort().join()) fail(`write-check qualification "${title}": failing ${got.join()} expected ${failing.join()}`)
  qualification.push({ suite, writeCase: c.id, title, envelope: hex(res.envelope), failingChecks: [...failing].sort() })
}
qualify('VA-ENV', 'Known-answer record R2', 'The single recipient\'s ephemeral key written into the outer protected header, as a stock JOSE library does for one recipient', { outerEpkInProtected: true }, ['outer-protected-members', 'outer-epk-per-recipient'])
qualify('VA-ENV', 'Known-answer record R1', 'Private values compressed with the end-of-stream marker written', { fieldCompressed: (c, n, plaintext) => compressWithMarker(plaintext) }, ['field-kwh-lzma-no-marker', 'field-site-lzma-no-marker'])
qualify('VA-ENV', 'Known-answer record R1', 'The writer self-recipient left off the outer wrap', { outer: o => ({ ...o, recipients: o.recipients.slice(1) }) }, ['outer-self-recipient', 'outer-recipient-kids', 'outer-recipient-order'])
qualify('VA-ENV', 'Known-answer record R1', 'The external recipient of `kwh` placed before the writer self-recipient', { fieldJwe: (j, n) => (n === 'kwh' ? { ...j, recipients: [...j.recipients].reverse() } : j) }, ['field-kwh-kids', 'field-kwh-encrypted-keys'])
qualify('VA-SIG', 'Known-answer signed record', 'Signed by a key not derived from the writer\'s root, named by `hdr.pk` and `kid`', { signerKey: (d, ctx) => ctx.strayKey.d, sigKid: (k, ctx) => hex(ctx.strayKey.pub), hdr: (h, ctx) => ({ ...h, pk: ctx.strayKey.pub }) }, ['hdr-signer', 'signature-kid'])
qualify('VA-SIG', 'Known-answer signed record', 'Signed over the superseded integer shape, which a writer no longer emits', { signedBytes: (b, x) => encodeSuperseded(x) }, ['signature-verifies-current'])

// ---- documents ---------------------------------------------------------------------------------
const PROFILE_REF = { id: PROFILE.profile, path: PROFILE_PATH, sha256: hex(sha256(PROFILE_BYTES)) }
const IDENTITY_TABLE = Object.fromEntries(Object.entries(ID).map(([k, x]) => [k, { role: { W: 'writer', A: 'reader A', B: 'reader B', O: 'outsider' }[k], acct: x.acct, rid: x.rid, ep: x.ep, rootIkm: hex(x.rootIkm), R: x.R, derivedFrom: `SHA-512("TPNIL SDX v1 LAB_SELF_TEST_ONLY public test root: ${x.name}")` }]))
const COMMON = {
  schema: 'tpnil-sdx-vectors@0.1.0',
  claim: 'LAB_SELF_TEST_ONLY',
  status: 'BASELINE-v0.1',
  profile: PROFILE_REF,
  driverContract: 'programs/proposals/sdx-data-sharing/0.1.0/driver-contract.md',
  testIdentities: { warning: 'Public LAB_SELF_TEST_ONLY roots. They protect nothing and control no value.', identities: IDENTITY_TABLE, actorKey: { publicKey: hex(EXTRA.actor.pub), privateKey: hex(EXTRA.actor.d), derivedFrom: 'SHA-256("TPNIL SDX v1 LAB_SELF_TEST_ONLY public test key: delegate actor")', use: 'The raw P-256 key a grant pins for the delegate-signed records (KEYS §2.3, §2.14.1)' }, delIds: [hex(EXTRA.delId), hex(EXTRA.delId2)], otherAid: OTHER_AID },
  outcomeTags: {
    tag: '`required`: the expected outcome follows from the cited clauses and can fail an implementation. `labChoice`: the laboratory\'s outcome where the text leaves it open; a differing implementation is reported and does not fail.',
    classTag: 'On a refusal, the verdict is compared under `tag`; the refusal class is compared only when `classTag` is `required` (the default). The laboratory refusal classes are `format`, `structure`, `integrity`, `signature`, `decode`, `root-pk-mismatch` and `delegation-invalid`; ENV names `integrity`, `signature` and `decode` refusals, and KEYS §2.7 names the last two. `detail` is the laboratory\'s label and is never compared for an implementation.'
  },
  generator: {
    component: 'components/sdx/envelope',
    command: 'npm run generate --prefix components/sdx/envelope',
    check: 'npm run check --prefix components/sdx/envelope',
    dependencies: JSON.parse(fs.readFileSync(path.join(HERE, 'package.json'), 'utf8')).dependencies,
    lockfile: 'components/sdx/envelope/package-lock.json',
    frozen: 'components/sdx/envelope/frozen.json',
    deterministic: 'Fixed public test roots, frozen random values and RFC 6979 low-S ES256 nonces; `node generate.mjs --check` reproduces both files byte for byte.'
  }
}
const ORACLES = {
  generatorWitness: 'jose 6.2.17 opens every JWE of every known-answer record through every recipient (ECDH-ES+A256KW and A256GCMKW) and verifies every known-answer ES256 signature; the generator builds JWEs on @noble primitives from the frozen values.',
  node: { modules: ['src/sdx/env.mjs', 'src/sdx/cbor-det.mjs', 'src/sdx/ec-p256.mjs', 'src/sdx/lzma.mjs'], kind: 'oracle', dependencies: 'Node.js built-ins only', covers: 'Every step of every case: CBOR, the ENV §14 decode flow, the JOSE steps by hand on node:crypto (ECDH, Concat KDF, AES key wrap, AES-GCM, A256GCMKW), ES256 on both candidate shapes, KEYS §1.8.2 derivation, its own LZMA decoder (which also detects an end-of-stream marker) and ENV §4 PBKDF2.', tests: ['test/sdx-env.test.mjs'], agreement: 'The generator declares each expected outcome from the case\'s construction; the checker reproduces every one, including the laboratory refusal detail, or generation stops.' },
  python: { modules: ['test/sdx_env.py', 'test/sdx_ec.py', 'test/sdx_anc.py'], kind: 'oracle', dependencies: 'Python standard library only', covers: 'Every step of every case: CBOR, the decode flow, the JOSE steps by hand (its AES-256, GCM and key unwrap are pure Python in test/sdx_ec.py), ES256 on both candidate shapes, KEYS §1.8.2 derivation, LZMA through the standard library\'s lzma module (FORMAT_ALONE; it cannot tell whether an end-of-stream marker was written, which only the Node oracle checks) and ENV §4 PBKDF2.', tests: ['test/test_sdx_env.py'] }
}

function documentFor(suite, meta) {
  const list = cases.filter(c => c.suite === suite).map(({ suite: _s, ...c }) => c)
  const writeCheckQualification = qualification.filter(q => q.suite === suite).map(({ suite: _s, ...q }) => q)
  return { ...COMMON, suite, ...meta, oracles: ORACLES, writeCheckQualification, caseCount: list.length, cases: list }
}
const docs = {
  env: documentFor('VA-ENV', {
    requirements: ['SDX-A-02', 'SDX-A-03', 'SDX-A-04'],
    citations: ['ENV §2', 'ENV §3', 'ENV §4', 'ENV §5', 'ENV §6', 'ENV §7', 'ENV §8.1', 'ENV §8.6', 'ENV §9', 'ENV §9.1', 'ENV §11', 'ENV §12', 'ENV §13', 'ENV §14', 'ENV §15', 'ENV §16', 'ENV §17.5', 'KEYS §1.4.2', 'KEYS §1.6.2', 'KEYS §1.8.2'].map(clause => ({ path: clause.startsWith('KEYS') ? 'fixtures/sdx/v1/standards/text/keys.md' : 'fixtures/sdx/v1/standards/text/envelope.md', clause })),
    decisions: (await import('./suites/decisions.mjs')).ENV_DECISIONS
  }),
  sig: documentFor('VA-SIG', {
    requirements: ['SDX-A-02'],
    citations: ['ENV §8.2', 'ENV §8.3', 'ENV §8.4', 'ENV §8.5', 'ENV §14', 'ENV §16', 'KEYS §1.8.3', 'KEYS §2.7.1', 'KEYS §2.7.2', 'KEYS §2.14.1'].map(clause => ({ path: clause.startsWith('KEYS') ? 'fixtures/sdx/v1/standards/text/keys.md' : 'fixtures/sdx/v1/standards/text/envelope.md', clause })),
    decisions: (await import('./suites/decisions.mjs')).SIG_DECISIONS
  })
}

const serialise = value => JSON.stringify(value, null, 1) + '\n'
let mismatch = false
for (const [key, rel] of Object.entries(OUTPUTS)) {
  const text = serialise(docs[key])
  const file = path.join(REPO, rel)
  if (mode === '--write') { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, text); console.log(`wrote ${rel} (${docs[key].cases.length} cases)`) }
  else if (!fs.existsSync(file) || fs.readFileSync(file, 'utf8') !== text) { console.error(`${rel} is not current; run --write`); mismatch = true }
  else console.log(`${rel} is current (${docs[key].cases.length} cases)`)
}
const unused = Object.keys(frozen.records).filter(k => !frozen.used.has(k))
if (unused.length) { if (mode !== '--write') { console.error(`frozen.json holds unused entries ${unused.join(', ')}; run --write`); mismatch = true } else { for (const k of unused) delete frozen.records[k]; frozen.changed = true } }
if (frozen.changed) {
  if (mode !== '--write') mismatch = true
  else { fs.writeFileSync(FROZEN_FILE, serialise({ note: FROZEN_NOTE, records: Object.fromEntries(Object.keys(frozen.records).sort().map(k => [k, frozen.records[k]])) })); console.log('wrote components/sdx/envelope/frozen.json') }
}
if (mismatch) process.exit(1)
