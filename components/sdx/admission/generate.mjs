#!/usr/bin/env node
// LAB_SELF_TEST_ONLY generator for VA-ADM: overlay admission and the per-topic index (ANC §10-§12)
// as a laboratory stand-in for SDX's unpublished `overlay-binding` suite. Each case is a sequence
// of driver-contract steps (submit, lookup and an optional fault hook) against a fresh admission
// service and index, with the expected admission and query results.
//
// The records are real SDX v0.1 envelopes taken from the VA-ENV and VA-SIG suite files, carried
// in ANC §2.1 containers under their ANC §3.1 commitment keys. Transactions are synthetic and
// signed; nothing is broadcast. Libraries: @bsv/sdk 4.0.1 (transactions, BRC-42 commitment
// keys, signing, and Spend validation of every input), @noble/curves and @noble/hashes (an
// independent derivation of each commitment key) and cborg 6.2.1 (the gate variants). The
// checkers (src/sdx/adm.mjs with src/sdx/tx.mjs and src/sdx/cbor-det.mjs; test/sdx_adm.py with
// test/sdx_anc.py) import none of them.
//
//   node generate.mjs --write | --check
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { decode as cborDecode, encode as cborEncode, rfc8949EncodeOptions } from 'cborg'
import { KeyDeriver, LockingScript, P2PKH, PrivateKey, Spend, Transaction, UnlockingScript } from '@bsv/sdk'
import { runCase } from '../../../src/sdx/adm.mjs'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const REPO = path.resolve(HERE, '../../..')
const OUTPUT = 'fixtures/sdx/v1/va-adm/vectors.json'
const PROFILE_PATH = 'fixtures/sdx/v1/deployment-profile.json'
const PROFILE_BYTES = fs.readFileSync(path.join(REPO, PROFILE_PATH))
const PROFILE = JSON.parse(PROFILE_BYTES.toString('utf8'))
const mode = process.argv[2]
if (process.argv.length !== 3 || !['--write', '--check'].includes(mode)) { console.error('usage: node generate.mjs --write | --check'); process.exit(2) }
const hex = b => Buffer.from(b).toString('hex')
const unhex = t => Uint8Array.from(Buffer.from(t, 'hex'))
const utf8 = t => new TextEncoder().encode(t)
const fail = m => { throw new Error(`generator self-check failed: ${m}`) }
const read = rel => fs.readFileSync(path.join(REPO, rel))
const ENV_FILE = 'fixtures/sdx/v1/va-env/vectors.json', SIG_FILE = 'fixtures/sdx/v1/va-sig/vectors.json'
const ENV = JSON.parse(read(ENV_FILE)), SIG = JSON.parse(read(SIG_FILE))

// ---- envelopes ----------------------------------------------------------------------------------
const byTitle = (doc, prefix, pick = c => c.expect.envelope ?? c.request.envelope) => {
  const c = doc.cases.find(x => x.title.startsWith(prefix))
  if (!c) fail(`no case "${prefix}"`)
  return { id: c.id, bytes: unhex(pick(c)) }
}
const E = {
  R1: byTitle(ENV, 'Known-answer record R1'),
  R2: byTitle(ENV, 'Known-answer record R2'),
  R4: byTitle(ENV, 'Known-answer record R4'),
  SIG: byTitle(SIG, 'Known-answer signed record'),
  BADSIG: byTitle(SIG, 'A flipped bit in the signature'),
  DELEG: byTitle(SIG, 'A delegate record with an empty'),
  PUBARE: byTitle(ENV, 'A public slot carrying neither a value nor the marker')
}
const W = ENV.testIdentities.identities.W
const decodeEnv = bytes => cborDecode(bytes, { useMaps: false })
const encodeEnv = value => cborEncode(value, rfc8949EncodeOptions)
const aidOf = bytes => { try { return JSON.parse(Buffer.from(decodeEnv(bytes).outer.protected, 'base64url').toString()).aid } catch { return null } }
const variant = fn => { const v = decodeEnv(E.R2.bytes); fn(v); return encodeEnv(v) }

// ---- commitment keys (ANC §3.1), by @bsv/sdk and by noble ---------------------------------------
const k1Seed = hkdf(sha256, unhex(W.rootIkm), new Uint8Array(0), utf8(PROFILE.derivation.curveLabels.secp256k1), 32)
const deriver = new KeyDeriver(PrivateKey.fromHex(hex(k1Seed)))
const KW = PROFILE.derivation.keyPath.keywords
const commitmentPath = aid => `${KW.level1}/${W.acct}/${KW.level2}/${W.rid}/${KW.level3}/${aid}`
function commitmentKey(aid) {
  const key = deriver.derivePrivateKey([2, PROFILE.derivation.namespaces.signing], commitmentPath(aid), 'self')
  const id = `2-${PROFILE.derivation.namespaces.signing}-${commitmentPath(aid)}`
  const shared = secp256k1.getSharedSecret(k1Seed, secp256k1.getPublicKey(k1Seed, true), true)
  const h = BigInt('0x' + hex(hmac(sha256, shared, utf8(id))))
  const d = (BigInt('0x' + hex(k1Seed)) + h) % secp256k1.Point.CURVE().n
  if (key.toHex().padStart(64, '0') !== d.toString(16).padStart(64, '0')) fail('commitment key: @bsv/sdk vs noble')
  return key
}

// ---- transactions -------------------------------------------------------------------------------
const FUND_KEY = PrivateKey.fromHex(hex(sha256(utf8('TPNIL SDX v1 LAB_SELF_TEST_ONLY public test key: VA-ADM funding'))))
const STRAY_KEY = PrivateKey.fromHex(hex(sha256(utf8('TPNIL SDX v1 LAB_SELF_TEST_ONLY public test key: VA-ADM stray commitment'))))
const FUNDING = new Transaction(1, [{ sourceTXID: hex(sha256(utf8('TPNIL SDX v1 LAB_SELF_TEST_ONLY VA-ADM synthetic coinbase'))), sourceOutputIndex: 0, unlockingScript: new UnlockingScript([]), sequence: 0xffffffff }],
  Array.from({ length: 40 }, () => ({ lockingScript: new P2PKH().lock(FUND_KEY.toAddress()), satoshis: 1000 })), 0)
let nextFunding = 0
const container = (bytes, pub) => LockingScript.fromASM(`${hex(bytes)} OP_DROP ${pub.toString()} OP_CHECKSIG`)
const record = (env, key = commitmentKey(aidOf(env.bytes ?? env) ?? aidOf(E.R2.bytes))) => ({ lockingScript: container(env.bytes ?? env, key.toPublicKey()), satoshis: 1, key })
const raw = script => ({ lockingScript: LockingScript.fromHex(typeof script === 'string' ? script : script.toHex()), satoshis: 1 })
const change = () => ({ lockingScript: new P2PKH().lock(FUND_KEY.toAddress()), satoshis: 500 })
async function tx(outputs, spends = []) {
  const t = new Transaction(1, [], [], 0)
  for (const s of spends) {
    const unlock = { sign: async (txx, i) => { const full = await new P2PKH().unlock(s.key).sign(txx, i); return new UnlockingScript([full.chunks[0]]) }, estimateLength: async () => 74 }
    t.addInput({ sourceTransaction: s.tx, sourceOutputIndex: s.vout, unlockingScriptTemplate: unlock, sequence: 0xffffffff })
  }
  t.addInput({ sourceTransaction: FUNDING, sourceOutputIndex: nextFunding++, unlockingScriptTemplate: new P2PKH().unlock(FUND_KEY), sequence: 0xffffffff })
  for (const o of outputs) t.addOutput({ lockingScript: o.lockingScript, satoshis: o.satoshis })
  await t.sign()
  t.inputs.forEach((input, i) => {
    const src = input.sourceTransaction.outputs[input.sourceOutputIndex]
    const ok = new Spend({ sourceTXID: input.sourceTransaction.id('hex'), sourceOutputIndex: input.sourceOutputIndex, sourceSatoshis: src.satoshis, lockingScript: src.lockingScript, transactionVersion: 1, otherInputs: t.inputs.filter((_, j) => j !== i), outputs: t.outputs, unlockingScript: input.unlockingScript, inputSequence: 0xffffffff, inputIndex: i, lockTime: 0 }).validate()
    if (!ok) fail('a synthetic input does not validate')
  })
  t.keys = outputs.map(o => o.key)
  return t
}
const ref = (t, vout) => ({ txid: t.id('hex'), outputIndex: vout })

// ---- cases --------------------------------------------------------------------------------------
const TOPIC = 'tm_lab', INDEX = 'ls_lab', OTHER = 'tm_lab_handoff', OTHER_INDEX = 'ls_lab_handoff'
const cases = []
const add = c => cases.push({ id: `VA-ADM-${String(cases.length + 1).padStart(3, '0')}`, requirement: ['SDX-A-09'], tag: 'required', setup: { topics: [TOPIC] }, ...c })
const submit = (t, topics = [TOPIC], extra = {}) => ({ op: 'submit', topics, tx: t.toHex(), ...extra })
const lookup = (query, service = INDEX) => ({ op: 'lookup', service, query })
const admittedOnly = (outputs, retained = []) => ({ admitted: outputs, retained, declined: false })
const rows = list => ({ rows: list })
const qref = (t, vout) => ({ txid: t.id('hex'), outputIndex: vout })

// ANC §11.1: the keyless gate on every output, position-agnostic.
{
  const t = await tx([record(E.R1), change(), record(E.R2)])
  add({ title: 'Two real record envelopes in ANC §2.1 containers, at outputs 0 and 2 around a payment output: both admitted, the payment ignored', basis: ['ANC §11.1', 'ANC §2.1', 'ANC §2.3'], steps: [{ request: submit(t), expect: { topics: { [TOPIC]: admittedOnly([0, 2]) } } }, { request: lookup({ topic: TOPIC, since: null }), expect: rows([qref(t, 0), qref(t, 2)]) }] })
}
const gate = async (title, bad, basis = ['ANC §11.1']) => {
  const t = await tx([bad, record(E.R2)])
  add({ title, basis, steps: [{ request: submit(t), expect: { topics: { [TOPIC]: admittedOnly([1]) } } }] })
}
const r2key = commitmentKey(aidOf(E.R2.bytes))
await gate('A payment output with no record is ignored', change())
await gate('Record bytes after OP_FALSE OP_RETURN are not the container and are ignored', raw(LockingScript.fromASM(`OP_FALSE OP_RETURN ${hex(E.R2.bytes)}`)))
await gate('A container whose record push is not minimal (OP_PUSHDATA4 for a short envelope) is ignored', raw(Buffer.concat([Buffer.from([0x4e]), (b => { b.writeUInt32LE(E.R2.bytes.length); return b })(Buffer.alloc(4)), Buffer.from(E.R2.bytes), Buffer.from([0x75, 0x21]), Buffer.from(r2key.toPublicKey().encode(true)), Buffer.from([0xac])]).toString('hex')), ['ANC §11.1', 'ANC §2.1'])
await gate('A container with two data fields is ignored', raw(LockingScript.fromASM(`${hex(E.R2.bytes)} ${hex(utf8('second'))} OP_2DROP ${r2key.toPublicKey().toString()} OP_CHECKSIG`)), ['ANC §11.1', 'ANC §2.2'])
await gate('A container whose data is not CBOR is ignored', record(utf8('LAB_SELF_TEST_ONLY not an envelope')))
await gate('A container whose data is tagged CBOR is ignored: the canonical encoding rejects tags', record(Uint8Array.from([0xd8, 0x18, ...E.R2.bytes])), ['ANC §11.1', 'ENV §3 rule 4'])
await gate('An envelope whose `proto` is the example profile\'s `sdx:record:v1`, not the deployment\'s format identifier, is ignored', record(variant(v => { v.proto = 'sdx:record:v1' })), ['ANC §11.1', 'ENV §2'])
await gate('An envelope without `proto` is ignored', record(variant(v => { delete v.proto })))
await gate('An envelope without `pu` is ignored', record(variant(v => { delete v.pu })))
await gate('An envelope whose `pu` is a map is ignored', record(variant(v => { v.pu = {} })))
await gate('An envelope whose outer JWE has no authentication tag is ignored', record(variant(v => { delete v.outer.tag })))
await gate('An envelope whose outer JWE is a compact string is ignored', record(variant(v => { v.outer = `${v.outer.protected}..${v.outer.iv}.${v.outer.ciphertext}.${v.outer.tag}` })))
await gate('A CBOR array in place of the envelope map is ignored', record(encodeEnv([E.R2.bytes])))

// ANC §11.2: business rules narrow and never widen.
{
  const t = await tx([record(E.R1), record(E.R2), change(), record(E.R4)])
  add({ title: 'A business rule that drops output 1 narrows the admitted set to [0, 3]', basis: ['ANC §11.1', 'ANC §11.2'], setup: { topics: [TOPIC], rules: { [TOPIC]: { kind: 'drop', outputs: [1] } } }, steps: [{ request: submit(t), expect: { topics: { [TOPIC]: admittedOnly([0, 3]) } } }] })
  add({ title: 'A business rule that returns the payment output 2, an out-of-range index 9 and duplicates is clamped to the format-admissible set, in ascending order', basis: ['ANC §11.2'], setup: { topics: [TOPIC], rules: { [TOPIC]: { kind: 'inject', outputs: [2, 9, 0, 0] } } }, steps: [{ request: submit(t), expect: { topics: { [TOPIC]: admittedOnly([0, 1, 3]) } } }] })
  add({ title: 'A business rule that mutates its argument to add output 2 reaches no admitted set: the hook receives a defensive copy and its answer is clamped', basis: ['ANC §11.2'], setup: { topics: [TOPIC], rules: { [TOPIC]: { kind: 'mutate', outputs: [2] } } }, steps: [{ request: submit(t), expect: { topics: { [TOPIC]: admittedOnly([0, 1, 3]) } } }] })
}

// ANC §11.3: what admission does not do. Each output is format-valid and wrong in a way only a
// root-holder or a reader can see, and each is admitted.
const mustAdmit = async (title, out, basis) => {
  const t = await tx([out])
  add({ title, basis: ['ANC §11.3', ...basis], steps: [{ request: submit(t), expect: { topics: { [TOPIC]: admittedOnly([0]) } } }] })
}
await mustAdmit('A record under a commitment key that is not its ANC §3.1 derivation is admitted: checking it needs the root', record(E.R2, STRAY_KEY), ['ANC §3.1', 'ANC §6.2'])
await mustAdmit('A record whose signature does not verify (VA-SIG) is admitted: admission verifies no signature', record(E.BADSIG), ['ENV §8.3'])
await mustAdmit('A delegate record that a reader refuses `delegation-invalid` (VA-SIG) is admitted: admission judges no delegation', record(E.DELEG), ['KEYS §2.7.2'])
await mustAdmit('A record whose public slot carries neither a value nor the marker is admitted, though every reader refuses it before any unwrap (ENV §14 step 3): the ANC §11.1 gate does not look into public slots', record(E.PUBARE), ['ANC §11.1', 'ENV §7 rule 1', 'ENV §14 step 3'])

// ANC §11.4: idempotency; ANC §10.2: topics are independent.
{
  const t = await tx([record(E.R1), record(E.R2)])
  add({
    title: 'Resubmitting an admitted transaction to the same topic is a success with the same outcome and adds no index row', basis: ['ANC §11.4', 'ANC §12.2'],
    steps: [
      { request: submit(t), expect: { topics: { [TOPIC]: admittedOnly([0, 1]) } } },
      { request: submit(t), expect: { topics: { [TOPIC]: admittedOnly([0, 1]) } } },
      { request: lookup({ topic: TOPIC, since: null }), expect: rows([qref(t, 0), qref(t, 1)]) }
    ]
  })
  add({
    title: 'One submission to two topics is admitted independently per topic; a business rule on one narrows that topic only', basis: ['ANC §10.2', 'ANC §11.2'],
    setup: { topics: [TOPIC, OTHER], rules: { [OTHER]: { kind: 'drop', outputs: [0] } } },
    steps: [
      { request: submit(t, [TOPIC, OTHER]), expect: { topics: { [TOPIC]: admittedOnly([0, 1]), [OTHER]: admittedOnly([1]) } } },
      { request: lookup({ topic: OTHER, since: null }, OTHER_INDEX), expect: rows([qref(t, 1)]) }
    ]
  })
}

// ANC §11.5 retention, §12.2 cursor, §12.3 paging, §12.5 point lookups, on one chain.
const t1 = await tx([record(E.R1)])
const t2 = await tx([record(E.R2)], [{ tx: t1, vout: 0, key: t1.keys[0] }])
const t3 = await tx([record(utf8('LAB_SELF_TEST_ONLY not an envelope'))], [{ tx: t2, vout: 0, key: t2.keys[0] }])
const t4 = await tx([record(E.R4)])
const chain = [
  { request: submit(t1), expect: { topics: { [TOPIC]: admittedOnly([0]) } } },
  { request: submit(t2), expect: { topics: { [TOPIC]: admittedOnly([0], [qref(t1, 0)]) } } }
]
add({ title: 'An action that consumes an admitted entry names it as retained, and the consumed entry stays in the cold-start backfill, in admission order', basis: ['ANC §11.5', 'ANC §12.2'], steps: [...chain, { request: lookup({ topic: TOPIC, since: null }), expect: rows([qref(t1, 0), qref(t2, 0)]) }] })
add({ title: 'A submission whose only output fails to parse as a record admits nothing and still names the entry it consumes as retained; the history survives', basis: ['ANC §11.5'], steps: [...chain, { request: submit(t3), expect: { topics: { [TOPIC]: admittedOnly([], [qref(t2, 0)]) } } }, { request: lookup({ topic: TOPIC, since: null }), expect: rows([qref(t1, 0), qref(t2, 0)]) }] })
add({ title: 'Retention names only previously admitted entries: a transaction that spends only a funding output retains nothing', basis: ['ANC §11.5'], steps: [{ request: submit(t4), expect: { topics: { [TOPIC]: admittedOnly([0]) } } }] })
add({
  title: 'A cursor returns the admissions strictly after it; at the last entry the page is empty; an explicit limit is honoured verbatim', basis: ['ANC §12.2', 'ANC §12.3'],
  steps: [...chain, { request: submit(t4), expect: { topics: { [TOPIC]: admittedOnly([0]) } } },
    { request: lookup({ topic: TOPIC, since: qref(t1, 0) }), expect: rows([qref(t2, 0), qref(t4, 0)]) },
    { request: lookup({ topic: TOPIC, since: qref(t4, 0) }), expect: rows([]) },
    { request: lookup({ topic: TOPIC, since: null, limit: 2 }), expect: rows([qref(t1, 0), qref(t2, 0)]) },
    { request: lookup({ topic: TOPIC, since: qref(t2, 0), limit: 1 }), expect: rows([qref(t4, 0)]) }]
})
add({
  title: 'Point lookups: an admitted entry, a consumed and retained entry, an entry never admitted (empty, not an error) and an entry admitted only to another topic (empty)', basis: ['ANC §12.5'],
  setup: { topics: [TOPIC, OTHER] },
  steps: [...chain, { request: submit(t4, [OTHER]), expect: { topics: { [OTHER]: admittedOnly([0]) } } },
    { request: lookup({ topic: TOPIC, outpoint: qref(t2, 0) }), expect: rows([qref(t2, 0)]) },
    { request: lookup({ topic: TOPIC, outpoint: qref(t1, 0) }), expect: rows([qref(t1, 0)]) },
    { request: lookup({ topic: TOPIC, outpoint: qref(t3, 0) }), expect: rows([]) },
    { request: lookup({ topic: TOPIC, outpoint: qref(t4, 0) }), expect: rows([]) }]
})

// ANC §12.4 fail-closed rules and the ANC §12.1 constants.
const refusedQuery = (title, request, detail, basis = ['ANC §12.4'], before = chain) => add({ title, basis, steps: [...before, { request, expect: { refusal: { class: 'query', detail } } }] })
refusedQuery('A query that is not an object is refused', lookup([TOPIC]), 'not-object')
refusedQuery('A query with an unrecognised key is refused, and the refusal names the keys the index answers', lookup({ topic: TOPIC, since: null, from: 0 }), 'unknown-key:limit,outpoint,since,topic')
refusedQuery('A query without `topic` is refused', lookup({ since: null }), 'topic')
refusedQuery('A query whose `topic` is empty is refused', lookup({ topic: '', since: null }), 'topic')
refusedQuery('A query whose `topic` is not a string is refused', lookup({ topic: 7, since: null }), 'topic')
refusedQuery('A query naming a topic this index is not bound to is refused', lookup({ topic: OTHER, since: null }), 'topic-not-bound')
refusedQuery('A cursor query without `since` is refused: it is required and nullable, never optional', lookup({ topic: TOPIC }), 'since-absent')
refusedQuery('A `since` that is not an entry reference is refused', lookup({ topic: TOPIC, since: { txid: 'zz', outputIndex: 0 } }), 'since')
refusedQuery('A `since` naming an entry this topic never admitted is refused rather than treated as a cold start', lookup({ topic: TOPIC, since: qref(t4, 0) }), 'since-unknown')
refusedQuery('A `limit` of 0 is refused', lookup({ topic: TOPIC, since: null, limit: 0 }), 'limit')
refusedQuery('A `limit` that is not an integer is refused', lookup({ topic: TOPIC, since: null, limit: '5' }), 'limit')
refusedQuery('A point lookup combined with `since` is refused', lookup({ topic: TOPIC, outpoint: qref(t1, 0), since: null }), 'outpoint-with-cursor', ['ANC §12.5'])
refusedQuery('A point lookup combined with `limit` is refused', lookup({ topic: TOPIC, outpoint: qref(t1, 0), limit: 1 }), 'outpoint-with-cursor', ['ANC §12.5'])
refusedQuery('A point lookup naming a topic this index is not bound to is refused', lookup({ topic: OTHER, outpoint: qref(t1, 0) }), 'topic-not-bound', ['ANC §12.5'])
refusedQuery('A lookup addressed to `tm_lab`, the topic name, rather than its index `ls_lab` is refused: the prefixes are wire constants', lookup({ topic: TOPIC, since: null }, TOPIC), 'service', ['ANC §12.1'])
add({
  title: 'After the index is known to be short a row (an admission notification that failed to record), every later answer for the topic is refused, cursor and point lookups alike', basis: ['ANC §12.4'], hook: true,
  steps: [...chain, { request: { op: 'fault', topic: TOPIC }, expect: { ok: true } },
    { request: lookup({ topic: TOPIC, since: null }), expect: { refusal: { class: 'query', detail: 'index-fault' } } },
    { request: lookup({ topic: TOPIC, outpoint: qref(t1, 0) }), expect: { refusal: { class: 'query', detail: 'index-fault' } } }]
})

// ANC §11.6: side-channel accounting against the public manifests a node can read without a key.
const pubValue = text => encodeEnv(text)
const V1 = pubValue('LAB_SELF_TEST_ONLY public value one'), V2 = pubValue('LAB_SELF_TEST_ONLY public value two, longer')
const manifest = (n, bytes, sz = bytes.length) => ({ n, im: { sha: sha256(bytes), u: `overlay://${TOPIC}/${hex(sha256(bytes))}`, sz } })
const withPublic = slots => variant(v => { v.pu = slots })
const sideCase = async (title, outputs, run, expectTopic, basis = ['ANC §11.6']) => {
  const t = await tx(outputs)
  const steps = [{ request: submit(t, [TOPIC], { offChain: hex(run) }), expect: { topics: { [TOPIC]: expectTopic } } }]
  if (!expectTopic.declined) steps.push({ request: lookup({ topic: TOPIC, outpoint: qref(t, expectTopic.admitted[0]) }), expect: rows([{ ...qref(t, expectTopic.admitted[0]), offChain: hex(run) }]) })
  add({ title, basis, steps })
}
const two = withPublic([manifest('one', V1), manifest('two', V2)])
await sideCase('One admitted output whose public manifests account for the whole run: the node slices the run in declared order and verifies both entries', [record(two)], Buffer.concat([V1, V2]), { admitted: [0], retained: [], declined: false, sideChannel: { accounting: 'verified', publicEntriesVerified: 2 } })
await sideCase('One admitted output, sizes equal to the run, one slice whose digest differs: declined', [record(two)], Buffer.concat([V1, Buffer.from(V2).fill(0x7a, 5, 6)]), { admitted: [], retained: [], declined: true })
await sideCase('Public manifests whose sizes exceed the run: declined, with no attribution needed', [record(two)], Buffer.from(V1), { admitted: [], retained: [], declined: true })
await sideCase('One admitted output whose public sizes are below the run: non-public bytes are present, so the run is retained unverified', [record(two)], Buffer.concat([V1, V2, utf8('hidden audit bytes')]), { admitted: [0], retained: [], declined: false, sideChannel: { accounting: 'unverified', publicEntriesVerified: 0 } })
await sideCase('Two admitted outputs: the run cannot be attributed, so it is retained unverified and not declined, even with sizes equal to it', [record(withPublic([manifest('one', V1)])), record(withPublic([manifest('two', V2)]))], Buffer.concat([V2, V1]), { admitted: [0, 1], retained: [], declined: false, sideChannel: { accounting: 'unverified', publicEntriesVerified: 0 } })
await sideCase('Two admitted outputs whose public sizes exceed the run: declined', [record(withPublic([manifest('one', V1)])), record(withPublic([manifest('two', V2)]))], Buffer.from(V1), { admitted: [], retained: [], declined: true })
await sideCase('A public manifest on an external scheme is not on the channel and is not counted: one admitted output, overlay sizes equal to the run, verified', [record(withPublic([manifest('one', V1), { n: 'ext', im: { sha: sha256(V2), u: 'file:///lab/two', sz: V2.length } }]))], Buffer.from(V1), { admitted: [0], retained: [], declined: false, sideChannel: { accounting: 'verified', publicEntriesVerified: 1 } }, ['ANC §11.6', 'ENV-FP §2.2', 'ENV-FP §2.3'])

// ---- every case through the Node checker -------------------------------------------------------
for (const c of cases) {
  const result = runCase(PROFILE, c)
  if (!result.ok) fail(`${c.id} ${c.title}: step ${result.step}: ${JSON.stringify(result.actual)}`)
}

const doc = {
  schema: 'tpnil-sdx-vectors@0.1.0',
  suite: 'VA-ADM',
  claim: 'LAB_SELF_TEST_ONLY',
  status: 'LABORATORY-STAND-IN',
  standIn: 'A laboratory stand-in for SDX\'s unpublished `overlay-binding` suite (BASE §6 item 6). It is replaced by the published suite when SDX releases it.',
  requirements: ['SDX-A-09'],
  profile: { id: PROFILE.profile, path: PROFILE_PATH, sha256: hex(sha256(PROFILE_BYTES)) },
  driverContract: 'programs/proposals/sdx-data-sharing/0.1.0/driver-contract.md',
  citations: ['ANC §2.1', 'ANC §2.2', 'ANC §2.3', 'ANC §3.1', 'ANC §10.1', 'ANC §10.2', 'ANC §11.1', 'ANC §11.2', 'ANC §11.3', 'ANC §11.4', 'ANC §11.5', 'ANC §11.6', 'ANC §12.1', 'ANC §12.2', 'ANC §12.3', 'ANC §12.4', 'ANC §12.5'].map(clause => ({ path: 'fixtures/sdx/v1/standards/text/anchoring.md', clause })),
  sources: { envelopes: [{ suite: 'VA-ENV', path: ENV_FILE, sha256: hex(sha256(read(ENV_FILE))) }, { suite: 'VA-SIG', path: SIG_FILE, sha256: hex(sha256(read(SIG_FILE))) }], cases: Object.fromEntries(Object.entries(E).map(([k, v]) => [k, v.id])) },
  constants: { topicPrefix: 'tm_', indexPrefix: 'ls_', topics: { [TOPIC]: INDEX, [OTHER]: OTHER_INDEX }, pageCeiling: 1000, basis: 'ANC §10.1, §12.1, §12.3' },
  funding: { transaction: FUNDING.toHex(), note: 'A synthetic parent whose 40 P2PKH outputs fund every submitted transaction; nothing is broadcast and it carries no proof. Every input of every submitted transaction validates (@bsv/sdk Spend).' },
  decisions: [
    { id: 'stand-in', kind: 'Laboratory test-construction choice', text: 'VA-ADM states ANC §10-§12 behaviour as driver-contract steps against a fresh admission service and index per case: `submit` (a raw transaction, its topics and an optional side-channel run) and `lookup` (an index name and a query), plus an optional `fault` hook. Admission outcomes are compared as admitted output indices, retained entries, the decline flag and the side-channel accounting; index answers as entry references in order, with the retained run. Transactions are raw and their parents are in this file; a harness driving an overlay engine that requires proofs wraps them for its controlled network. Basis: ANC §11.4, §12.2, §12.5, §12.6.' },
    { id: 'gate-proto', kind: 'Laboratory interpretation', text: 'The admission gate compares the envelope\'s `proto` with the deployment profile\'s format identifier. Source finding: ANC §11.1 asks for "the fixed value for this specification", while ENV §2 makes the identifier a deployment-profile parameter and calls the example `sdx:record:v1` non-normative. Basis: ANC §11.1; ENV §2, §2.1.' },
    { id: 'gate-shape', kind: 'Rests on the cited text', text: 'An output is format-admissible when it is an ANC §2.1 container with exactly one minimally pushed data field, the field decodes under the ENV §3 semantic decoder, the value is a map whose `proto` is the format identifier, `pu` is an array and `outer` is a map carrying `ciphertext`, `iv` and `tag`. Nothing else is judged. The laboratory\'s readers apply the same checks before any unwrap (VA-ENV). Basis: ANC §2.1, §2.2, §11.1.' },
    { id: 'gate-versus-reader', kind: 'Rests on the cited text', text: 'Admission admits a record whose public slot carries neither a value nor the marker, which every reader refuses before any unwrap (ENV §14 step 3). Source finding: ANC §11.1 says the gate is exactly the set the reader will attempt to decode, so that a node does not admit records the reader will dead-letter, while ENV §14 step 3 refuses public-slot faults that the gate does not look at. Basis: ANC §11.1, §11.3; ENV §7, §14 step 3.' },
    { id: 'rules', kind: 'Laboratory test-construction choice', text: 'Business rules are laboratory hooks: `drop` removes listed outputs, `inject` returns extra indices and `mutate` adds them to its argument. The service passes the hook a copy and intersects its answer with the format-admissible set, in ascending order. Basis: ANC §11.2.' },
    { id: 'retention', kind: 'Laboratory interpretation', text: 'Every admitted entry a submitted transaction consumes is named as retained on every path that returns, including a submission whose outputs fail to parse as records and admit nothing; a declined submission (ANC §11.6) raises and returns nothing. Retained entries stay in index answers. Basis: ANC §11.5, §11.6, §12.2.' },
    { id: 'side-channel', kind: 'Laboratory interpretation', text: 'The run is accounted against the public manifests of the admitted outputs whose URI is `overlay://`, the only bytes that ride the channel; a manifest on an external scheme is not counted. Sum above the run: declined. Sum equal and exactly one admitted output: sliced in declared order, each slice checked for length and digest, declined on a mismatch, otherwise `verified` with the count of public entries verified. Sum below with one output, or two or more outputs: retained `unverified`. Source finding: ANC §11.6 does not say which manifests count; ENV-FP §2.2-§2.3 and §5 step 4 put only overlay bytes on the channel. A declined submission is reported as `declined: true` with no admitted output; ANC §11.6 records that a refusal is not yet distinguishable to the submitter, so a harness reads it from the service\'s diagnostic channel. Basis: ANC §11.6; ENV-FP §2.2, §2.3, §5.' },
    { id: 'index', kind: 'Rests on the cited text', text: 'The index answers from its own append-only admission record, in admission order; a cursor returns entries strictly after it; an explicit limit is honoured verbatim; consumed entries remain. Every ANC §12.4 condition is refused with the class `query`; the `detail` labels are the laboratory\'s, and an unknown key names the keys the index answers. A point lookup returns the one admission, with its transaction\'s retained run, or an empty answer for an entry the topic does not hold. The index of topic `tm_<scope>` is `ls_<scope>`. Basis: ANC §12.1-§12.5.' },
    { id: 'fault-hook', kind: 'Laboratory test-construction choice', text: 'The ANC §12.4 index-fault rule needs a failed admission notification, which only the implementation can produce, so the case uses the optional `fault` hook; an implementation without one is BLOCKED on that case.' },
    { id: 'outpoints', kind: 'Laboratory test-construction choice', text: 'Entry references are {txid, outputIndex} with the txid in display byte order, as the ANC §12.2 query shows them.' }
  ],
  generator: { component: 'components/sdx/admission', command: 'npm run generate --prefix components/sdx/admission', check: 'npm run check --prefix components/sdx/admission', dependencies: JSON.parse(fs.readFileSync(path.join(HERE, 'package.json'), 'utf8')).dependencies, lockfile: 'components/sdx/admission/package-lock.json', deterministic: 'Envelopes from the VA-ENV and VA-SIG files, keys from published roots and labels, and RFC 6979 signatures; `node generate.mjs --check` reproduces the file byte for byte. Regenerate after VA-ENV or VA-SIG changes.' },
  oracles: {
    generatorWitness: '@bsv/sdk 4.0.1 validates every input of every synthetic transaction (Spend) and derives every commitment key, which noble derives independently.',
    node: { modules: ['src/sdx/adm.mjs', 'src/sdx/tx.mjs', 'src/sdx/cbor-det.mjs'], kind: 'oracle', dependencies: 'Node.js built-ins only', tests: ['test/sdx-adm.test.mjs'] },
    python: { modules: ['test/sdx_adm.py', 'test/sdx_anc.py'], kind: 'oracle', dependencies: 'Python standard library only', tests: ['test/test_sdx_adm.py'] }
  },
  caseCount: cases.length,
  cases
}
const text = JSON.stringify(doc, null, 1) + '\n'
const file = path.join(REPO, OUTPUT)
if (mode === '--write') { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, text); console.log(`wrote ${OUTPUT} (${cases.length} cases)`) }
else if (!fs.existsSync(file) || fs.readFileSync(file, 'utf8') !== text) { console.error(`${OUTPUT} is not current; run --write`); process.exit(1) }
else console.log(`${OUTPUT} is current (${cases.length} cases)`)
