// LAB_SELF_TEST_ONLY oracle for VA-ADM: an SDX admission service and per-topic index (ANC §10-§12)
// as the laboratory states them, driven by the driver contract's submit, lookup and fault steps.
// Node.js built-ins only: transactions and the ANC §2.1 container from src/sdx/tx.mjs, the ENV §3
// semantic decoder from src/sdx/cbor-det.mjs. It holds no key and imports no generator code.
import { createHash } from 'node:crypto'
import { CborDetError, decode as cborDecode } from './cbor-det.mjs'
import { checkContainer, displayHex, parseTransaction } from './tx.mjs'

const sha256 = bytes => createHash('sha256').update(bytes).digest()
const isMap = v => v instanceof Map
const QUERY_KEYS = ['limit', 'outpoint', 'since', 'topic']
const PAGE_CEILING = 1000

// ANC §11.1: the keyless, position-agnostic format gate. Returns the decoded envelope or null.
export function admissible(profile, script) {
  const c = checkContainer(script)
  if (!c.ok) return null
  let env
  try { env = cborDecode(c.record) } catch (error) { if (error instanceof CborDetError) return null; throw error }
  if (!isMap(env) || env.get('proto') !== profile.formatIdentifier.value || !Array.isArray(env.get('pu'))) return null
  const outer = env.get('outer')
  if (!isMap(outer) || !['ciphertext', 'iv', 'tag'].every(m => typeof outer.get(m) === 'string')) return null
  return env
}

// The public manifests on the side channel: `overlay://` manifests in the public array.
function publicOverlayManifests(env) {
  const out = []
  for (const slot of env.get('pu')) {
    const im = isMap(slot) ? slot.get('im') : undefined
    if (isMap(im) && typeof im.get('u') === 'string' && im.get('u').startsWith('overlay://') && Number.isSafeInteger(im.get('sz')) && im.get('sha') instanceof Uint8Array) out.push({ size: im.get('sz'), sha: im.get('sha') })
  }
  return out
}

function applyRule(rule, pristine) {
  if (!rule) return pristine
  const copy = [...pristine]
  let answer
  if (rule.kind === 'drop') answer = copy.filter(i => !rule.outputs.includes(i))
  else if (rule.kind === 'inject') answer = [...copy, ...rule.outputs]
  else if (rule.kind === 'mutate') { copy.push(...rule.outputs); answer = copy }
  else throw new Error(`unknown rule ${rule.kind}`)
  // ANC §11.2: intersect with the pristine set; drop duplicates; ascending order.
  return pristine.filter(i => answer.includes(i))
}

const refKey = r => `${r.txid}:${r.outputIndex}`
const validRef = r => isPlainObject(r) && Object.keys(r).length === 2 && typeof r.txid === 'string' && /^[0-9a-f]{64}$/.test(r.txid) && Number.isSafeInteger(r.outputIndex) && r.outputIndex >= 0
function isPlainObject(v) { return v !== null && typeof v === 'object' && !Array.isArray(v) }

export function createEngine(profile, setup) {
  const topics = new Map(setup.topics.map(t => [t, { rows: [], keys: new Set(), done: new Map(), fault: false, rule: setup.rules?.[t] }]))
  const runs = new Map() // txid -> retained side-channel run

  function submit(req) {
    const tx = parseTransaction(Buffer.from(req.tx, 'hex'))
    const txid = displayHex(tx.txid)
    const run = req.offChain === undefined ? null : Buffer.from(req.offChain, 'hex')
    const result = {}
    for (const name of req.topics) {
      const topic = topics.get(name)
      if (!topic) throw new Error(`topic ${name} is not hosted`)
      if (topic.done.has(txid)) { result[name] = topic.done.get(txid); continue } // ANC §11.4
      const decoded = tx.outputs.map(o => admissible(profile, o.script))
      const pristine = decoded.flatMap((env, i) => (env ? [i] : []))
      const admitted = applyRule(topic.rule, pristine)
      // ANC §11.6: account for the run against the manifests readable without a key.
      let sideChannel
      let declined = false
      if (run) {
        const manifests = admitted.flatMap(i => publicOverlayManifests(decoded[i]))
        const sum = manifests.reduce((a, m) => a + m.size, 0)
        if (sum > run.length) declined = true
        else if (admitted.length === 1 && sum === run.length) {
          let at = 0
          for (const m of manifests) {
            const slice = run.subarray(at, at + m.size)
            at += m.size
            if (slice.length !== m.size || !sha256(slice).equals(Buffer.from(m.sha))) declined = true
          }
          if (!declined) sideChannel = { accounting: 'verified', publicEntriesVerified: manifests.length }
        } else sideChannel = { accounting: 'unverified', publicEntriesVerified: 0 }
      }
      let entry
      if (declined) entry = { admitted: [], retained: [], declined: true }
      else {
        // ANC §11.5: name every previously admitted entry the transaction consumes.
        const retained = tx.inputs.map(input => ({ txid: displayHex(input.prevTxid), outputIndex: input.vout })).filter(r => topic.keys.has(refKey(r)))
        for (const i of admitted) {
          const r = { txid, outputIndex: i }
          topic.rows.push(r)
          topic.keys.add(refKey(r))
        }
        if (run && admitted.length > 0) runs.set(txid, run)
        entry = { admitted, retained, declined: false, ...(sideChannel ? { sideChannel } : {}) }
      }
      topic.done.set(txid, entry)
      result[name] = entry
    }
    return { topics: result }
  }

  const refusal = detail => ({ refusal: { class: 'query', detail } })
  const row = r => (runs.has(r.txid) ? { ...r, offChain: runs.get(r.txid).toString('hex') } : { ...r })

  function lookup(req) {
    // ANC §12.1: the index of `tm_<scope>` is `ls_<scope>`.
    const bound = typeof req.service === 'string' && req.service.startsWith('ls_') ? `tm_${req.service.slice(3)}` : null
    if (!bound || !topics.has(bound)) return refusal('service')
    const q = req.query
    if (!isPlainObject(q)) return refusal('not-object')
    for (const k of Object.keys(q)) if (!QUERY_KEYS.includes(k)) return refusal(`unknown-key:${QUERY_KEYS.join(',')}`)
    if (typeof q.topic !== 'string' || q.topic.length === 0) return refusal('topic')
    if (q.topic !== bound) return refusal('topic-not-bound')
    const topic = topics.get(bound)
    if ('outpoint' in q) {
      if ('since' in q || 'limit' in q) return refusal('outpoint-with-cursor')
      if (!validRef(q.outpoint)) return refusal('outpoint')
      if (topic.fault) return refusal('index-fault')
      return { rows: topic.rows.filter(r => refKey(r) === refKey(q.outpoint)).map(row) } // ANC §12.5: absent is an empty answer
    }
    if (!('since' in q)) return refusal('since-absent')
    if (q.since !== null && !validRef(q.since)) return refusal('since')
    if ('limit' in q && !(Number.isSafeInteger(q.limit) && q.limit > 0)) return refusal('limit')
    if (topic.fault) return refusal('index-fault')
    let start = 0
    if (q.since !== null) {
      const at = topic.rows.findIndex(r => refKey(r) === refKey(q.since))
      if (at < 0) return refusal('since-unknown')
      start = at + 1
    }
    return { rows: topic.rows.slice(start, start + ('limit' in q ? q.limit : PAGE_CEILING)).map(row) }
  }

  function fault(req) {
    topics.get(req.topic).fault = true
    return { ok: true }
  }

  return { step: req => ({ submit, lookup, fault })[req.op](req) }
}

export function runCase(profile, kase) {
  const engine = createEngine(profile, kase.setup)
  for (let i = 0; i < kase.steps.length; i++) {
    const actual = engine.step(kase.steps[i].request)
    if (JSON.stringify(canon(actual)) !== JSON.stringify(canon(kase.steps[i].expect))) return { ok: false, step: i, actual }
  }
  return { ok: true }
}
const canon = v => (Array.isArray(v) ? v.map(canon) : isPlainObject(v) ? Object.fromEntries(Object.keys(v).sort().map(k => [k, canon(v[k])])) : v)
