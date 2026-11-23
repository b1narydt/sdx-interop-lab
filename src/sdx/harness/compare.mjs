// LAB_SELF_TEST_ONLY comparison rules of the SDX laboratory driver contract (driver-contract.md,
// Comparison): projections by value, refusals by verdict and by class only where the case tags the
// class `required`, never by the laboratory's `detail` label. Node.js built-ins and the
// laboratory's own checker modules only; no generator code.
import { CURVES, encodePoint, mulBase, toInt } from '../ec-p256.mjs'

const isObject = v => v !== null && typeof v === 'object' && !Array.isArray(v)

// JSON objects are unordered: members compare by name. Arrays compare in order.
export const canon = v => (Array.isArray(v) ? v.map(canon) : isObject(v) ? Object.fromEntries(Object.keys(v).sort().map(k => [k, canon(v[k])])) : v)
export const same = (a, b) => JSON.stringify(canon(a)) === JSON.stringify(canon(b))
const show = v => { const s = JSON.stringify(canon(v)); return s === undefined ? 'absent' : s.length > 300 ? `${s.slice(0, 300)}…` : s }

// The members a read projection defines. Members a driver adds are not judged; a defined member
// that is `null` counts as absent.
const PROJECTION = ['tier', 'verdict', 'aid', 'hdr', 'fields', 'signature']
const member = (o, k) => (o[k] === null ? undefined : o[k])

// Returns null when the observation matches, or the first difference as text.
export function compareRead(expect, actual, classTag = 'required') {
  if (!isObject(actual)) return 'response is not a projection'
  if (actual.verdict !== expect.verdict) return `verdict ${show(actual.verdict)}, expected ${expect.verdict}${actual.refusal ? ` (${show(actual.refusal)})` : ''}`
  if (expect.verdict === 'refused') {
    if (!isObject(actual.refusal)) return 'refused without a refusal member'
    if (classTag === 'required' && actual.refusal.class !== expect.refusal.class) return `refusal class ${show(actual.refusal.class)}, expected ${expect.refusal.class}`
    return null
  }
  for (const k of PROJECTION) {
    if (k === 'verdict') continue
    const want = member(expect, k)
    const got = member(actual, k)
    if (want === undefined && got !== undefined && (k === 'hdr' || k === 'signature')) return `${k} present at tier ${expect.tier}`
    if (!same(want, got)) return k === 'fields' ? fieldDiff(want, got) : `${k} ${show(got)}, expected ${show(want)}`
  }
  return null
}

function fieldDiff(want, got) {
  if (!Array.isArray(got)) return `fields ${show(got)}, expected an array`
  if (got.length !== want.length) return `${got.length} fields, expected ${want.length}: ${show(got.map(f => f?.n))} against ${show(want.map(f => f.n))}`
  for (let i = 0; i < want.length; i++) if (!same(want[i], got[i])) return `field ${i} ${show(got[i])}, expected ${show(want[i])}`
  return 'fields differ'
}

// A writer's refusal is compared by its presence (driver-contract.md, Comparison).
export const isRefusal = v => isObject(v) && isObject(v.refusal)

// ---- keys (VA-KEY) ----

const publicOf = (curve, seedHex) => Buffer.from(encodePoint(CURVES[curve], mulBase(CURVES[curve], toInt(Buffer.from(seedHex, 'hex'))))).toString('hex')

// `contained`: the driver's declaration says its keys never leave its key store. Then `split` may
// answer the two root public keys, and `derive` may omit `privateKey`, whose public key it answers:
// on a prime-order group a public key determines its private key in [1, n − 1].
export function compareKey(expect, actual, request, { contained = false } = {}) {
  if (!isObject(actual)) return { diff: 'response is not an object' }
  if (expect.refusal) {
    if (!isRefusal(actual)) return { diff: `answered ${show(actual)}, expected a refusal` }
    if (actual.refusal.class !== expect.refusal.class) return { diff: `refusal class ${show(actual.refusal.class)}, expected ${expect.refusal.class}` }
    return { diff: null }
  }
  if (isRefusal(actual)) return { diff: `refused (${show(actual.refusal)}), expected ${show(expect)}` }
  const notes = []
  switch (request.op) {
    case 'split': {
      if ('secp256k1Seed' in actual || !contained) return { diff: same(expect, pick(actual, ['secp256k1Seed', 'p256Seed'])) ? null : `seeds ${show(actual)}, expected ${show(expect)}` }
      const want = { secp256k1Public: publicOf('secp256k1', expect.secp256k1Seed), p256Public: publicOf('p256', expect.p256Seed) }
      notes.push('contained keys: compared as the public keys of the expected seeds')
      return { diff: same(want, pick(actual, ['secp256k1Public', 'p256Public'])) ? null : `public keys ${show(actual)}, expected ${show(want)}`, notes }
    }
    case 'derive': {
      const keys = ['identifier', 'publicKey', ...('privateKey' in expect && 'privateKey' in actual ? ['privateKey'] : [])]
      if ('privateKey' in expect && !('privateKey' in actual)) {
        if (!contained) return { diff: 'privateKey missing' }
        notes.push('contained keys: privateKey not exposed; the matching publicKey determines it')
      }
      return { diff: same(pick(expect, keys), pick(actual, keys)) ? null : `derived ${show(pick(actual, keys))}, expected ${show(pick(expect, keys))}`, notes }
    }
    case 'validate':
      return { diff: actual.verdict === expect.verdict ? null : `verdict ${show(actual.verdict)}, expected ${expect.verdict}` }
    case 'profile': {
      if (actual.verdict !== expect.verdict) return { diff: `verdict ${show(actual.verdict)}, expected ${expect.verdict}` }
      const got = Array.isArray(actual.failures) ? [...actual.failures].sort() : actual.failures
      return { diff: same([...expect.failures].sort(), got) ? null : `failures ${show(actual.failures)}, expected ${show(expect.failures)}` }
    }
    default:
      return { diff: same(expect, actual) ? null : `answered ${show(actual)}, expected ${show(expect)}` }
  }
}

const pick = (o, keys) => Object.fromEntries(keys.filter(k => k in o).map(k => [k, o[k]]))

// ---- admission and index (VA-ADM) ----

export function compareAdmStep(expect, actual, request) {
  if (!isObject(actual)) return 'response is not an object'
  if (request.op === 'submit') {
    if (!isObject(actual.topics)) return `no topics in ${show(actual)}`
    for (const [topic, want] of Object.entries(expect.topics)) {
      const got = actual.topics[topic]
      if (!isObject(got)) return `topic ${topic} missing`
      for (const k of ['admitted', 'retained', 'declined']) if (!same(want[k], got[k])) return `${topic}.${k} ${show(got[k])}, expected ${show(want[k])}`
      if (!same(want.sideChannel, member(got, 'sideChannel'))) return `${topic}.sideChannel ${show(got.sideChannel)}, expected ${show(want.sideChannel)}`
    }
    return null
  }
  if (request.op === 'lookup') {
    if (expect.refusal) {
      if (!isRefusal(actual)) return `answered ${show(actual)}, expected a ${expect.refusal.class} refusal`
      return actual.refusal.class === expect.refusal.class ? null : `refusal class ${show(actual.refusal.class)}, expected ${expect.refusal.class}`
    }
    if (isRefusal(actual)) return `refused (${show(actual.refusal)}), expected rows`
    if (!Array.isArray(actual.rows)) return `no rows in ${show(actual)}`
    const rows = actual.rows.map(r => pick(r, ['txid', 'outputIndex', 'offChain']))
    return same(expect.rows, rows) ? null : `rows ${show(rows)}, expected ${show(expect.rows)}`
  }
  return same(expect, actual) ? null : `answered ${show(actual)}, expected ${show(expect)}`
}
