// LAB_SELF_TEST_ONLY harness for the proposed SDX data-sharing program: runs SDX v0.1
// implementations through the laboratory driver contract against the record-level suites and
// against each other. Node.js built-ins and the laboratory's checker modules only; it imports no
// generator code. Results are per case PASS, FAIL, BLOCKED, ERROR, INCONCLUSIVE or NOT_APPLICABLE,
// each with a reason (docs/conformance-model.md).
//
// - VA-ENV and VA-SIG: every write case through each implementation, judged by the write checks
//   published with the suite (`checkWrite`); every read case through each implementation; and every
//   read case marked `fromWrite` rerun on each implementation's own envelope through every
//   implementation, which is the exchange matrix (A writes, B reads; B writes, A reads; and each
//   reading its own).
// - VA-KEY: every case through each implementation.
// - VA-ADM: every case in one driver process per implementation.
// - VA-ENC and VA-ANC: the contract defines no operation for them, so every case is BLOCKED.
import fs from 'node:fs'
import path from 'node:path'
import { checkWrite } from '../env.mjs'
import { runSession, pool } from './driver.mjs'
import { compareRead, compareKey, compareAdmStep, isRefusal, canon } from './compare.mjs'

export const HARNESS_VERSION = '0.1.0'
export const PROFILE_PATH = 'fixtures/sdx/v1/deployment-profile.json'
export const SUITES = Object.freeze({
  'VA-ENV': 'fixtures/sdx/v1/va-env/vectors.json',
  'VA-SIG': 'fixtures/sdx/v1/va-sig/vectors.json',
  'VA-KEY': 'fixtures/sdx/v1/va-key/vectors.json',
  'VA-ADM': 'fixtures/sdx/v1/va-adm/vectors.json',
  'VA-ENC': 'fixtures/sdx/v1/va-enc/vectors.json',
  'VA-ANC': 'fixtures/sdx/v1/va-anc/vectors.json'
})
const RECORD_SUITES = ['VA-ENV', 'VA-SIG']
const UNRUNNABLE = {
  'VA-ENC': 'driver contract 0.1.0 defines no deterministic-encoding operation; VA-ENC runs only against the laboratory checkers',
  'VA-ANC': 'driver contract 0.1.0 defines no anchoring or chain-walk operation; VA-ANC runs only against the laboratory checkers'
}

// The optional write provisions a declaration may leave out, and how a write request uses them.
// ENV §4: the convergent property is opt-in per field. ENV §9.1: a private field MAY be writer-blind.
// Driver contract: a writer that cannot take `random` ignores it, and the checks that depend on it
// are then not applicable.
const WRITE_OPTIONS = {
  convergent: { uses: req => req.record.fields.some(f => 'cv' in f), basis: 'ENV §4: the convergent property is opt-in per field' },
  writerBlind: { uses: req => req.record.fields.some(f => f.blind === true), basis: 'ENV §9.1: a private field MAY be declared writer-blind' }
}

const readJson = (root, rel) => JSON.parse(fs.readFileSync(path.join(root, rel), 'utf8'))
const casesOf = doc => doc.cases ?? doc.vectors

// Aggregate precedence (docs/conformance-model.md): ERROR, FAIL, INCONCLUSIVE, BLOCKED, PASS.
// NOT_APPLICABLE never raises an aggregate.
const PRECEDENCE = ['ERROR', 'FAIL', 'INCONCLUSIVE', 'BLOCKED', 'PASS']
export function aggregate(outcomes) {
  const applicable = outcomes.filter(o => o !== 'NOT_APPLICABLE')
  if (applicable.length === 0) return 'NOT_APPLICABLE'
  return PRECEDENCE.find(o => applicable.includes(o))
}

const result = (outcome, reason, extra = {}) => ({ outcome, reason, ...extra })

// The refusal classes driver contract 0.1.0 defines for a record read.
const READ_CLASSES = ['format', 'structure', 'integrity', 'signature', 'decode', 'root-pk-mismatch', 'delegation-invalid']

// A driver built to an earlier revision of the contract declares the gaps (`contractGaps`). A
// difference the declared gaps explain is BLOCKED, never FAIL: the observation the contract asks
// for was not available. Anything else is judged as usual.
const gapsOf = sut => sut?.declaration?.contractGaps ?? null

// One observation of a driver response: an ERROR unless the session delivered valid JSON.
function observe(response, sut) {
  const gaps = gapsOf(sut)
  if (!response.ok && gaps?.unusableRequest && isRefusal(response.exitValue) && response.exitValue.refusal.class === gaps.unusableRequest.class) {
    return { gap: `the driver could not use the request (${response.exitValue.refusal.detail}); ${gaps.revision}` }
  }
  if (!response.ok) return { error: `${response.error}${response.raw ? `: ${response.raw}` : ''}` }
  const v = response.value
  if (v && typeof v === 'object' && !Array.isArray(v) && typeof v.unsupported === 'string') return { unsupported: v.unsupported }
  if (v && typeof v === 'object' && !Array.isArray(v) && typeof v.error === 'string' && Object.keys(v).length === 1) return { error: `driver error: ${v.error}` }
  return { value: v }
}

// A labChoice expectation never fails an implementation: a difference is reported as INCONCLUSIVE,
// because the pinned text leaves the outcome open.
function judge(diff, tag, extra = {}) {
  if (diff === null) return result('PASS', tag === 'labChoice' ? 'matches the laboratory choice' : 'matches', extra)
  if (tag === 'labChoice') return result('INCONCLUSIVE', `labChoice differs (the text leaves this open): ${diff}`, extra)
  return result('FAIL', diff, extra)
}

export class Harness {
  constructor({ root, suts, concurrency = 6, timeoutMs, transcript }) {
    this.root = root
    this.suts = suts
    this.concurrency = concurrency
    this.timeoutMs = timeoutMs
    this.transcript = transcript ?? (() => {})
    this.profile = readJson(root, PROFILE_PATH)
    this.suites = Object.fromEntries(Object.entries(SUITES).map(([id, rel]) => [id, readJson(root, rel)]))
  }

  async session(sut, requests, label) {
    const { responses, exit, stderr } = await runSession(sut.driver, requests, { timeoutMs: this.timeoutMs })
    requests.forEach((request, i) => this.transcript({ sut: sut.id, ...label, step: i, request, response: responses[i], exit: i === requests.length - 1 ? exit : undefined, stderr: i === requests.length - 1 && stderr ? stderr : undefined }))
    return responses
  }

  // A write request as one implementation receives it: `random` only for a writer that declares it.
  writeRequest(sut, request) {
    if (sut.declaration.writeOptions?.random === true) return request
    const { random, ...rest } = request
    return rest
  }

  notApplicable(sut, request) {
    for (const [option, { uses, basis }] of Object.entries(WRITE_OPTIONS)) {
      if (uses(request) && sut.declaration.writeOptions?.[option] !== true) return `${basis}; the declaration does not offer ${option} writes`
    }
    return null
  }

  // ---- VA-ENV and VA-SIG ----

  judgeWrite(sut, kase, obs) {
    if (obs.gap) return result('BLOCKED', `contract gap: ${obs.gap}`)
    if (obs.error) return result('ERROR', obs.error)
    if (obs.unsupported) return result('BLOCKED', `driver does not support ${obs.unsupported}`)
    const v = obs.value
    if (kase.expect.refusal) {
      if (isRefusal(v)) return result('PASS', 'refused, as expected (compared by presence)', { observed: { refusal: v.refusal } })
      if (typeof v?.envelope === 'string') return judge(`wrote an envelope; expected a refusal (${kase.expect.refusal.detail})`, kase.tag)
      return result('ERROR', `neither an envelope nor a refusal: ${JSON.stringify(v).slice(0, 200)}`)
    }
    if (isRefusal(v)) return judge(`refused the write: ${v.refusal.detail ?? v.refusal.class}`, kase.tag, { observed: { refusal: v.refusal } })
    if (typeof v?.envelope !== 'string' || !/^([0-9a-f]{2})+$/.test(v.envelope)) return result('ERROR', 'no envelope in the response')
    const random = sut.declaration.writeOptions?.random === true
    const checks = checkWrite(this.profile, kase, v.envelope).map(c => (c.random && !random ? { ...c, applicable: false } : c))
    const failed = checks.filter(c => c.applicable !== false && !c.ok)
    const required = failed.filter(c => c.tag === 'required')
    const extra = { checks: checks.map(c => ({ check: c.check, tag: c.tag, ok: c.ok, ...(c.applicable === false ? { applicable: false } : {}), ...(c.ok ? {} : { detail: c.detail }) })) }
    if (!random) extra.notes = ['writer declares no frozen randomness: the frozen-value checks are not applicable']
    if (required.length) return result('FAIL', `write checks failed: ${required.map(c => `${c.check} (${c.detail})`).join('; ')}`, extra)
    if (failed.length) return result('INCONCLUSIVE', `labChoice write checks differ: ${failed.map(c => c.check).join(', ')}`, extra)
    return result('PASS', `${checks.filter(c => c.applicable !== false).length} write checks pass`, extra)
  }

  judgeRead(kase, obs, sut) {
    if (obs.gap) return result('BLOCKED', `contract gap: ${obs.gap}`)
    if (obs.error) return result('ERROR', obs.error)
    if (obs.unsupported) return result('BLOCKED', `driver does not support ${obs.unsupported}`)
    const classTag = kase.classTag ?? 'required'
    const diff = compareRead(kase.expect, obs.value, classTag)
    const observed = obs.value?.verdict === 'refused' ? { verdict: 'refused', refusal: obs.value.refusal } : undefined
    const gaps = gapsOf(sut)
    if (diff && gaps) {
      const v = obs.value
      // A refusal class the revision cannot name: the actual class is outside the contract's
      // vocabulary, or the expected class is outside the revision's own.
      if (kase.expect.verdict === 'refused' && v?.verdict === 'refused' && classTag === 'required') {
        const expected = kase.expect.refusal.class
        if (!READ_CLASSES.includes(v.refusal?.class) || (gaps.refusalVocabulary && !gaps.refusalVocabulary.includes(expected))) {
          return result('BLOCKED', `contract gap: refused as ${JSON.stringify(v.refusal?.class)}; the revision's refusal classes cannot name ${expected}; ${gaps.revision}`, { observed })
        }
      }
      // Projection members the revision lacks: the rest is judged, and a match is still BLOCKED.
      if (kase.expect.verdict === 'accepted' && v?.verdict === 'accepted') {
        const missing = (gaps.missingProjectionMembers ?? []).filter(m => kase.expect[m] !== undefined && (v[m] === undefined || v[m] === null))
        const fieldMissing = (gaps.missingFieldMembers ?? []).filter(m => (kase.expect.fields ?? []).some(f => m in f) && !(v.fields ?? []).some(f => f && m in f))
        if (missing.length || fieldMissing.length) {
          const strip = o => {
            const out = Object.fromEntries(Object.entries(o).filter(([k]) => !missing.includes(k)))
            if (Array.isArray(out.fields)) out.fields = out.fields.map(f => (f && typeof f === 'object' ? Object.fromEntries(Object.entries(f).filter(([k]) => !fieldMissing.includes(k))) : f))
            return out
          }
          const lacking = [...missing, ...fieldMissing.map(m => `fields[].${m}`)].join(', ')
          const rest = compareRead(strip(kase.expect), strip(v), classTag)
          if (rest === null) return result('BLOCKED', `contract gap: the projection carries no ${lacking}; every other member matches; ${gaps.revision}`)
          return judge(rest, kase.tag, { observed, notes: [`the projection carries no ${lacking} (${gaps.revision})`] })
        }
      }
    }
    return judge(diff, kase.tag, { observed })
  }

  async recordSuite(sut, suiteId, envelopes) {
    const doc = this.suites[suiteId]
    const out = []
    await pool(casesOf(doc), this.concurrency, async kase => {
      const req = kase.request
      let res
      if (req.op === 'write') {
        // An optional provision makes only a write that must succeed not applicable; a write the
        // case expects refused is refused by every writer, whatever it offers.
        const na = kase.expect.refusal ? null : this.notApplicable(sut, req)
        if (na) res = result('NOT_APPLICABLE', na)
        else {
          const [response] = await this.session(sut, [this.writeRequest(sut, req)], { suite: suiteId, case: kase.id })
          const obs = observe(response, sut)
          res = this.judgeWrite(sut, kase, obs)
          if (obs.value && typeof obs.value.envelope === 'string') envelopes.set(kase.id, { envelope: obs.value.envelope, outcome: res.outcome })
        }
        if (!envelopes.has(kase.id)) envelopes.set(kase.id, { outcome: res.outcome, reason: res.reason })
      } else if (req.op === 'read') {
        const [response] = await this.session(sut, [req], { suite: suiteId, case: kase.id })
        res = this.judgeRead(kase, observe(response, sut), sut)
      } else {
        // `secrets`, an optional hook (ENV §4).
        const [response] = await this.session(sut, [req], { suite: suiteId, case: kase.id })
        const obs = observe(response, sut)
        if (obs.gap) res = result('BLOCKED', `contract gap: ${obs.gap}`)
        else if (obs.error) res = result('ERROR', obs.error)
        else if (obs.unsupported) res = result('BLOCKED', `optional hook ${obs.unsupported} not offered`)
        else res = judge(compareKey(kase.expect, obs.value, req).diff, kase.tag)
      }
      out.push({ id: kase.id, op: req.op, tag: kase.tag, ...(kase.classTag ? { classTag: kase.classTag } : {}), requirement: kase.requirement, ...res })
    })
    return sortById(out)
  }

  // ---- VA-KEY ----

  async keySuite(sut) {
    const doc = this.suites['VA-KEY']
    const contained = sut.declaration.containedKeys === true
    const out = []
    await pool(casesOf(doc), this.concurrency, async kase => {
      const [response] = await this.session(sut, [kase.request], { suite: 'VA-KEY', case: kase.id })
      const obs = observe(response, sut)
      let res
      if (obs.gap) res = result('BLOCKED', `contract gap: ${obs.gap}`)
      else if (obs.error) res = result('ERROR', obs.error)
      else if (obs.unsupported) res = result('BLOCKED', `driver does not support ${obs.unsupported}${kase.hook ? ' (an optional hook)' : ''}`)
      else {
        const { diff, notes } = compareKey(kase.expect, obs.value, kase.request, { contained })
        res = judge(diff, kase.tag, notes?.length ? { notes } : {})
      }
      out.push({ id: kase.id, op: kase.request.op, tag: kase.tag, requirement: kase.requirement, ...res })
    })
    return sortById(out)
  }

  // ---- VA-ADM: one process per case ----

  async admSuite(sut) {
    const doc = this.suites['VA-ADM']
    const out = []
    await pool(casesOf(doc), this.concurrency, async kase => {
      const setup = { op: 'setup', profile: PROFILE_PATH, topics: kase.setup.topics, ...(kase.setup.rules ? { rules: kase.setup.rules } : {}) }
      const requests = [setup, ...kase.steps.map(s => s.request)]
      const responses = await this.session(sut, requests, { suite: 'VA-ADM', case: kase.id })
      const steps = []
      responses.forEach((response, i) => {
        const obs = observe(response, sut)
        const expect = i === 0 ? { ok: true } : kase.steps[i - 1].expect
        if (obs.gap) steps.push(result('BLOCKED', `contract gap: ${obs.gap}`))
        else if (obs.error) steps.push(result('ERROR', obs.error))
        else if (obs.unsupported) steps.push(result('BLOCKED', `driver does not support ${obs.unsupported}`))
        else {
          const diff = compareAdmStep(expect, obs.value, requests[i])
          steps.push(diff === null ? result('PASS', 'matches') : result(kase.tag === 'labChoice' ? 'INCONCLUSIVE' : 'FAIL', diff))
        }
      })
      // A step after a BLOCKED or ERROR step depends on state the driver never built.
      const firstStop = steps.findIndex(s => s.outcome === 'BLOCKED' || s.outcome === 'ERROR')
      const counted = firstStop < 0 ? steps : steps.slice(0, firstStop + 1)
      const outcome = aggregate(counted.map(s => s.outcome))
      const worst = counted.find(s => s.outcome === outcome)
      const at = counted.indexOf(worst)
      out.push({
        id: kase.id, op: requests.slice(1).map(r => r.op).join('+'), tag: kase.tag, requirement: kase.requirement, outcome,
        reason: outcome === 'PASS' ? `${steps.length} steps match` : `step ${at} (${requests[at].op}): ${worst.reason}`,
        steps: steps.map((s, i) => ({ op: requests[i].op, outcome: s.outcome, ...(s.outcome === 'PASS' ? {} : { reason: s.reason }) }))
      })
    })
    return sortById(out)
  }

  unrunnable(suiteId) {
    return casesOf(this.suites[suiteId]).map(kase => ({ id: kase.id, tag: kase.basis ?? kase.tag, requirement: kase.requirement, outcome: 'BLOCKED', reason: UNRUNNABLE[suiteId] }))
  }

  // ---- the exchange matrix ----

  async exchange(writer, reader, envelopes) {
    const out = []
    const reads = RECORD_SUITES.flatMap(suiteId => casesOf(this.suites[suiteId]).filter(k => k.fromWrite).map(k => ({ suiteId, kase: k })))
    await pool(reads, this.concurrency, async ({ suiteId, kase }) => {
      const written = envelopes.get(kase.fromWrite)
      let res
      if (!written) res = result('NOT_APPLICABLE', `the writer did not run ${kase.fromWrite}`)
      else if (!written.envelope) {
        res = written.outcome === 'NOT_APPLICABLE'
          ? result('NOT_APPLICABLE', `the writer's ${kase.fromWrite} is not applicable`)
          : result('BLOCKED', `no envelope from the writer's ${kase.fromWrite} (${written.outcome}: ${written.reason})`)
      } else {
        const request = { ...kase.request, envelope: written.envelope }
        const [response] = await this.session(reader, [request], { suite: suiteId, case: kase.id, cell: `${writer.id}->${reader.id}` })
        res = this.judgeRead(kase, observe(response, reader), reader)
        if (written.outcome !== 'PASS') res.notes = [...(res.notes ?? []), `the writer's ${kase.fromWrite} was ${written.outcome}`]
      }
      out.push({ id: kase.id, suite: suiteId, fromWrite: kase.fromWrite, tag: kase.tag, requirement: kase.requirement, ...res })
    })
    return sortById(out)
  }

  // One repetition: every suite for every implementation, then every ordered pair of the matrix.
  async repetition() {
    const perSut = {}
    const envelopes = new Map()
    for (const sut of this.suts) {
      const own = new Map()
      envelopes.set(sut.id, own)
      perSut[sut.id] = {}
      for (const suiteId of RECORD_SUITES) perSut[sut.id][suiteId] = await this.recordSuite(sut, suiteId, own)
      perSut[sut.id]['VA-KEY'] = await this.keySuite(sut)
      perSut[sut.id]['VA-ADM'] = await this.admSuite(sut)
      for (const suiteId of Object.keys(UNRUNNABLE)) perSut[sut.id][suiteId] = this.unrunnable(suiteId)
    }
    const matrix = []
    for (const writer of this.suts) {
      for (const reader of this.suts) {
        matrix.push({ writer: writer.id, reader: reader.id, kind: writer === reader ? 'self-pair' : 'cross-implementation', cases: await this.exchange(writer, reader, envelopes.get(writer.id)) })
      }
    }
    return { suites: perSut, matrix }
  }
}

const sortById = list => list.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))

// Two clean repetitions with matching semantic projections are needed for PASS (program README,
// Outcomes and acceptance). A case whose outcome or observed projection differs between
// repetitions is INCONCLUSIVE.
export function mergeRepetitions(reps) {
  const key = r => JSON.stringify(canon({ outcome: r.outcome, reason: r.reason, observed: r.observed, checks: r.checks, steps: r.steps }))
  const merge = lists => lists[0].map((first, i) => {
    const all = lists.map(list => list[i])
    if (all.some(r => r.id !== first.id)) throw new Error('repetitions list different cases')
    if (all.every(r => key(r) === key(first))) return { ...first, repetitions: all.length }
    return { ...first, outcome: first.outcome === 'NOT_APPLICABLE' ? first.outcome : 'INCONCLUSIVE', reason: `repetitions differ: ${all.map(r => `${r.outcome} (${r.reason})`).join(' | ')}`, repetitions: all.length }
  })
  const suites = {}
  for (const sut of Object.keys(reps[0].suites)) {
    suites[sut] = {}
    for (const suiteId of Object.keys(reps[0].suites[sut])) suites[sut][suiteId] = merge(reps.map(r => r.suites[sut][suiteId]))
  }
  const matrix = reps[0].matrix.map((cell, i) => ({ ...cell, cases: merge(reps.map(r => r.matrix[i].cases)) }))
  return { suites, matrix }
}

export function summarise(list) {
  const counts = { PASS: 0, FAIL: 0, INCONCLUSIVE: 0, BLOCKED: 0, ERROR: 0, NOT_APPLICABLE: 0 }
  for (const r of list) counts[r.outcome] += 1
  return { cases: list.length, aggregate: aggregate(list.map(r => r.outcome)), counts }
}
