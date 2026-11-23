#!/usr/bin/env node
// LAB_SELF_TEST_ONLY qualification driver for the SDX harness. It is not an SDX implementation: it
// answers each request with the expectation the suites publish for it, found by matching the request
// against the suite cases, so the harness can be shown to pass what matches and to fail, block or
// error where it should. Node.js built-ins only.
//
//   ECHO_MODE=expected   answer the published expectation (the default)
//   ECHO_MODE=flip       answer a read with the opposite verdict and a write with the other outcome
//   ECHO_MODE=unsupported  answer every request {"unsupported": <op>}
//   ECHO_MODE=garbage    answer a line that is not JSON
import fs from 'node:fs'
import path from 'node:path'
import readline from 'node:readline'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..')
const SUITES = ['va-env', 'va-sig', 'va-key', 'va-adm']
const MODE = process.env.ECHO_MODE ?? 'expected'

const canon = v => (Array.isArray(v) ? v.map(canon) : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map(k => [k, canon(v[k])])) : v)
const key = v => JSON.stringify(canon(v))

// Every published request with its expectation. A read of a known-answer envelope and a read the
// harness reruns on an echoed envelope are the same request, because the echoed envelope is the
// known answer. A VA-ADM case is matched by its whole session: setup, then every step.
const answers = new Map()
const sessions = new Map()
for (const name of SUITES) {
  const doc = JSON.parse(fs.readFileSync(path.join(ROOT, 'fixtures/sdx/v1', name, 'vectors.json'), 'utf8'))
  for (const kase of doc.cases) {
    if (kase.steps) {
      const setup = { topics: kase.setup.topics, rules: kase.setup.rules ?? null }
      sessions.set(key([setup, ...kase.steps.map(s => s.request)]), [{ ok: true }, ...kase.steps.map(s => s.expect)])
      continue
    }
    const { random, ...rest } = kase.request
    answers.set(key(rest), kase.expect)
    answers.set(key(kase.request), kase.expect)
  }
}

function flip(req, expect) {
  if (req.op === 'read') return expect.verdict === 'accepted' ? { verdict: 'refused', refusal: { class: 'integrity', detail: 'flipped' }, fields: [] } : { tier: 'audit', verdict: 'accepted', aid: null, fields: [] }
  if (req.op === 'write') return expect.refusal ? { envelope: 'a0' } : { refusal: { class: 'write-refused', detail: 'flipped' } }
  if (req.op === 'setup') return expect
  return { refusal: { class: 'flipped', detail: 'flipped' } }
}

function answerAll(requests) {
  if (MODE === 'unsupported') return requests.map(r => ({ unsupported: r.op }))
  let expects
  if (requests[0]?.op === 'setup') {
    const setup = { topics: requests[0].topics, rules: requests[0].rules ?? null }
    expects = sessions.get(key([setup, ...requests.slice(1)])) ?? requests.map(() => ({ error: 'no published case matches this session' }))
  } else {
    expects = requests.map(r => answers.get(key(r)) ?? { error: 'no published case matches this request' })
  }
  return MODE === 'flip' ? expects.map((e, i) => (e.error ? e : flip(requests[i], e))) : expects
}

// The contract lets a driver answer once standard input closes, in order.
const requests = []
for await (const line of readline.createInterface({ input: process.stdin, crlfDelay: Infinity })) if (line.trim() !== '') requests.push(JSON.parse(line))
for (const response of answerAll(requests)) process.stdout.write(MODE === 'garbage' ? 'not json\n' : `${JSON.stringify(response)}\n`)
