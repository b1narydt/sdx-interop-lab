// Runs SDX v0.1 implementations through the laboratory driver contract and writes a run record of
// the proposed SDX data-sharing program. LAB_SELF_TEST_ONLY: it issues no certification and no
// conformance claim; it records what was executed and what each case observed.
//
//   node scripts/run-sdx-suts.mjs --sut <declaration.json>=<source checkout> [--sut ...]
//        [--repeat 2] [--concurrency 6] [--run-id <id>] [--out <dir>]
//
// A declaration (schema tpnil-sdx-sut-declaration@0.1.0) names the implementation, its driver
// command and its optional provisions, fixed before execution. `{source}` in its build and driver
// commands is the local checkout given after `=`, and `{build}` a fresh temporary directory; the
// run record keeps the declaration as written and never a local path. The record and a transcript
// of every driver request and response go to <out>/<run-id>/ (by default under the program's
// runs/ folder). Node.js built-ins only.
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { Harness, HARNESS_VERSION, PROFILE_PATH, SUITES, mergeRepetitions, summarise, aggregate } from '../src/sdx/harness/run.mjs'

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const PROGRAM = 'programs/proposals/sdx-data-sharing/0.1.0'
const CONTRACT = `${PROGRAM}/driver-contract.md`
const HARNESS_FILES = ['src/sdx/harness/driver.mjs', 'src/sdx/harness/compare.mjs', 'src/sdx/harness/run.mjs', 'scripts/run-sdx-suts.mjs', 'src/sdx/env.mjs', 'src/sdx/ec-p256.mjs', 'src/sdx/cbor-det.mjs', 'src/sdx/lzma.mjs']
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex')
const fileSha = rel => sha256(fs.readFileSync(path.join(ROOT, rel)))
const DIGEST_OVER = 256

function parseArgs(argv) {
  const o = { suts: [], repeat: 2, concurrency: 6, out: path.join(ROOT, PROGRAM, 'runs') }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    const next = () => { if (i + 1 >= argv.length) usage(); return argv[++i] }
    if (a === '--sut') { const [decl, source] = next().split('='); if (!source) usage(); o.suts.push({ decl: path.resolve(decl), source: path.resolve(source) }) }
    else if (a === '--repeat') o.repeat = Number(next())
    else if (a === '--concurrency') o.concurrency = Number(next())
    else if (a === '--run-id') o.runId = next()
    else if (a === '--out') o.out = path.resolve(next())
    else usage()
  }
  if (o.suts.length === 0 || !Number.isInteger(o.repeat) || o.repeat < 1) usage()
  return o
}
function usage() {
  console.error('usage: node scripts/run-sdx-suts.mjs --sut <declaration.json>=<source checkout> [--sut ...] [--repeat 2] [--concurrency 6] [--run-id <id>] [--out <dir>]')
  process.exit(2)
}

const git = (cwd, ...args) => { try { return execFileSync('git', ['-C', cwd, ...args], { encoding: 'utf8' }).trim() } catch { return null } }

// The implementation's identity: its repository commit, the last commit that changed its folder,
// and whether the folder differs from that commit.
function revision(source) {
  return {
    commit: git(source, 'rev-parse', 'HEAD'),
    lastChange: git(source, 'log', '-1', '--format=%H', '--', '.'),
    path: (git(source, 'rev-parse', '--show-prefix') ?? '').replace(/\/$/, ''),
    clean: git(source, 'status', '--porcelain', '--', '.') === ''
  }
}

const fill = (text, vars) => text.replace(/\{(source|build)\}/g, (_, k) => vars[k])

function prepare({ decl, source }) {
  const declaration = JSON.parse(fs.readFileSync(decl, 'utf8'))
  if (declaration.schema !== 'tpnil-sdx-sut-declaration@0.1.0') throw new Error(`${decl}: not a tpnil-sdx-sut-declaration@0.1.0`)
  const build = fs.mkdtempSync(path.join(os.tmpdir(), `sdx-sut-${declaration.id}-`))
  const vars = { source, build }
  for (const step of declaration.driver.build ?? []) {
    const [cmd, ...args] = step.map(part => fill(part, vars))
    execFileSync(cmd, args, { cwd: source, stdio: ['ignore', 'ignore', 'inherit'] })
  }
  return {
    id: declaration.id,
    declaration,
    revision: revision(source),
    driver: { argv: declaration.driver.argv.map(part => fill(part, vars)), cwd: ROOT }
  }
}

// Hex strings longer than DIGEST_OVER characters are replaced by their digest. A written envelope,
// which the matrix reads back, is kept whole.
function compact(value) {
  if (typeof value === 'string' && value.length > DIGEST_OVER && /^[0-9a-f]+$/.test(value)) return { sha256: sha256(Buffer.from(value, 'hex')), bytes: value.length / 2 }
  if (Array.isArray(value)) return value.map(compact)
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, compact(v)]))
  return value
}
function transcriptLine(entry) {
  const line = compact(entry)
  const envelope = entry.request?.op === 'write' ? entry.response?.value?.envelope : undefined
  if (typeof envelope === 'string') line.response.value.envelope = envelope
  return line
}

async function main() {
  const opts = parseArgs(process.argv.slice(2))
  const suts = opts.suts.map(prepare)
  const runId = opts.runId ?? `run-${new Date().toISOString().replace(/[-:]/g, '').replace(/\..*/, '')}`
  const dir = path.join(opts.out, runId)
  fs.mkdirSync(dir, { recursive: true })
  const transcriptPath = path.join(dir, 'transcript.jsonl')
  const transcript = fs.openSync(transcriptPath, 'w')
  let repetition = 0
  const write = entry => fs.writeSync(transcript, `${JSON.stringify(transcriptLine({ repetition, ...entry }))}\n`)

  const started = new Date().toISOString()
  const harness = new Harness({ root: ROOT, suts, concurrency: opts.concurrency, transcript: write })
  const reps = []
  for (repetition = 1; repetition <= opts.repeat; repetition++) {
    console.error(`repetition ${repetition} of ${opts.repeat}`)
    reps.push(await harness.repetition())
  }
  fs.closeSync(transcript)
  const merged = mergeRepetitions(reps)

  const suiteSummary = {}
  for (const [sutId, suites] of Object.entries(merged.suites)) {
    suiteSummary[sutId] = Object.fromEntries(Object.entries(suites).map(([id, list]) => [id, summarise(list)]))
  }
  const matrixSummary = merged.matrix.map(cell => ({ writer: cell.writer, reader: cell.reader, kind: cell.kind, ...summarise(cell.cases) }))
  const record = {
    schema: 'tpnil-sdx-run-record@0.1.0',
    claim: 'LAB_SELF_TEST_ONLY',
    statement: 'A laboratory self-test run of the proposed SDX data-sharing program. It records what was executed and what each case observed. It is not a conformance result, issues no certification and confers no right to use the SDX Protocol name or marks.',
    runId,
    program: { id: 'sdx-data-sharing@0.1.0', status: 'PROPOSED', programIdentifier: null, profile: `${PROGRAM}/profile.json` },
    contract: { version: '0.1.0', path: CONTRACT, sha256: fileSha(CONTRACT) },
    deploymentProfile: { id: harness.profile.profile, path: PROFILE_PATH, sha256: fileSha(PROFILE_PATH) },
    suites: Object.entries(SUITES).map(([id, rel]) => ({ id, path: rel, sha256: fileSha(rel), cases: (harness.suites[id].cases ?? harness.suites[id].vectors).length })),
    harness: { version: HARNESS_VERSION, files: HARNESS_FILES.map(rel => ({ path: rel, sha256: fileSha(rel) })) },
    runtime: { node: process.versions.node, platform: `${process.platform}-${process.arch}` },
    started,
    finished: new Date().toISOString(),
    repetitions: opts.repeat,
    implementations: suts.map(s => ({ id: s.id, declaration: s.declaration, revision: s.revision })),
    summary: {
      suites: suiteSummary,
      matrix: matrixSummary,
      aggregate: aggregate([...Object.values(suiteSummary).flatMap(s => Object.values(s).map(x => x.aggregate)), ...matrixSummary.map(c => c.aggregate)])
    },
    results: merged,
    transcript: { path: 'transcript.jsonl', sha256: sha256(fs.readFileSync(transcriptPath)), note: `every driver request and response of every repetition, one JSON object per line; hex strings over ${DIGEST_OVER} characters are replaced by their SHA-256, except written envelopes` }
  }
  fs.writeFileSync(path.join(dir, 'record.json'), `${JSON.stringify(record, null, 2)}\n`)
  console.log(JSON.stringify({ runId, dir: path.relative(ROOT, dir), summary: record.summary }, null, 2))
}

main().catch(error => { console.error(error); process.exit(1) })
