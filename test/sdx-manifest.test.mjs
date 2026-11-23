import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { ROOT, safeRelative } from '../src/core.mjs';
import { parseJson } from '../src/json.mjs';
import { BUILDER, COMPONENTS, DEPLOYMENT_PROFILE, HARNESS, MANIFEST, RUNS, buildSdxManifest } from '../scripts/build-sdx-manifest.mjs';

const REBUILD = `review the change, then run node ${BUILDER}`;
const read = rel => fs.readFileSync(path.join(ROOT, rel));
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const manifest = parseJson(read(MANIFEST));
const pinned = [...manifest.standards, ...manifest.suites, ...manifest.artifacts];
const pinnedPaths = new Set(pinned.map(entry => entry.path));

// Files below dir, as repository-relative paths; node_modules and dot-files are outside the tracked set.
function files(dir) {
  const out = [];
  for (const entry of fs.readdirSync(path.join(ROOT, dir), { withFileTypes: true })) {
    if (entry.name.startsWith('.') || entry.name === 'node_modules') continue;
    const rel = `${dir}/${entry.name}`;
    if (entry.isDirectory()) out.push(...files(rel));
    else if (entry.isFile()) out.push(rel);
  }
  return out;
}
const vectorFiles = () => fs.readdirSync(path.join(ROOT, 'fixtures/sdx/v1'), { withFileTypes: true })
  .filter(entry => entry.isDirectory() && fs.existsSync(path.join(ROOT, 'fixtures/sdx/v1', entry.name, 'vectors.json')))
  .map(entry => `fixtures/sdx/v1/${entry.name}/vectors.json`).sort();

test('LAB_SELF_TEST_ONLY: the SDX fixture manifest is a strict proposed self-test control document', () => {
  assert.equal(manifest.profile, 'SDX-DATA-SHARING-PROPOSAL');
  assert.equal(manifest.version, '0.1.0');
  assert.equal(manifest.status, 'PROPOSED');
  assert.equal(manifest.resultClass, 'LAB_SELF_TEST_ONLY');
  assert.ok(Array.isArray(manifest.sutRuns));
  assert.ok(manifest.remainingAdmissions.length > 0);
  assert.equal(pinnedPaths.size, pinned.length, 'each file is pinned once');
});

test('LAB_SELF_TEST_ONLY: every SDX manifest digest matches the pinned file', () => {
  for (const entry of pinned) {
    safeRelative(entry.path);
    assert.match(entry.sha256, /^[0-9a-f]{64}$/, entry.path);
    assert.ok(fs.existsSync(path.join(ROOT, entry.path)), `${entry.path} is pinned but missing; ${REBUILD}`);
    assert.equal(sha256(read(entry.path)), entry.sha256, `${entry.path} differs from its pinned digest; ${REBUILD}`);
  }
});

test('LAB_SELF_TEST_ONLY: the stored SDX manifest equals a fresh build', () => {
  assert.equal(read(MANIFEST).toString('utf8'), buildSdxManifest(ROOT), `${MANIFEST} is stale; ${REBUILD}`);
});

test('LAB_SELF_TEST_ONLY: every SDX vector suite is pinned, self-test only and described exactly', () => {
  assert.deepEqual(manifest.suites.map(suite => suite.path).sort(), vectorFiles(), `vector suites and ${MANIFEST} differ; ${REBUILD}`);
  const profile = parseJson(read(manifest.program));
  const requirementIds = new Set(profile.requirements.map(row => row.id));
  const authored = new Map(profile.suites.filter(suite => suite.state === 'authored').map(suite => [suite.id, suite]));
  assert.equal(authored.size, manifest.suites.length, 'program profile lists every authored suite');
  for (const suite of manifest.suites) {
    const vectors = parseJson(read(suite.path));
    assert.equal(vectors.claim, 'LAB_SELF_TEST_ONLY', suite.path);
    assert.equal(vectors.suite, suite.id, suite.path);
    assert.equal(vectors.status, suite.status, suite.path);
    assert.deepEqual(vectors.requirements, suite.requirements, suite.path);
    assert.equal((vectors.cases ?? vectors.vectors).length, suite.cases, suite.path);
    for (const id of suite.requirements) assert.ok(requirementIds.has(id), `${suite.id} cites unknown requirement ${id}`);
    const listed = authored.get(suite.id);
    assert.ok(listed, `${suite.id} missing from the program profile`);
    assert.equal(listed.path, suite.path);
    assert.equal(listed.cases, suite.cases, `${suite.id} case count differs from the program profile`);
    assert.deepEqual(listed.requirements, suite.requirements);
  }
});

test('LAB_SELF_TEST_ONLY: every SDX fixture, checker, test, generator and builder file is pinned', () => {
  const required = [
    ...files('fixtures/sdx/v1').filter(rel => rel !== MANIFEST),
    ...files('src/sdx'),
    'src/portability/brc39-recipient.mjs',
    ...fs.readdirSync(path.join(ROOT, 'test')).filter(name => /^sdx-.*\.test\.mjs$/.test(name)).map(name => `test/${name}`),
    'test/brc39-recipient.test.mjs',
    ...fs.readdirSync(path.join(ROOT, 'test')).filter(name => /^(test_)?sdx_.*\.py$/.test(name)).map(name => `test/${name}`),
    ...COMPONENTS.flatMap(component => files(`components/sdx/${component}`)),
    DEPLOYMENT_PROFILE,
    BUILDER,
    ...files(HARNESS[0]),
    HARNESS[1],
    ...(fs.existsSync(path.join(ROOT, RUNS)) ? files(RUNS) : [])
  ];
  for (const rel of required) assert.ok(pinnedPaths.has(rel), `${rel} is not pinned in ${MANIFEST}; ${REBUILD}`);
});

test('LAB_SELF_TEST_ONLY: every SDX run record is a self-test record whose transcript and counts are its own', () => {
  const outcomes = ['PASS', 'FAIL', 'BLOCKED', 'INCONCLUSIVE', 'ERROR', 'NOT_APPLICABLE'];
  for (const run of manifest.sutRuns) {
    const record = parseJson(read(run.record));
    assert.equal(record.schema, 'tpnil-sdx-run-record@0.1.0', run.record);
    assert.equal(record.claim, 'LAB_SELF_TEST_ONLY', run.record);
    assert.match(record.statement, /not a conformance result/);
    assert.equal(record.program.status, 'PROPOSED');
    assert.equal(sha256(read(run.transcript)), record.transcript.sha256, `${run.transcript} differs from the digest its record names`);
    for (const [sut, suites] of Object.entries(record.results.suites)) {
      for (const [suite, list] of Object.entries(suites)) {
        const counts = Object.fromEntries(outcomes.map(o => [o, list.filter(r => r.outcome === o).length]));
        assert.deepEqual({ ...record.summary.suites[sut][suite].counts }, counts, `${run.record}: ${sut} ${suite}`);
        for (const r of list) assert.ok(outcomes.includes(r.outcome) && typeof r.reason === 'string' && r.reason.length > 0, `${run.record}: ${sut} ${r.id}`);
      }
    }
    for (const cell of record.results.matrix) assert.ok(cell.cases.every(r => outcomes.includes(r.outcome) && r.reason), `${run.record}: ${cell.writer}->${cell.reader}`);
    for (const impl of record.implementations) assert.equal(impl.declaration.claim, 'LAB_SELF_TEST_ONLY', `${run.record}: ${impl.id}`);
  }
});
