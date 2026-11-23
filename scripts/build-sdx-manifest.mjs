// Rebuilds fixtures/sdx/v1/manifest.json, the digest manifest of the proposed SDX
// data-sharing program. The manifest pins the SDX text snapshots, the imported SDX
// suites, the draft statements, the laboratory deployment profile, every authored
// vector suite, and the checkers, tests, generator files and proposal documents
// that produce or judge them.
//
//   node scripts/build-sdx-manifest.mjs           write the manifest
//   node scripts/build-sdx-manifest.mjs --check   exit 1 if the stored manifest is stale
//
// The builder uses Node.js built-in modules only. Its output is deterministic: paths
// are listed in a fixed order and serialised as two-space JSON with a final newline.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseJson } from '../src/json.mjs';

export const MANIFEST = 'fixtures/sdx/v1/manifest.json';
export const BUILDER = 'scripts/build-sdx-manifest.mjs';
const PROGRAM = 'programs/proposals/sdx-data-sharing/0.1.0';
export const RUNS = `${PROGRAM}/runs`;
export const HARNESS = ['src/sdx/harness', 'scripts/run-sdx-suts.mjs'];
export const COMPONENTS = ['b39r', 'proof', 'p256', 'envelope', 'key', 'admission'];
export const DEPLOYMENT_PROFILE = 'fixtures/sdx/v1/deployment-profile.json';
const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

const byCodePoint = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

export function buildSdxManifest(root = ROOT) {
  const abs = rel => path.join(root, rel);
  const bytes = rel => fs.readFileSync(abs(rel));
  const sha256 = rel => createHash('sha256').update(bytes(rel)).digest('hex');
  const json = rel => parseJson(bytes(rel));
  const isFile = rel => fs.existsSync(abs(rel)) && fs.statSync(abs(rel)).isFile();
  const list = (dir, accept) => fs.readdirSync(abs(dir)).filter(name => !name.startsWith('.') && accept(name))
    .sort(byCodePoint).map(name => `${dir}/${name}`);
  const entry = (rel, fields) => {
    if (!isFile(rel)) throw new Error(`Missing pinned file ${rel}`);
    return { ...fields, path: rel, sha256: sha256(rel) };
  };
  // Files of dir first, then each subdirectory in order; node_modules and dot-files are excluded.
  const walk = dir => {
    const names = fs.readdirSync(abs(dir), { withFileTypes: true }).filter(item => !item.name.startsWith('.'))
      .sort((a, b) => byCodePoint(a.name, b.name));
    const files = names.filter(item => item.isFile()).map(item => `${dir}/${item.name}`);
    const dirs = names.filter(item => item.isDirectory() && item.name !== 'node_modules');
    return [...files, ...dirs.flatMap(item => walk(`${dir}/${item.name}`))];
  };

  const standards = [];
  for (const text of json('fixtures/sdx/v1/standards/text/index.json').texts) {
    standards.push(entry(text.path, { id: text.id, kind: 'sdx-text' }));
  }
  standards.push(entry('fixtures/sdx/v1/standards/text/index.json', { id: 'sdx-text-index', kind: 'index' }));
  for (const rel of list('fixtures/sdx/v1/standards/cbor-det-v1', name => name.endsWith('.json'))) {
    const name = path.basename(rel, '.json');
    standards.push(entry(rel, name === 'index'
      ? { id: 'sdx-published-suite-index', kind: 'index' }
      : { id: `sdx-${name}`, kind: 'sdx-published-suite' }));
  }
  for (const statement of json('fixtures/sdx/v1/standards/draft-statements/index.json').statements) {
    standards.push(entry(statement.path, { id: statement.id, kind: 'draft-statement' }));
  }
  standards.push(entry('fixtures/sdx/v1/standards/draft-statements/index.json', { id: 'draft-statement-index', kind: 'index' }));

  const suites = list('fixtures/sdx/v1', name => name !== 'standards' && isFile(`fixtures/sdx/v1/${name}/vectors.json`))
    .map(dir => `${dir}/vectors.json`)
    .map(rel => {
      const vectors = json(rel);
      if (vectors.claim !== 'LAB_SELF_TEST_ONLY') throw new Error(`${rel} is not labelled LAB_SELF_TEST_ONLY`);
      const cases = vectors.cases ?? vectors.vectors;
      if (!Array.isArray(cases)) throw new Error(`${rel} has no case list`);
      return { id: vectors.suite, status: vectors.status, path: rel, sha256: sha256(rel), requirements: vectors.requirements, cases: cases.length };
    });

  const artifacts = [];
  const groups = [
    ['checker', [...list('src/sdx', name => name.endsWith('.mjs')), 'src/portability/brc39-recipient.mjs']],
    ['deployment-profile', [DEPLOYMENT_PROFILE]],
    ['test', [...list('test', name => /^sdx-.*\.test\.mjs$/.test(name)), 'test/brc39-recipient.test.mjs', ...list('test', name => /^(test_)?sdx_.*\.py$/.test(name))]],
    ['generator', COMPONENTS.flatMap(component => walk(`components/sdx/${component}`))],
    ['harness', [...walk(HARNESS[0]), HARNESS[1]]],
    ['program', ['README.md', 'AGENTS.md', 'profile.json', 'coverage.json', 'promotion.md', 'driver-contract.md', 'run-record.schema.json'].map(name => `${PROGRAM}/${name}`)],
    ['run', fs.existsSync(abs(RUNS)) ? walk(RUNS) : []],
    ['builder', [BUILDER]],
    ['licence-reference', ['LICENSES/SDX-Specification-License-1.0.reference.txt']]
  ];
  for (const [role, paths] of groups) for (const rel of paths) artifacts.push(entry(rel, { role }));

  const manifest = {
    profile: 'SDX-DATA-SHARING-PROPOSAL',
    version: '0.1.0',
    status: 'PROPOSED',
    resultClass: 'LAB_SELF_TEST_ONLY',
    program: `${PROGRAM}/profile.json`,
    standards,
    suites,
    artifacts,
    oracleRuntime: {
      node: '24.22.1',
      python: 'python3 standard library',
      checkers: 'Node.js built-in modules only'
    },
    generatorRuntime: {
      node: '24.22.1',
      npmLockfiles: COMPONENTS.map(component => `components/sdx/${component}/package-lock.json`),
      go: 'components/sdx/p256/grind/go.mod declares go 1.22 and no module dependencies'
    },
    syntheticFixtures: {
      keys: 'public labelled test keys and fixed test roots',
      chain: 'pinned synthetic regtest-difficulty headers; nothing broadcast',
      validFunding: false,
      containsPersonalData: false
    },
    // Laboratory self-test runs of SDX implementations through the driver contract
    // (scripts/run-sdx-suts.mjs). Each is LAB_SELF_TEST_ONLY and claims no conformance.
    sutRuns: (fs.existsSync(abs(RUNS)) ? list(RUNS, name => isFile(`${RUNS}/${name}/record.json`)) : []).map(dir => {
      const record = json(`${dir}/record.json`);
      if (record.claim !== 'LAB_SELF_TEST_ONLY') throw new Error(`${dir}/record.json is not labelled LAB_SELF_TEST_ONLY`);
      return {
        runId: record.runId,
        record: `${dir}/record.json`,
        transcript: `${dir}/${record.transcript.path}`,
        repetitions: record.repetitions,
        implementations: record.implementations.map(i => ({ id: i.id, commit: i.revision.commit, clean: i.revision.clean })),
        aggregate: record.summary.aggregate
      };
    }),
    remainingAdmissions: [
      'TPNIL program identifier assignment',
      'SDX publication of docv2-envelope, dual-curve, placement, utxo-chaining, overlay-binding and cross-domain-refs',
      'SDX publication of the reader, writer and recorder port contracts',
      'BRC-process adoption of the companion drafts',
      'authoring of the remaining Phase A suites VA-GRANT and VA-ROT',
      'replacement of the laboratory stand-in VA-ADM by SDX\'s overlay-binding suite',
      'two independent admitted SDX implementations and SDX intake'
    ]
  };
  const text = `${JSON.stringify(manifest, null, 2)}\n`;
  parseJson(text); // The manifest is a TPNIL-JSON-1 control document.
  return text;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const args = process.argv.slice(2);
  if (args.length > 1 || (args.length === 1 && args[0] !== '--check')) {
    console.error('Usage: node scripts/build-sdx-manifest.mjs [--check]');
    process.exit(2);
  }
  const text = buildSdxManifest();
  const target = path.join(ROOT, MANIFEST);
  const current = fs.existsSync(target) ? fs.readFileSync(target, 'utf8') : null;
  if (args[0] === '--check') {
    if (current !== text) {
      console.error(`${MANIFEST} is stale; review the changed files, then run node ${BUILDER}`);
      process.exit(1);
    }
    console.log(`${MANIFEST} is current`);
  } else {
    if (current !== text) fs.writeFileSync(target, text);
    console.log(`${current === text ? 'unchanged' : 'wrote'}: ${MANIFEST}`);
  }
}
