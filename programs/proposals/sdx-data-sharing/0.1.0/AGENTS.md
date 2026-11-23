# AGENTS.md: running an SDX implementation through the suites

This guide is for people and AI agents who connect an SDX v0.1 implementation to the vector suites of the proposed SDX data-sharing program. The repository's root `AGENTS.md` also applies.

Run every command from the root of a TPNIL checkout that contains this program. Results are `LAB_SELF_TEST_ONLY`. A run records what was executed and what each case observed. It is not a conformance result and issues no certification.

## What a run does

The harness, `scripts/run-sdx-suts.mjs`, starts the implementation's driver and sends it every case of the suites. It compares each response with the case's expectation. With two implementations, each one also reads the records the other wrote. The [driver contract](driver-contract.md) defines every request and response.

| Suite | Cases | Operations | Optional hooks |
| --- | --- | --- | --- |
| VA-KEY | 69 | `split`, `derive`, `symmetric`, `validate`, `profile` | `offset` |
| VA-ENV | 95 | `write`, `read` | `secrets` |
| VA-SIG | 32 | `write`, `read` | |
| VA-ADM | 51 | `setup`, `submit`, `lookup` | `fault` |
| VA-ENC, VA-ANC | 106 | none | |

VA-ENC and VA-ANC are always BLOCKED. The contract has no operation for them.

## 1. Check the setup

- Use Node.js 24.22.1, the version in `.nvmrc`.
- The harness uses Node.js built-ins only. It needs no `npm install`.

```sh
node --version                          # v24.22.1
node --test test/sdx-harness.test.mjs   # qualifies the harness; every test passes
```

## 2. Write a driver

A driver is a command in any language. It reads one JSON request per line on standard input. It writes one JSON response per line on standard output, in the same order, until standard input closes.

Start from this skeleton. It answers every operation as unsupported.

```js
// driver.mjs: SDX laboratory driver contract 0.1.0
import readline from 'node:readline'

const handlers = {
  // split: async req => ({ secp256k1Seed: '<hex>', p256Seed: '<hex>' }),
  // read: async req => ({ tier, verdict, aid, hdr, fields, signature }),
}

for await (const line of readline.createInterface({ input: process.stdin, crlfDelay: Infinity })) {
  if (line.trim() === '') continue
  const req = JSON.parse(line)
  const handler = handlers[req.op]
  const res = handler ? await handler(req) : { unsupported: req.op }
  process.stdout.write(`${JSON.stringify(res)}\n`)
}
```

The harness holds every driver to these rules:

- Write exactly one response line per request. Write logs to standard error only. The transcript keeps the first 4000 characters of standard error.
- Answer `{"unsupported": "<op>"}` for an operation that is not implemented. The case is BLOCKED.
- Answer a refusal as an ordinary response, for example `{"refusal": {"class": "key", "detail": "<text>"}}`. The contract lists the refusal classes.
- A crash, a non-zero exit status, a missing response, a line that is not JSON or a run over 120 seconds is ERROR.
- The driver's working directory is the checkout root. The `profile` member of a request, `fixtures/sdx/v1/deployment-profile.json`, opens as given.
- Each case runs in a new process. A VA-ADM case sends `setup` and all its steps to one process, and that process starts with an empty admission service and index. Keep no state between processes.
- Byte strings are lowercase hexadecimal. A byte string inside a record value is `{"$bytes": "<hex>"}`.

## 3. Write a declaration

The declaration tells the harness how to build and start the driver, and which optional provisions the implementation offers. Fix it before the run. Keep it with the implementation.

```json
{
  "schema": "tpnil-sdx-sut-declaration@0.1.0",
  "claim": "LAB_SELF_TEST_ONLY",
  "id": "my-sdx",
  "implementation": {
    "name": "my-sdx",
    "version": "0.1.0",
    "language": "JavaScript (Node.js 24)",
    "statement": "Implements SDX v0.1 (Draft); conformance not demonstrated"
  },
  "driver": {
    "argv": ["node", "{source}/driver.mjs"],
    "build": []
  },
  "contract": "0.1.0",
  "roles": ["writer", "reader", "verifier"],
  "writeOptions": { "random": false, "convergent": false, "writerBlind": false },
  "containedKeys": false
}
```

- `{source}` is the implementation's checkout, given on the command line. `{build}` is a new temporary folder. Use them in `argv` and `build`, because the driver starts in the TPNIL checkout.
- `build` lists commands to run in `{source}` before the run, each as an argument list. A compiled driver builds into `{build}`, for example:

  ```json
  "driver": {
    "argv": ["{build}/driver"],
    "build": [
      ["go", "build", "-o", "{build}/driver", "./cmd/driver"]
    ]
  }
  ```

- `writeOptions` lists the optional write provisions. `random` takes the contract's frozen random values. `convergent` builds convergent fields (ENV §4). `writerBlind` builds writer-blind fields (ENV §9.1). A write case that needs a provision the declaration does not offer is NOT_APPLICABLE.
- `containedKeys: true` declares that keys never leave the implementation's key store. `split` may then answer `{"secp256k1Public", "p256Public"}`, and `derive` may omit `privateKey`.
- `roles` takes `writer`, `reader`, `verifier`, `runtime`, `admission-service` and `wallet-substrate`. `operations` and `notes` are optional.

The schema is `$defs/declaration` in [`run-record.schema.json`](run-record.schema.json). The pilot declarations in [`runs/declarations/`](runs/declarations/) are complete examples.

## 4. Run

```sh
node scripts/run-sdx-suts.mjs \
  --sut /path/to/my-sdx/sdx-declaration.json=/path/to/my-sdx \
  --repeat 1 --run-id dev --out ../sdx-runs
```

- `--sut <declaration>=<checkout>` names one implementation. Repeat it to add another.
- Make `<checkout>` a git working tree. The run record names its commit and whether it had uncommitted changes. Outside git the run still works, but git prints `not a git repository` and the record has no revision.
- `--repeat 1` is enough while developing. A run for the record keeps the default of 2. A case whose outcome differs between repetitions is INCONCLUSIVE.
- `--out` keeps the run outside this folder. Without it, the run is written to `runs/`, which the fixture manifest pins.
- `--concurrency <n>` sets how many driver processes run at once. The default is 6.

The run prints a summary per suite. With the skeleton driver, every case is BLOCKED except those that need a convergent or writer-blind write, which are NOT_APPLICABLE. That result shows the declaration and the driver work.

## 5. Read the results

The run writes `<out>/<run-id>/record.json`, with every outcome, and `transcript.jsonl`, with every request and response.

List the cases that did not pass, leaving out VA-ENC and VA-ANC:

```sh
node -e '
const r = JSON.parse(require("node:fs").readFileSync(process.argv[1], "utf8"))
for (const [sut, suites] of Object.entries(r.results.suites))
  for (const [suite, cases] of Object.entries(suites))
    if (suite !== "VA-ENC" && suite !== "VA-ANC")
      for (const c of cases) if (c.outcome !== "PASS") console.log(sut, c.id, c.op, c.outcome, c.reason)
for (const cell of r.results.matrix)
  for (const c of cell.cases) if (c.outcome !== "PASS") console.log(`${cell.writer}->${cell.reader}`, c.id, c.outcome, c.reason)
' ../sdx-runs/dev/record.json
```

Show a case's request and expectation:

```sh
node -e '
const id = process.argv[1], suite = id.split("-").slice(0, 2).join("-").toLowerCase()
const v = JSON.parse(require("node:fs").readFileSync(`fixtures/sdx/v1/${suite}/vectors.json`, "utf8"))
console.log(JSON.stringify((v.cases ?? v.vectors).find(c => c.id === id), null, 2))
' VA-KEY-001
```

Show what the harness sent for that case and what the driver answered:

```sh
grep '"case":"VA-KEY-001"' ../sdx-runs/dev/transcript.jsonl
```

| Outcome | Meaning |
| --- | --- |
| PASS | The response matched the expectation. |
| FAIL | The response differed. `reason` says how. |
| BLOCKED | The driver answered `unsupported`, or the contract has no operation for the suite. |
| ERROR | The driver crashed, exited non-zero, timed out, missed a response or wrote a line that is not JSON. Its standard error is in the transcript. |
| INCONCLUSIVE | A `labChoice` case, where the text leaves the outcome open, came out differently. Or the outcome differed between repetitions. |
| NOT_APPLICABLE | The case needs a write provision the declaration does not offer. |

A refusal's `detail` is never compared. Its `class` is compared only where the case requires it.

## 6. Implement in this order

1. **VA-KEY.** `split`, `derive`, `validate`, `profile` and `symmetric`. They are stateless, and every record depends on correct keys.
2. **`read`.** The VA-ENV and VA-SIG read cases carry ready-made envelopes.
3. **`write`.** The harness checks each written envelope with the suite's write checks. Then every implementation in the run reads it, and those reads are the matrix cells.
4. **VA-ADM.** `setup`, `submit` and `lookup`. Transactions are raw, and their parents are in the suite file.

The hooks `secrets`, `offset` and `fault` are optional. Answer `unsupported` for a hook the implementation does not offer.

## 7. Run against a second implementation

One `--sut` gives one self-pair: the implementation reads its own records. A second `--sut` adds the cross-implementation cells, where each implementation reads the other's records. The pilot declarations in `runs/declarations/` name their sources. With a checkout of one of them, pass it as the second `--sut`:

```sh
node scripts/run-sdx-suts.mjs \
  --sut /path/to/my-sdx/sdx-declaration.json=/path/to/my-sdx \
  --sut programs/proposals/sdx-data-sharing/0.1.0/runs/declarations/sdxgo.json=/path/to/sdx-go \
  --run-id dev-pair --out ../sdx-runs
```

Building `sdx-go` needs Go.

## Testing a running service

A driver can forward each request to a deployed service instead of calling a library. The service must then accept what the suites send:

- imported root keying material (`rootIkm`);
- the laboratory deployment profile, `tpnil-sdx-lab:v1`;
- for VA-ADM, the case's business rules in `setup`, and raw transactions. A driver for an engine that requires proofs wraps them for its controlled network.

Each VA-ADM `setup` needs an empty admission service and index of its own, and cases run in parallel. Use a test instance and synthetic data only. Lower `--concurrency` if the service limits requests.

## Rules

- Never edit a vector, a checker or an expectation to make a case pass. Fix the implementation. When a case seems wrong, record its ID and the SDX clause it rests on.
- Keep development runs out of `runs/`. A run there changes the fixture manifest and becomes part of the proposal.
- Results describe one configuration of one implementation. They claim no conformance and no certification.
- Use synthetic data only.

## Checking the laboratory itself

These commands check the suites, the checkers and the harness. They do not run an implementation. `npm test` needs the checkout outside any folder that has a `vite.config.ts`.

```sh
npm ci
npm test && npm run check && npm run qualify:standards
python3 -m unittest discover -s test -p 'test_*.py'
node scripts/build-sdx-manifest.mjs --check
(cd components/sdx/<component> && npm ci && node generate.mjs --check)   # each SDX component
```
