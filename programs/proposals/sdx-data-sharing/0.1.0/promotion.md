# Promotion of the SDX data-sharing proposal

The [SDX data-sharing proposal](README.md) 0.1.0 is outside the program register. This record lists the decisions TPNIL maintainers make and the repository changes that follow if the proposal becomes an assigned program. It changes nothing by itself. `ISI-N` below stands for the identifier the maintainers assign.

## Maintainer decisions

1. **Program identifier.** Maintainers assign the identifier and record the decision, with rationale, participants, dissent, evidence and affected requirements, in the [decision register](../../../../docs/decisions.md) as its next entry (D-021 follows the current register) and in a program decision record under `programs/ISI-N/decisions/`.
2. **Mandatory set.** The eight Phase A rows form the initial mandatory set. Companion rows remain PROPOSED in the proposal profile and enter the catalog only after their BRC drafts are adopted.
3. **Environment.** Every catalog names an ITCVE. `checkRepository` in `src/core.mjs` accepts only `ITCVE-1` and requires `itcves/ITCVE-1/<version>/profile.json`. Maintainers either select an ITCVE-1 version whose controlled network and header source serve the anchoring rows, or define a new environment and extend that check.
4. **Standard references.** Maintainers choose one of the citation routes below.
5. **Recorded interpretations.** For each interpretation recorded in the proposal README and in [coverage](coverage.json), maintainers decide whether the affected row waits for SDX clarification, carries origin `open-interpretation`, or follows a recorded laboratory rule. Two readings decide expected bytes: the laboratory deployment profile, `tpnil-sdx-lab:v1` with one level-3 keyword `action`, decides every derived key, and the scalar-rejection reading of KEYS §1.8.2 decides the derivation rejection cases.
6. **Release.** Registering a program is a laboratory release. `VERSION`, `package.json` and `RELEASE_VERSION` in `src/core.mjs` change together, with a [changelog](../../../../CHANGELOG.md) entry.

## Repository changes

| Location | Change |
| --- | --- |
| `programs/index.json` | Add `{"id": "ISI-N", "version": "0.1.0"}` |
| `schemas/program-index.schema.json`, `schemas/catalog.schema.json` | Add `ISI-N` to the `id` enumerations |
| `src/core.mjs` | Update the registered-program count in `checkRepository`, which requires exactly four programs. Extend the environment check if a new ITCVE is defined, and the reference rule if route 2 below is chosen |
| `test/core.test.mjs` | Update the expected `checkRepository` result, currently four catalogs, 26 draft vectors and 6 executable SUT vectors |
| `programs/README.md` | Add the register row and update the program count |
| `programs/ISI-N/0.1.0/README.md`, `catalog.json` | Carry this proposal's README forward under the assigned identifier, and add the catalog described below |
| `programs/ISI-N/decisions/` | Record the assignment decision |
| `docs/implementation-status.md` | Record the program's maturity |
| Intake schema and `src/intake.mjs` | Add the SDX intake record version described below |
| Evidence verifier | Carry the SDX run-record schema forward and add the verification branch described below |
| `fixtures/sdx/v1/manifest.json`, `scripts/build-sdx-manifest.mjs` | The manifest already pins every snapshot, draft statement, imported SDX suite, the laboratory deployment profile, every authored suite, checker, test, generator file and proposal document by SHA-256, and `test/sdx-manifest.test.mjs` verifies it. Point the builder's program paths at `programs/ISI-N/0.1.0/` and rebuild with `node scripts/build-sdx-manifest.mjs` |
| `THIRD_PARTY_NOTICES.md`, `legal/provenance.md` | Record any additional SDX material, such as later snapshots or newly published SDX suites |

### Catalog

The catalog follows `schemas/catalog.schema.json` with status `draft`. `checkCatalog` requires identifiers `ISI-N-V…` and `ISI-N-R…` and a unique requirement identifier per vector, so the catalog carries one vector for each requirement. The program README keeps a mapping from the proposal identifiers to catalog identifiers, for example SDX-A-01 to ISI-N-R001 and ISI-N-V001. Each vector supplies `title`, `origin`, `reference`, `applicability`, `executable`, `preconditions`, `steps`, `expected`, `evidence` and `blockers`; the array fields each need at least one entry. The catalog `applicability` field is a string, so the clause form in [profile.json](profile.json) remains the machine-readable applicability rule until a schema carries it. A vector becomes `executable: true` only after its independent oracle, fixtures, admitted component digests and adapters are qualified.

### Citation routes for origin `standard`

`checkCatalog` accepts a `standard` reference only as a GitHub blob URL pinned to a 40-character commit. `checkRepository` resolves other non-HTTPS references as in-repository paths, but that branch does not apply to `standard` rows. SDX publishes its texts on a website without a commit-addressable repository, so the snapshots under `fixtures/sdx/v1/standards/text/` carry the pin.

1. **Commit-pinned URL of this repository.** Cite the snapshot as `https://github.com/p2ppsr/interop/blob/<commit>/fixtures/sdx/v1/standards/text/<page>.md`, once the commit containing it exists, with the clause's line range from [coverage.json](coverage.json) as a `#L<start>-L<end>` fragment. This route needs no core change.
2. **Digest-pinned in-repository path.** Amend `checkCatalog` so a `standard` reference may be a safe relative path whose bytes are pinned by the SDX fixture manifest, with tests for missing, altered and unpinned references. The clause then travels in the vector title or steps.

### Intake

`schemas/intake.schema.json` (2.0.0) fixes the program to `ISI-4@1.0.0`, the environment to `ITCVE-1@1.0.0` and the production-wallet profile. SDX systems under test need a new intake record version, dispatched by `schemaVersion` in `src/intake.mjs`, that records the artifact identity and the declaration fixed before execution: roles, capabilities, deployment-profile strings, the implementation's published KEYS §1.12 known-answer results, its statement of which SHOULD and MAY provisions it supports (BASE §6, conformance levels), and the command of its driver under the [driver contract](driver-contract.md), with the optional operations it supports. It also records licence and permission evidence as current intake does. Retained 1.0.0 and 2.0.0 reviews keep their schemas and report shapes.

### Evidence verification

`tpnil verify` replays laboratory self-test journals, and ISI-4 wallet runs use `src/sut-evidence.mjs` with explicit `tpnil-isi4-*` schemas. SDX runs have their own run-record schema, [`run-record.schema.json`](run-record.schema.json) (`tpnil-sdx-run-record@0.1.0`), which the proposal's harness `scripts/run-sdx-suts.mjs` writes with a transcript of every driver request and response; `test/sdx-manifest.test.mjs` checks each recorded run's label, transcript digest and outcome counts. A verification branch in `tpnil verify` is still needed. It checks the program and environment identity, the declaration and every NOT_APPLICABLE reason, both directions of each matrix cell, the driver requests and responses of every step, two clean repetitions with matching semantic projections, the exact evidence file set with sizes and SHA-256 digests, and the digests of the pinned sources and suites. Retained journals stay append-only.

## Moving a companion row to standard

1. The BRC process adopts text that matches the row.
2. TPNIL pins the adopted text with a commit-pinned URL for the BRC. Earlier draft statements remain.
3. The row's citation moves from the draft statement to the adopted clause, and its PROPOSED status is removed. Where the adopted wording differs, the assertion follows the adopted text. A change of substance takes a new row identifier; identifiers are never reused, and rows for declined changes are retired.
4. The row's suite is qualified again against the adopted text and any published vectors, which take precedence for the bytes they pin.
5. The program takes a new version under [versioning](../../../../docs/versioning.md): new optional rows increment MINOR, and new mandatory rows change acceptance and increment MAJOR.

Normative changes precede evaluations that rely on them. No scored run depends on a row before these steps are complete.
