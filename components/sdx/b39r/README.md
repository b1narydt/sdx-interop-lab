# BRC-39 recipient-protector vectors

This component generates the `VC-B39R` suite of the proposed SDX data-sharing
conformance program: BRC-39 files encrypted to a recipient's key with no
password, as specified by the contributed BRC draft
`fixtures/sdx/v1/standards/draft-statements/brc-draft-brc39-recipient-protector.md`.
Every vector file and every result is `LAB_SELF_TEST_ONLY`, with status
`PROPOSED`: the draft has not been adopted by the BRC maintainers. No system
under test is evaluated here.

| Suite | Requirements | Cases | Covers |
| --- | --- | --- | --- |
| `fixtures/sdx/v1/vc-b39r` | B39R-01, B39R-02 | 37 | Recipient-protector files (handover and backup to self) and every draft §3 refusal, each with the stage that refuses it |

## Oracles

The suite has two oracles that share no protocol code.

- **Generator (this component).** `@bsv/sdk` 4.0.1 for BRC-42, BRC-2 and
  BRC-78; `@noble/ciphers` 2.4.0 for AES-256-GCM with additional authenticated
  data, which `@bsv/sdk` 4.0.1 does not expose. The generator asserts every
  value with these libraries before it writes it.
- **Checker (`src/portability/brc39-recipient.mjs`, with `src/sdx/brc42.mjs`
  and `src/sdx/brc2.mjs`).** It imports nothing but Node built-ins: node:crypto
  for ECDH, HMAC and AES-GCM, and minimal BigInt arithmetic for the secp256k1
  operations node:crypto does not expose. It does not reuse
  `src/portability/brc39.mjs`.

`@bsv/sdk` 4.0.1 normally routes AES-GCM, SHA-256 and HMAC through node:crypto.
`oracle.mjs` loads it with `process.getBuiltinModule` hidden, so its
pure-TypeScript implementations produce every SDK-derived value. The test "the
@bsv/sdk oracle shares no node:crypto code with the checkers" counts node:crypto
calls in a child process and requires zero, against a control that requires
more than zero.

`test/differential.test.mjs` adds randomised cross-checks on fresh inputs:
BRC-42 derivation in both `getPublicKey` directions, BRC-2 and BRC-78 in both
directions, and recipient-protector files written by either side.

## Randomised fields

BRC-78 draws a random key ID and IV inside the SDK, and callers cannot fix
them. Those values are decrypt-direction: they were generated once, are frozen
in `frozen-random.json`, and appear in each case's `randomized` list. The
checker decrypts them with the public test keys; it does not reproduce them.
Every other byte is deterministic.

`--write` and `--check` reuse the frozen values, so a regeneration reproduces
the committed suite byte for byte. `--fresh` draws new values into another
directory; two fresh runs differ only in the annotated fields, and the test
"fresh randomness changes only the fields each case lists as randomized"
enforces that.

## Regenerating and checking

Run from the repository root with Node 24:

```sh
npm ci --ignore-scripts --prefix components/sdx/b39r
npm test --prefix components/sdx/b39r
node components/sdx/b39r/generate.mjs --check
node --test test/brc39-recipient.test.mjs
```

`--check` regenerates in memory and requires byte equality with the committed
suite (a different Node patch version changes only `generator.runtime`, which
is reported). `--write` rewrites the suite and `frozen-random.json`.
`--fresh --out <directory>` never writes into `fixtures/`.

## Test keys

Every key in `testKeys` is a public test key, not a secret, never funded.
Accounts A and B are the secp256k1 halves of the KEYS §1.4.2 split of the
64-byte roots `00..3f` and `40..7f`, the roots the P-256 suites use. Every
other key is SHA-256 of the label recorded with it. The checker tests recompute
each key from its label or root.
