# SDX encoding and anchoring vectors

This component generates two vector suites for the SDX data-sharing conformance
program and cross-checks them against independent implementations:

| Suite | File | Requirements | What it pins |
|---|---|---|---|
| VA-ENC | `fixtures/sdx/v1/va-enc/vectors.json` | SDX-A-01 | The ENV §3 deterministic profile: every published `cbor-det-v1` and `historical-float64-decode` vector, and laboratory-derived decoder and encoder cases, each tagged `required` or `labChoice` |
| VA-ANC | `fixtures/sdx/v1/va-anc/vectors.json` | SDX-A-07 | SDX v0.1 anchoring: the ANC §6.1 reference check, and the ANC §7.1 walk with the ANC §6.2 chain-integrity check and the ANC §4.2 tip rule, outcomes named by ANC §7.5 dead-letter class |

Both suites carry `"claim": "LAB_SELF_TEST_ONLY"` and status `BASELINE-v0.1`.
Each file records its citations, its decisions on points the texts leave open,
its generator and its oracles. VA-ANC also records its test keys and roots, its
synthetic chain and the deployment profile it is computed under.

## The deployment profile

VA-ANC is computed under the laboratory deployment profile
`fixtures/sdx/v1/deployment-profile.json` (`tpnil-sdx-lab:v1`; KEYS §1.3.1,
ENV §2.1). Every commitment key is the ANC §3.1 key: a BRC-42 self-derivation
on the secp256k1 seed of the epoch's root, under `[2, "sdx sign"]` and key ID
`account/<accountId>/runtime/<runtimeId>/action/<actionId>`. The roots are
public 64-byte test values published in the file. They control 1-satoshi
entries on the synthetic chain only.

## Records

Records are laboratory stand-ins. A v0.1 record keeps its action identifier and
key epoch inside its outer wrap (ENV §6.1), so a reader decrypts it to read them.
The stand-in is a deterministic CBOR map that carries `hdr.aid` and `hdr.ep` in
clear, and its decode replaces that step. Its `proto` is not the profile's format
identifier, so no stand-in is an SDX record envelope.

## The reference

SDX v0.1 publishes no byte encoding for a reference and its proof; the
`utxo-chaining` and `cross-domain-refs` suites are not yet published. VA-ANC
carries a reference as a deterministic CBOR map:

```
Reference = { "v": 1, "aid": text, "tx": bstr(32), "out": uint, "beef": bstr }
```

`beef` is BEEF V1 or Atomic BEEF holding the referenced transaction with its
BUMP. `tx` and `out` cite that transaction and output, and `aid` is the action
the citation claims. A verifier that is a recipient of the referenced record
checks `aid` against the record (the ANC §6.1 honest-citation guard). VA-ANC is
re-based on the SDX suites when SDX publishes them.

## Checkers

The Node.js checker in `src/sdx/` uses Node.js built-ins only:

- `cbor-det.mjs`: the ENV §3 encoder, the semantic decoder, and the strict
  decoder the reference map is read with;
- `tx.mjs`: transactions, scripts, the ANC §2 container shape, BIP 143
  SIGHASH_FORKID signature checks, BEEF V1 and Atomic BEEF, BRC-74 BUMP roots,
  and a header source over a pinned header list;
- `anc.mjs`: the KEYS §1.4.2 split and BRC-42 self-derivation of commitment
  keys, `verifyReference` (ANC §6.1 in its order) and `walkChain` (ANC §7.1,
  §6.2, §4.2).

`test/sdx_anc.py` is a second checker on the Python standard library only. It
shares no code with the Node.js checker and reproduces every VA-ANC outcome and
every laboratory-derived VA-ENC case (`test/test_sdx_anc.py`).

## Regeneration

Run from the repository root with Node 24:

```sh
npm ci --ignore-scripts --prefix components/sdx/proof
npm run generate --prefix components/sdx/proof   # rewrites both vectors.json files
npm run check --prefix components/sdx/proof      # regenerates in memory and compares
npm test --prefix components/sdx/proof           # @bsv/sdk and cborg cross-checks
node --test test/sdx-cbor.test.mjs test/sdx-anc.test.mjs test/sdx-profile.test.mjs
python3 -m unittest discover -s test -p 'test_sdx_anc.py'
```

Generation is deterministic. Keys and roots come from fixed labels, signatures
use RFC 6979 nonces, header times are fixed, and each header's nonce is the
first that meets its regtest bits. Two runs write identical files, and
`npm run check` confirms it.

The generator declares each case's expected outcome from the way the case is
built. It then runs the Node.js checker on every case and stops on any
disagreement, so the files never record the checker's output as its own
expectation. In the same run it confirms the construction with @bsv/sdk:

- `Spend.validate()` accepts every input of every synthetic transaction,
  including the high-S input of M4;
- `MerklePath.computeRoot` and `MerklePath.verify` confirm every mined
  transaction;
- `Beef.fromBinary`, `isValid` and `verify` accept the BEEF of every walk row
  and every accepted reference;
- the commitment key @bsv/sdk derives for each participant entry equals the
  checker's.

cborg and `src/sdx/cbor-det.mjs` must also encode every map identically.

## Oracles

| Oracle | What it checks |
|---|---|
| SDX published suites | The encoder's bytes and the decoder's values for VA-ENC-001 to 044; the expected values come from SDX |
| Python checker (`test/sdx_anc.py`) | Every VA-ANC outcome and every laboratory-derived VA-ENC case, from the files alone |
| BRC-74 and BRC-62 published examples | BUMP root computation, and the sighash and ECDSA check on a mainnet P2PKH spend |
| @bsv/sdk 4.0.1 | Merkle roots, BEEF, and the commitment key of every participant entry, re-verified from the committed files (`test/sdk-cross-check.test.mjs`) |
| cborg 6.2.1 | Re-encoding of every deterministic reference, and the expected bytes of the VA-ENC encoder cases |
| Rust participant | BEEF parsing and merkle roots of the accepted references, through `components/rust` (`test/rust-oracle.test.mjs`) |

The Rust oracle runs when `TPNIL_RUST_PARTICIPANT` names a binary built with
`cargo build --locked` in `components/rust`; otherwise it is skipped.

The root tests also mutate an accepted reference one bit at a time. A recipient
refuses every change except to the informational BRC-74 client-txid flag. A
verifier that is not a recipient also accepts changes to `aid`, which only the
honest-citation guard binds.

## Synthetic chain

VA-ANC carries a list of 107 synthetic 80-byte headers, which `headersSha256`
pins. Height 0 holds the genesis coinbase that funds every transaction. Heights
1-100 hold only coinbases, so the genesis output is mature when it is spent at
height 101. The payload is mined at heights 101-106. A case with
`headersThrough` gives the verifier the list up to that height only.

The chain is not any real network. Nothing in it is broadcast. Its keys and
roots are published in the file's `testKeys` and control value only on this
chain.

## Imported SDX suites

`fixtures/sdx/v1/standards/cbor-det-v1/` holds `cbor-det-v1.json` and
`historical-float64-decode.json` as retrieved from
`https://sdxprotocol.org/vectors/`, unchanged and pinned by SHA-256 in
`index.json`. They are published under the SDX specification texts and test
vectors licence 1.0 (`LICENSES/SDX-Specification-License-1.0.reference.txt`),
with attribution to the SDX Protocol specification, version 0.1. To re-verify a
file, fetch its `sourceUrl` and compare its SHA-256 with `index.json`.

## Scope

VA-ANC does not cover the write path (ANC §5), rotation (ANC §4.3),
reorganisation (ANC §7.4), or admission and the per-topic index (ANC §10-§16).
The ANC §2.4 value floor is a writer obligation; every entry here carries the
profile's floor of one satoshi.
