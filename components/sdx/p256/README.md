# `p sdx` module vectors: VC-P256 and VC-SDX-K1

This package generates two proposed SDX vector suites for the `p sdx` BRC-98
module draft, a wallet module that holds SDX accounts and serves both of their
key trees. Both are `LAB_SELF_TEST_ONLY` and `PROPOSED`; they test the
laboratory's own checkers and do not record any system under test. The
directory keeps its earlier name, `p256`, because the laboratory's scripts and
pinned paths name it.

| Suite | File | Requirements | Cases |
|---|---|---|---|
| VC-P256 | `fixtures/sdx/v1/vc-p256/vectors.json` | P256-01 to P256-04 | 175 (163 checked, 12 behavioural) |
| VC-SDX-K1 | `fixtures/sdx/v1/vc-sdx-k1/vectors.json` | K1-01 to K1-05 | 71 (65 checked, 6 behavioural) |

Both suites use the laboratory deployment profile published in
`fixtures/sdx/v1/deployment-profile.json`: format identifier `tpnil-sdx-lab:v1`,
and SDX's example labels, namespaces, key-path keywords, level-4 purposes and
credential type, used for the laboratory only (KEYS §1.3.1; ENV §2.1). The
generator reads every string from that file, and the tests check that each
suite's `profile` and `wallets.profile` carry the same values. One
level-3 keyword, `action`, names a record on both curves, so a record's P-256
signing key and its secp256k1 commitment key share one key path (decision
D-PROFILE).

VC-P256 pins the module's P-256 side:
- the KEYS §1.4.2 root split, and roots derived inside a wallet: d is the BRC-42 child private key under `[2, "admin sdx root"]`, key ID `"<accountId> <epoch>"` (or `actor` for an actor root), counterparty `self`, and the 64-byte root is HKDF-SHA-256(d, salt `"p sdx v1"`, info `"sdx root"`);
- `open`, which returns R ‖ K for an epoch the wallet holds and creates an account or epoch after a prompt;
- root selection: two accounts in one wallet, two epochs of one account, the current epoch, and the actor and session roots;
- KEYS §1.8.2 child keys for record signing, recipient, persistent-actor and session paths;
- the `key`, `peer` and `sign` results, RFC 6979 Appendix A.2.5 nonces, and the low-S signatures `sign` returns;
- `decrypt` on JWEs made by jose: a one-recipient outer wrap with `proto`, `aid` and `epk` in its protected header (ENV §5.2, §5.3), both entries of a two-recipient outer wrap, and a recipient's entry of a two-recipient per-field JWE (ENV §9); and its refusals: a wrong key path, another party's entry, altered ciphertext, an altered protected header, and every malformed `jwe` and ephemeral key;
- the namespace rules (separation both ways, the reserved rotation namespace) and the key-path rules (KEYS §1.3, §1.6.1, §1.12 item 10, §2.14.1);
- point validation, carrier and method rejections, the logical protocol ID form, unknown accounts and epochs, grant scoping, input rules, and the permission behaviour of P256-04.

VC-SDX-K1 pins the module's secp256k1 side:
- `k1key` and `k1peer`: the root key K, ANC §3.1 commitment keys, a top-up lock, a handoff lock addressed to a recipient and the recipient's matching key, the actor's persistent key and a session key. The generator computes every result a second time with `@bsv/sdk` 4.0.1 `ProtoWallet(new PrivateKey(secp256k1_seed)).getPublicKey({protocolID: [s, namespace], keyID: keyPath, counterparty, forSelf})` and fails if the two differ; each case records that call in `brc100`;
- `k1sign`: RFC 6979, low-S DER signatures over the 32 bytes of `hash` as given, equal to `@bsv/sdk` `createSignature` with `hashToDirectlySign`. Case `k1sign-commitment-spend` signs the SIGHASH_ALL|FORKID hash of a real (synthetic, unbroadcast) transaction that spends an ANC §2.1 record output, and carries both transactions;
- selection of accounts and epochs on secp256k1;
- the KEYS §1.12 item 7 offset range on secp256k1, as a computation (decision D-K1-RANGE);
- rejections: invalid secp256k1 points (including x ≥ p before any parser), `hash` lengths, the encryption and rotation namespaces, an unregistered purpose, the `record` keyword, unknown accounts and epochs, `privileged`, counterparties, carrier methods and grants;
- the permission behaviour of K1-05.

Each file records its citations, decisions, test keys, wallets, generator and
oracles.

## Replaying the cases with an independent module

Every suite is self-describing, so a module implementation can replay each executable case from the file alone. No case needs a test hook in the module.

### The `wallets` table

`wallets` holds the exact wallet state that every module case starts from. No case sees another case's effects.

```text
wallets
  profile
    labels                  {secp256k1, p256}: the KEYS §1.4.2 labels
    namespaces[]            {role, namespace, curves}: the six KEYS §1.7 namespaces and the curves each serves
    keywords                {account, runtime, action, session, delegation, actor}: the KEYS §1.6.1 keywords,
                            and `actor` for the persistent key path actor/<index>
    purposes[]              the registered level-4 purposes
  walletRootDerivation      {protocolID [2, "admin sdx root"], keyID "<acct> <ep>", counterparty "self",
                             salt "p sdx v1", info "sdx root", length 64}
  entries
    <wallet name>
      walletRoot            optional; the wallet's own 32-byte root private key, hex
      accounts[]
        acct                the account ID
        tag                 32 lowercase hex: the first 16 bytes of SHA-256(UTF-8 acct)
        current             the epoch used when a request has no ep
        epochs[]            {ep, ikm, R, K} or {ep, walletRoot, derived: true, R, K}
      actor                 optional; {ikm, R, K}: the wallet's actor root
      sessions              optional; {<sessionId>: {ikm, R, K}}: session roots by session ID
      grants[]              {protocolID [2, "p sdx <operation> <role> <tag>"], prefixes[]}
```

To load a wallet:
1. An epoch with `ikm` uses those 64 bytes as its root keying material. An epoch with `derived: true` derives it from `walletRoot`: d is the BRC-42 child private key for invoice `2-admin sdx root-<acct> <ep>`, counterparty `self`, and the ikm is HKDF-SHA-256(d as 32 bytes, salt, info, 64).
2. Split every ikm with `profile.labels` (KEYS §1.4.2). `R` and `K` are the resulting P-256 and secp256k1 root public keys; compare them after loading.
3. The wallet-level `walletRoot` is the root `open` creates accounts and epochs from. A wallet without one has no creation case.
4. A session ID is the 32-hex `<sessionId>` segment that follows `/session/` in a path.
5. The grants belong to one laboratory originator. A request runs under a grant only when the grant's `protocolID` equals its own; a request with `path` also needs one of the grant's prefixes to be a byte prefix of `path`. `open` grants list no prefixes.

### Module cases and requests

Cases of kind `module`, `request-rejection` and `point-rejection` are executable. Each names its `wallet` and carries a `request`:

```text
request
  method          "encrypt", "decrypt", or another BRC-100 method that must be refused
  args            the BRC-100 arguments exactly: protocolID, keyID, counterparty, and where present
                  privileged and privilegedReason; plaintext (encrypt) or ciphertext (decrypt) is the
                  lowercase hex of the CBOR input bytes
  input           a readable view of the CBOR map, absent when the bytes are malformed on purpose
```

- Send `args` as given, decoding only the hex of `plaintext` or `ciphertext` to bytes. Some carried bytes are malformed on purpose.
- In `input`, `path` and `acct` are JSON strings, `ep` is a JSON number, `jwe` is the CBOR map written as a JSON object, and every other member is lowercase hex of a byte string. A member of the wrong major type is written `{"tstr": text}`, `{"bstr": hex}`, `{"uint": n}` or `{"nint": n}`.
- `expected.ciphertext` (from `encrypt`) or `expected.plaintext` (from `decrypt`) is the result as hex. `expected.error` means the request is refused.
- `variants` lists argument overrides; each overridden request must give the same result.
- `prompt: "approve"` marks a request that raises a prompt (creating an account or an epoch); the result applies when the user approves it, and the same request without approval is refused. Requests without it run with no user interaction, under the standing grants only.
- A `decrypt` case's `intermediate` holds the key agreement `z`, the key-encryption key `kek` and, when the key is right, the content-encryption key `cek`; `frozen` names the JWE in `frozen.json` its entry comes from.
- `point-rejection` cases list one request per point position in `requests`; each is refused.
- Kinds `split`, `wallet-root`, `seed-range`, `offset-range` and `es256-external` are computations without a module request. Kind `behaviour` is a given/when/then row with no portable bytes.

VC-P256 has 189 executable requests and VC-SDX-K1 91, not counting variants.

### Rejection labels and order

Labels such as `unknown-epoch` are laboratory labels; conformance requires the rejection, not the label. The laboratory checks in this order (decision D-ERRORS), so a module that does the same gives the same label:
1. the method, and `p sdx` baskets and labels;
2. the protocol name: scheme, operation, carrier method, security level, `privileged`, then the logical protocol ID `<role> <h>`;
3. `counterparty`;
4. the CBOR input: encoding, members, types, point validation, the length of `hash`, and the shape of `jwe` with its ephemeral key (`jwe-shape`, or a point label);
5. the operation's rules: `open`'s role and tag, then the path: `2-<namespace>-<keyPath>`, a namespace registered for the curve, the rotation namespace (`namespace-rotation`), the encryption namespace for `decrypt` (`namespace-decrypt`) and for `sign` and `k1sign` (`namespace-encryption`), the key path's length (`key-path-length`), then its grammar (`key-path-grammar`) and purpose (`purpose-unregistered`);
6. the selection checks that read only the request: `ep` on actor and session roles, the session the path names;
7. the grant and its prefixes, or the approved prompt, which `open` needs whenever it creates;
8. root selection from what the wallet holds: account, epoch, a tag another account holds (`account-tag-collision`), a wallet that cannot create (`cannot-create`). It comes after authorization, so a request with no grant and no approval gets `no-grant` whether or not the wallet holds its account or epoch;
9. derivation, where an offset of 0 or at least n fails;
10. for `decrypt`, the JOSE steps, where a wrong key or altered content gives `decrypt-failed`.

## Oracles

The generator uses `@noble/curves`, `@noble/hashes`, `cborg`, `jose` and
`@bsv/sdk`, pinned exactly in `package.json` and `package-lock.json`. Two
checkers recompute the vectors without any of them:

- **`src/sdx/p256.mjs` and `src/sdx/k1.mjs`** (tests `test/sdx-p256.test.mjs` and `test/sdx-k1.test.mjs`) use node:crypto. OpenSSL performs scalar multiplication, ECDH, HKDF, HMAC, ES256 verification, AES key unwrap and AES-GCM.
  - `src/sdx/p256.mjs` holds the module semantics: a wallet built from a `wallets` entry, with root selection, the request rules and every operation, including the JWE decryption step of `decrypt`.
  - `src/sdx/ec-p256.mjs` adds point validation, y recovery and point addition on both curves, which node:crypto does not expose.
  - The laboratory's own oracle `src/sdx/brc42.mjs` gives the BRC-42 steps, and recomputes every BRC-100 `getPublicKey` result VC-SDX-K1 records. `src/sdx/tx.mjs` recomputes the transaction preimage and evaluates the commitment spend. These are node:crypto checker modules, not generator code.
  - RFC 6979 nonces are recomputed with node:crypto HMAC, on both curves.
- **`test/sdx_ec.py`, `test/sdx_module.py`, `test/test_sdx_p256.py` and `test/test_sdx_k1.py`** use the Python standard library only. They decode every request's CBOR strictly, replay every request against the `wallets` table and recompute every value, including each `decrypt` case end to end.

`test/sdx_ec.py` implements P-256 and secp256k1 arithmetic, point validation,
ECDSA, RFC 6979, DER signatures, HKDF, the Concat KDF, BRC-42/BRC-2 key
derivation, and the AES-256 block cipher (FIPS 197), AES key unwrap (RFC 3394)
and GCM decryption (NIST SP 800-38D), each checked against its published known
answers, for reuse by other SDX checks.

## Regeneration

From the repository root, with Node 24:

```sh
npm ci --ignore-scripts --prefix components/sdx/p256
npm run check --prefix components/sdx/p256      # regenerate in memory; require identical bytes
npm run generate --prefix components/sdx/p256   # rewrite the two vectors.json files
```

Every value is deterministic except the JWEs the `decrypt` cases open. jose
draws a random content-encryption key, IV and ephemeral key for each, so
`frozen.json` holds each JWE together with the protected header, recipient kids
and plaintext it was made for, and its content-encryption key.

- `--write` creates an entry once with jose 5.10.0 `GeneralEncrypt`. It
  replaces an entry whose inputs have changed, and removes entries no case uses.
- `--check` fails on any of those conditions instead.
- Every run decrypts each entry of each frozen JWE with its recipient's key, by
  jose and by node:crypto, and checks the content-encryption key and where jose
  put `epk`.
- The `generator.runtime` field records the Node version that wrote the files.
  `--check` under another version reports that field as a difference.

## Rejection inputs found by search

Two P-256 rejections cannot be produced by construction. On P-256,
`2^256 - n` is about `2^224`, so a uniformly random 32-byte value is `>= n`
with probability about `2^-32`. `grind/main.go` (Go standard library only)
searches for one input of each kind:

| Search | Input | Result | Search cost |
|---|---|---|---|
| Unusable ikm (KEYS §1.4.3) | `ikm = 0xff × 56 ‖ uint64be(counter)`, label `sdx-p256` | counter 1557900713; P-256 seed `ffffffff5595…d25f` | 1.56 × 10^9 tries, 139 s, 4 workers |
| Rejected offset (KEYS §1.8.2) | Account root, counterparty `self`; identifier `2-sdx sign-account/3MNQpxFAsp/runtime/8kRt2wVbZq/action/01JB8ZK3QN` followed by 16 Crockford base32 digits of the counter | counter 6019505901; action ID `01JB8ZK3QN0000000005KCMQQD`; HMAC `ffffffff2d65…64bf` | 6.03 × 10^9 tries, 284 s, 4 workers |

Workers interleave counters and continue until each has passed the best hit,
so the reported counter is the smallest one regardless of thread timing.
The generator and both checkers re-verify the two results on every run. To
reproduce the searches:

```sh
cd components/sdx/p256/grind
go build -o grind .
./grind seed ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff sdx-p256 840 4
./grind path 02be4bdb55e891f95b60c45c0c2c53ff8b60a9a2e0a2f8d0d664d8abc67ff56d14 "2-sdx sign-account/3MNQpxFAsp/runtime/8kRt2wVbZq/action/01JB8ZK3QN" 1200 4
```

The path search's first argument is the SEC1-compressed point `r·(r·G)` of
the account root, the HMAC key for its self-derivations. The program accepts
at most four workers.

Some values have no findable input: a seed or offset of exactly 0, `n` or
`n + 1`, and any secp256k1 value of `n` or above. The `seed-range` and
`offset-range` cases inject those values into the range check directly, as
KEYS §1.12 item 7 provides; no module request carries an injected value.

## Scope

- **Wallets and grants:** the `wallets` table models wallet state for the request vectors. Each grant covers one `[2, "p sdx <operation> <role> <h>"]` and lists the derivation-identifier prefixes it covers.
- **Behavioural cases (P256-04, K1-05)** describe a request, a wallet state and the required outcome. They have no portable bytes, and the checkers verify only their form.
- **Threshold wallets** draw signing nonces jointly, so their `sign` and `k1sign` results are checked by verification rather than by these bytes.
