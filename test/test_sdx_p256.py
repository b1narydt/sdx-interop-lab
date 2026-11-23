"""LAB_SELF_TEST_ONLY: standard-library checker for the VC-P256 suite.

Every value in the suite is recomputed here from the test roots and the
`wallets` table with test/sdx_ec.py and test/sdx_module.py, independently of
the generator and of the node:crypto checker: root splits, wallet-created
roots, account and epoch selection, seeds, keys, offsets, shared points, low-S
ES256 signatures and their RFC 6979 nonces, the namespace and key-path rules,
CBOR request bytes (decoded strictly here), point validation, grant scoping,
request rejections, and each `decrypt` case end to end: the ECDH, the Concat
KDF key-encryption key, the AES key unwrap and the A256GCM decryption, with the
AES of test/sdx_ec.py.
"""

import base64
import copy
import json
import unittest
from pathlib import Path

import sdx_ec as ec
import sdx_module as m

ROOT = Path(__file__).resolve().parents[1]
VC = json.loads((ROOT / 'fixtures/sdx/v1/vc-p256/vectors.json').read_text(encoding='utf-8'))

CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
unhex = m.unhex


def b64u(text):
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def low_s(s):
    return ec.P256.n - s if s > ec.P256.n // 2 else s


def check_intermediates(test, root, entry, fields):
    known = entry.get('intermediate', {})
    peer, path = fields.get('peer') or root.R, fields['path']
    shared, digest = None, None
    point = ec.decode_point(ec.P256, peer)
    shared = ec.compress(ec.P256, ec.mul(ec.P256, root.r, point))
    digest = ec.hmac_sha256(shared, path.encode('utf-8'))
    if 'sharedPoint' in known:
        test.assertEqual(shared.hex(), known['sharedPoint'])
        test.assertEqual(digest.hex(), known['hmac'])
    if 'childPrivate' in known:
        test.assertEqual(ec.int32(m.own_child(ec.P256, root.r, peer, path)).hex(), known['childPrivate'])
    if 'digest' in known:
        test.assertEqual(ec.sha256(fields['msg']).hex(), known['digest'])
        r, s, _ = ec.ecdsa_sign_rfc6979(ec.P256, m.own_child(ec.P256, root.r, peer, path), ec.sha256(fields['msg']))
        test.assertEqual((ec.int32(r) + ec.int32(s)).hex(), known['rfc6979'])
        test.assertEqual(s > ec.P256.n // 2, known['normalised'])
    return digest


class VcP256(unittest.TestCase):
    """VC-P256: P256-01..05."""

    def test_vectors_recomputed(self):
        roots, wallets = m.check_header(self, VC, 'VC-P256', ['P256-01', 'P256-02', 'P256-03', 'P256-04'])
        by_id = {entry['id']: entry for entry in VC['cases']}
        behavioural = 0
        for entry in VC['cases']:
            with self.subTest(case=entry['id']):
                kind = entry['kind']
                if kind == 'split':
                    labels = entry['input']['labels']
                    ikm = unhex(entry['input']['ikm'])
                    k1 = ec.hkdf_sha256(ikm, b'', labels['secp256k1'].encode(), 32)
                    r1 = ec.hkdf_sha256(ikm, b'', labels['p256'].encode(), 32)
                    if 'error' in entry['expected']:
                        self.assertEqual((k1.hex(), r1.hex()), (entry['intermediate']['secp256k1Seed'], entry['intermediate']['p256Seed']))
                        self.assertGreaterEqual(int.from_bytes(r1, 'big'), ec.P256.n)
                        with self.assertRaises(ec.EcError) as raised:
                            ec.split_ikm(ikm, labels['secp256k1'].encode(), labels['p256'].encode())
                        self.assertEqual(str(raised.exception), f"{entry['expected']['error']}: {entry['expected']['curve']}")
                        grind = VC['generator']['grind']['seed']
                        self.assertEqual(ikm, unhex(grind['prefix']) + grind['counter'].to_bytes(8, 'big'))
                        self.assertEqual(ikm.hex(), grind['ikm'])
                        continue
                    expected = entry['expected']
                    self.assertEqual((k1.hex(), r1.hex()), (expected['secp256k1Seed'], expected['p256Seed']))
                    self.assertEqual(ec.compress(ec.SECP256K1, ec.base_mul(ec.SECP256K1, int(k1.hex(), 16))).hex(), expected['secp256k1PublicKey'])
                    self.assertEqual(ec.compress(ec.P256, ec.base_mul(ec.P256, int(r1.hex(), 16))).hex(), expected['p256PublicKey'])
                    self.assertEqual(roots[entry['root']].R.hex(), expected['p256PublicKey'])
                elif kind == 'wallet-root':
                    # A root derived inside a wallet: d = BRC-42 child private key under
                    # [2, "admin sdx root"], key ID "<accountId> <epoch>" or "actor", counterparty self;
                    # ikm = HKDF-SHA-256(d, salt "p sdx v1", info "sdx root", 64); then the split.
                    given, expected, inter = entry['input'], entry['expected'], entry['intermediate']
                    self.assertEqual((given['protocolID'], given['counterparty'], given['salt'], given['info']), ([2, 'admin sdx root'], 'self', 'p sdx v1', 'sdx root'))
                    self.assertRegex(given['keyID'], r'^(?:[1-9A-HJ-NP-Za-km-z]+ (?:0|[1-9][0-9]*)|actor)$')
                    w = unhex(given['walletRootPrivateKey'])
                    self.assertEqual(ec.sha256(given['walletRootLabel'].encode()), w)
                    invoice_number = f"{given['protocolID'][0]}-{given['protocolID'][1]}-{given['keyID']}"
                    self.assertEqual(invoice_number, inter['invoiceNumber'])
                    w_int = int(w.hex(), 16)
                    shared = ec.compress(ec.SECP256K1, ec.mul(ec.SECP256K1, w_int, ec.base_mul(ec.SECP256K1, w_int)))
                    self.assertEqual(shared.hex(), inter['sharedPoint'])
                    mac = ec.hmac_sha256(shared, invoice_number.encode())
                    self.assertEqual(mac.hex(), inter['hmac'])
                    d = ec.int32((w_int + int(mac.hex(), 16)) % ec.SECP256K1.n)
                    self.assertEqual(d, ec.int32(ec.brc42_child_private(w_int, ec.base_mul(ec.SECP256K1, w_int), invoice_number)))
                    self.assertEqual(d.hex(), expected['d'])
                    ikm = ec.hkdf_sha256(d, given['salt'].encode(), given['info'].encode(), 64)
                    self.assertEqual(ikm.hex(), expected['ikm'])
                    self.assertEqual(m.wallet_derived_ikm(w, VC['wallets']['walletRootDerivation'], given['keyID']), ikm)
                    root = m.Root(ikm, given['labels'])
                    self.assertEqual((root.secp256k1_seed.hex(), root.p256_seed.hex()), (expected['secp256k1Seed'], expected['p256Seed']))
                    self.assertEqual((root.K.hex(), root.R.hex()), (expected['secp256k1PublicKey'], expected['p256PublicKey']))
                elif kind == 'seed-range':
                    curve = ec.CURVES[entry['curve']]
                    for value in entry['values']:
                        self.assertEqual(1 <= int(value['seed'], 16) < curve.n, value['expected'] == 'accept')
                elif kind == 'offset-range':
                    curve = ec.CURVES[entry['curve']]
                    for value in entry['values']:
                        if value['expected'] == 'accept':
                            self.assertEqual(ec.check_offset(curve, unhex(value['hmac'])), int(value['hmac'], 16))
                        else:
                            self.assertRaises(ec.EcError, ec.check_offset, curve, unhex(value['hmac']))
                elif kind == 'module':
                    self.check_module(roots, wallets, by_id, entry)
                elif kind == 'es256-external':
                    d = int(entry['privateKey'], 16)
                    public = ec.base_mul(ec.P256, d)
                    self.assertEqual(ec.compress(ec.P256, public).hex(), entry['publicKey'])
                    digest = ec.sha256(unhex(entry['message']))
                    r, s, k = ec.ecdsa_sign_rfc6979(ec.P256, d, digest)
                    expected = entry['expected']
                    self.assertEqual(ec.int32(k).hex(), expected['k'])
                    self.assertEqual((ec.int32(r) + ec.int32(s)).hex(), expected['rfc6979'])
                    self.assertEqual((ec.int32(r) + ec.int32(low_s(s))).hex(), expected['signature'])
                    self.assertEqual(s > ec.P256.n // 2, expected['normalised'])
                    self.assertTrue(ec.ecdsa_verify(ec.P256, public, digest, r, s))
                    self.assertTrue(ec.ecdsa_verify(ec.P256, public, digest, r, ec.P256.n - s))
                elif kind == 'point-rejection':
                    self.assertEqual(entry['curve'], 'P-256')
                    encoding = unhex(entry['encoding'])
                    with self.assertRaises(ec.EcError) as raised:
                        ec.decode_point(ec.P256, encoding)
                    self.assertEqual(raised.exception.code, entry['expected']['error'])
                    if 'reducesTo' in entry:
                        x = int.from_bytes(encoding[1:], 'big')
                        self.assertGreaterEqual(x, ec.P256.p)
                        self.assertEqual(ec.int32(x % ec.P256.p).hex(), entry['reducesTo']['x'])
                        self.assertEqual(ec.sqrt_mod(ec.P256, (x % ec.P256.p) ** 3 - 3 * (x % ec.P256.p) + ec.P256.b) is not None, entry['reducesTo']['validX'])
                    self.assertEqual(len(entry['requests']), 4)
                    for request in entry['requests']:
                        self.assertEqual(m.request_fields(self, request)[request['field']], encoding)
                        with self.assertRaises(ec.EcError) as raised:
                            m.dispatch(wallets[entry['wallet']], request['method'], request['args'])
                        self.assertEqual(raised.exception.code, entry['expected']['error'])
                elif kind == 'request-rejection':
                    if 'input' in entry['request']:
                        m.request_fields(self, entry['request'])
                    with self.assertRaises(ec.EcError) as raised:
                        m.dispatch(wallets[entry['wallet']], entry['request']['method'], entry['request']['args'])
                    self.assertEqual(raised.exception.code, entry['expected']['error'])
                elif kind == 'behaviour':
                    self.assertTrue(all(isinstance(entry[k], str) and entry[k] for k in ('given', 'when', 'then')))
                    behavioural += 1
                else:
                    self.fail(f'unknown kind {kind}')
        self.assertEqual((len(VC['cases']), behavioural), (177, 12))

    def check_module(self, roots, wallets, by_id, entry):
        wallet = wallets[entry['wallet']]
        request = entry['request']
        fields = m.request_fields(self, request)
        operation = request['args']['protocolID'][1].split(' ')[2]
        approve = entry.get('prompt') == 'approve'
        if approve:
            with self.assertRaises(ec.EcError) as raised:
                m.dispatch(wallet, request['method'], request['args'])
            self.assertEqual(raised.exception.code, 'prompt-required')
        root = None if operation == 'open' else m.selected_root(VC, wallets, entry['wallet'], request)
        if 'path' in fields and root is not None:
            check_intermediates(self, root, entry, fields)
        expected = entry['expected']
        if operation == 'decrypt':
            self.check_decrypt(root, entry, fields)
        if 'error' in expected:
            with self.assertRaises(ec.EcError) as raised:
                m.dispatch(wallet, request['method'], request['args'])
            self.assertEqual(raised.exception.code, expected['error'])
            if expected['error'] == 'scalar-rejected':
                self.assertGreaterEqual(int(entry['intermediate']['hmac'], 16), ec.P256.n)
                grind = VC['generator']['grind']['path']
                digits = ''.join(CROCKFORD[(grind['counter'] >> (5 * (15 - i))) & 31] for i in range(16))
                self.assertEqual(fields['path'], grind['prefix'] + digits)
                self.assertEqual(fields['path'], grind['identifier'])
                shared = ec.compress(ec.P256, ec.mul(ec.P256, root.r, ec.decode_point(ec.P256, root.R)))
                self.assertEqual(shared.hex(), grind['hmacKey'])
            return
        result = m.dispatch(wallet, request['method'], request['args'], approve=approve)
        if operation == 'decrypt':
            self.assertEqual(result.hex(), expected['plaintext'])
            return
        self.assertEqual(result.hex(), expected['ciphertext'])
        if operation == 'open':
            self.assertEqual(len(result), 66)
            if 'matches' in entry:
                derived = by_id[entry['matches']]['expected']
                self.assertEqual(result.hex(), derived['p256PublicKey'] + derived['secp256k1PublicKey'])
        if operation == 'key' and 'path' not in fields:
            self.assertEqual(result, root.R)
        for variant in entry.get('variants', []):
            self.assertEqual(m.dispatch(wallet, request['method'], {**request['args'], **variant}).hex(), expected['ciphertext'])
        if 'sameAs' in entry:
            self.assertEqual(by_id[entry['sameAs']]['expected']['ciphertext'], expected['ciphertext'])
        if 'differsFrom' in entry:
            self.assertNotEqual(by_id[entry['differsFrom']]['expected']['ciphertext'], expected['ciphertext'])
        if operation == 'sign':
            public = ec.base_mul(ec.P256, m.own_child(ec.P256, root.r, fields.get('peer') or root.R, fields['path']))
            r, s = int(result[:32].hex(), 16), int(result[32:].hex(), 16)
            self.assertLessEqual(s, ec.P256.n // 2)
            self.assertTrue(ec.ecdsa_verify(ec.P256, public, ec.sha256(fields['msg']), r, s))

    def check_decrypt(self, root, entry, fields):
        """The entry's key agreement with the one candidate key; when the key is right, the whole decryption."""
        known = entry['intermediate']
        child = m.own_child(ec.P256, root.r, fields['peer'], fields['path'])
        joint, ephemeral = m.check_jwe_shape(fields['jwe'])
        if 'z' in known:
            z = ec.ecdh_x(ec.P256, child, ec.decode_point(ec.P256, ephemeral))
            kek = ec.concat_kdf_sha256(z, 256, b'ECDH-ES+A256KW')
            self.assertEqual((z.hex(), kek.hex()), (known['z'], known['kek']))
            if 'cek' not in known:
                with self.assertRaises(ec.EcError) as raised:
                    ec.aes_key_unwrap(kek, m.b64u_decode(fields['jwe']['encrypted_key']))
                self.assertEqual(raised.exception.code, 'decrypt-failed')
        if 'error' in entry['expected']:
            return
        opened = m.jwe_decrypt(child, fields['jwe'])
        self.assertEqual((opened['cek'].hex(), opened['plaintext'].hex()), (known['cek'], entry['expected']['plaintext']))
        self.assertEqual(fields['jwe']['header']['kid'], ec.compress(ec.P256, ec.base_mul(ec.P256, child)).hex())
        key_path = fields['path'].split('-', 2)[2]
        if key_path.split('/')[-2] == VC['wallets']['profile']['keywords']['action']:
            self.assertEqual((joint['proto'], key_path.rsplit('/', 1)[1]), (VC['profile']['formatIdentifier'], joint['aid']))
        else:
            self.assertNotIn('proto', joint)


class LaboratoryProfile(unittest.TestCase):
    """Both module suites use the published laboratory deployment profile byte for byte (KEYS §1.3.1)."""

    def test_suites_use_the_published_profile(self):
        lab = json.loads((ROOT / 'fixtures/sdx/v1/deployment-profile.json').read_text(encoding='utf-8'))
        k1 = json.loads((ROOT / 'fixtures/sdx/v1/vc-sdx-k1/vectors.json').read_text(encoding='utf-8'))
        derivation = lab['derivation']
        kw = derivation['keyPath']['keywords']
        keywords = {'account': kw['level1'], 'runtime': kw['level2'], 'action': kw['level3'], 'session': kw['level3Session'], 'delegation': kw['level3Delegation'], 'actor': kw['delegationActor']}
        roles = {'encryption': 'encryption', 'signing': 'signing', 'delegation': 'delegation', 'transport authentication': 'transportAuthentication', 'rotation': 'rotation', 'handoff': 'handoff'}
        for doc in (VC, k1):
            self.assertEqual(doc['profile']['file'], 'fixtures/sdx/v1/deployment-profile.json')
            self.assertEqual((doc['profile']['formatIdentifier'], doc['profile']['credentialType']), (lab['formatIdentifier']['value'], derivation['credentialType']['value']))
            self.assertEqual(doc['profile']['labels'], {k: derivation['curveLabels'][k] for k in ('secp256k1', 'p256')})
            for row in doc['wallets']['profile']['namespaces']:
                self.assertEqual(row['namespace'], derivation['namespaces'][roles[row['role']]])
            self.assertEqual(doc['wallets']['profile']['keywords'], keywords)
            self.assertEqual(doc['wallets']['profile']['purposes'], [p['purpose'] for p in derivation['keyPath']['purposes']])


class Negatives(unittest.TestCase):
    """Altered vectors fail the checks above."""

    def failures(self, check, name, mutate):
        doc = copy.deepcopy(globals()[name])
        mutate({entry['id']: entry for entry in doc['cases']}, doc)
        saved, globals()[name] = globals()[name], doc
        try:
            result = unittest.TestResult()
            check('test_vectors_recomputed').run(result)
            return len(result.failures) + len(result.errors)
        finally:
            globals()[name] = saved

    def test_altered_vectors_fail(self):
        def flip(text):
            return text[:-1] + ('1' if text[-1] == '0' else '0')

        def raw_form(entry):
            entry['expected']['ciphertext'] = entry['intermediate']['rfc6979']

        def reencode(entry):
            entry['request']['args']['plaintext'] = m.cbor_input(m.input_from_json(entry['request']['input'])).hex()

        vc = [
            lambda c, d: c['key-record-signing-self']['expected'].update(ciphertext=flip(c['key-record-signing-self']['expected']['ciphertext'])),
            lambda c, d: c['key-root-public-key']['expected'].update(ciphertext=c['key-record-signing-self']['expected']['ciphertext']),
            lambda c, d: raw_form(c['sign-record-normalised']),
            lambda c, d: c['es256-rfc6979-a25-sample']['expected'].update(signature=c['es256-rfc6979-a25-sample']['expected']['rfc6979']),
            lambda c, d: c['decrypt-outer-self']['intermediate'].update(kek=flip(c['decrypt-outer-self']['intermediate']['kek'])),
            lambda c, d: c['decrypt-outer-recipient-entry']['expected'].update(plaintext=flip(c['decrypt-outer-recipient-entry']['expected']['plaintext'])),
            lambda c, d: c['decrypt-field-recipient-entry']['intermediate'].update(cek=flip(c['decrypt-field-recipient-entry']['intermediate']['cek'])),
            lambda c, d: c['decrypt-wrong-path'].update(expected=c['decrypt-field-recipient-entry']['expected']),
            lambda c, d: c['decrypt-signing-namespace']['expected'].update(error='path-not-granted'),
            lambda c, d: c['decrypt-epk-y-mismatch']['expected'].update(error='jwe-shape'),
            lambda c, d: c['key-purpose-unregistered']['expected'].update(error='key-path-grammar'),
            lambda c, d: c['key-path-record-keyword']['expected'].update(error='path-not-granted'),
            lambda c, d: c['key-namespace-rotation']['expected'].update(error='path-not-granted'),
            lambda c, d: d['wallets']['profile'].update(purposes=d['wallets']['profile']['purposes'] + ['photo']),
            lambda c, d: d['profile'].update(formatIdentifier='sdx:record:v1'),
            lambda c, d: c['point-x-equals-p']['expected'].update(error='point-not-on-curve'),
            lambda c, d: c['decrypt-with-sign']['expected'].update(error='method-not-permitted'),
            lambda c, d: c['path-outside-grant-account']['expected'].update(error='no-grant'),
            lambda c, d: c['cbor-unsorted-keys']['expected'].update(error='unknown-member'),
            lambda c, d: c['key-path-nfd']['expected'].update(ciphertext=c['key-path-nfc']['expected']['ciphertext']),
            lambda c, d: (c['key-actor-persistent-0']['request']['input'].update(path='2-sdx delegate-actor/1'), reencode(c['key-actor-persistent-0'])),
            lambda c, d: c['split-session']['expected'].update(secp256k1Seed=flip(c['split-session']['expected']['secp256k1Seed'])),
            lambda c, d: c['wallet-root-epoch-0']['expected'].update(ikm=flip(c['wallet-root-epoch-0']['expected']['ikm'])),
            lambda c, d: c['wallet-root-epoch-1']['input'].update(salt='p p256 v1'),
            lambda c, d: c['wallet-root-new-account']['intermediate'].update(hmac=flip(c['wallet-root-new-account']['intermediate']['hmac'])),
            lambda c, d: d['generator']['grind']['path'].update(counter=d['generator']['grind']['path']['counter'] + 1),
            lambda c, d: c['peer-recipient-record-kid']['request']['args'].update(plaintext=flip(c['peer-recipient-record-kid']['request']['args']['plaintext'])),
            lambda c, d: c['open-current-epoch']['expected'].update(ciphertext=c['open-earlier-epoch']['expected']['ciphertext']),
            lambda c, d: c['open-creates-account'].pop('prompt'),
            lambda c, d: c['key-second-account-epoch-0']['expected'].update(ciphertext=c['key-second-account-root']['expected']['ciphertext']),
            lambda c, d: c['unknown-epoch']['expected'].update(error='unknown-account'),
            lambda c, d: c['no-grant-unheld-account']['expected'].update(error='unknown-account'),
            lambda c, d: c['no-grant-unheld-epoch']['expected'].update(error='unknown-epoch'),
            lambda c, d: c['session-path-names-no-session']['expected'].update(error='path-not-granted'),
            lambda c, d: c['sign-encryption-namespace']['expected'].update(error='path-not-granted'),
            lambda c, d: c['ep-negative']['expected'].update(error='input-encoding'),
            lambda c, d: c['key-session-p256'].update(wallet='account'),
            lambda c, d: d['wallets']['entries']['account']['grants'][2].update(prefixes=[d['wallets']['entries']['account']['grants'][3]['prefixes'][1][:-1]]),
            lambda c, d: c['decrypt-outer-writer-entry']['request']['input']['jwe'].update(tag=c['decrypt-outer-self']['request']['input']['jwe']['tag']),
            lambda c, d: d['wallets']['entries']['account']['accounts'][1].update(current=0),
            lambda c, d: d['wallets']['walletRootDerivation'].update(salt='p p256 v1'),
            lambda c, d: d['profile']['accountTags'].update({d['profile']['identifiers']['accountId']: '00' * 16}),
            lambda c, d: d.update(claim='CONFORMANT'),
        ]
        for index, mutate in enumerate(vc):
            with self.subTest(suite='VC-P256', mutation=index):
                self.assertGreater(self.failures(VcP256, 'VC', mutate), 0)


class Primitives(unittest.TestCase):
    """sdx_ec and sdx_module against published vectors, so later suites can rely on them."""

    def test_rfc6979_a25(self):
        d = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
        self.assertEqual(ec.compress(ec.P256, ec.base_mul(ec.P256, d)).hex(), '0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6')
        r, s, k = ec.ecdsa_sign_rfc6979(ec.P256, d, ec.sha256(b'sample'))
        self.assertEqual((hex(k), hex(r), hex(s)), (
            '0xa6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60',
            '0xefd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716',
            '0xf7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8'))
        self.assertEqual(ec.ecdsa_sign_rfc6979(ec.P256, d, ec.sha256(b'sample'), low_s=True)[1], ec.P256.n - s)
        self.assertFalse(ec.ecdsa_verify(ec.P256, ec.base_mul(ec.P256, d), ec.sha256(b'samplf'), r, s))

    def test_brc42_and_brc2(self):
        child = ec.brc42_child_private(0x6a1751169c111b4667a6539ee1be6b7cd9f6e9c8fe011a5f2fe31e03a15e0ede, ec.decode_point(ec.SECP256K1, unhex('033f9160df035156f1c48e75eae99914fa1a1546bec19781e8eddb900200bff9d1')), 'f3WCaUmnN9U=')
        self.assertEqual(ec.int32(child).hex(), '761656715bbfa172f8f9f58f5af95d9d0dfd69014cfdcacc9a245a10ff8893ef')
        public = ec.brc42_child_public(0x583755110a8c059de5cd81b8a04e1be884c46083ade3f779c1e022f6f89da94c, ec.decode_point(ec.SECP256K1, unhex('02c0c1e1a1f7d247827d1bcf399f0ef2deef7695c322fd91a01a91378f101b6ffc')), 'IBioA4D/OaE=')
        self.assertEqual(ec.compress(ec.SECP256K1, public).hex(), '03c1bf5baadee39721ae8c9882b3cf324f0bf3b9eb3fc1b8af8089ca7a7c2e669f')
        # BRC-2's published HMAC vector checks the symmetric key without AES.
        key = ec.brc2_symmetric_key(0x6a2991c9de20e38b31d7ea147bf55f5039e4bbc073160f5e0d541d1f17e321b8, ec.decode_point(ec.SECP256K1, unhex('0294c479f762f6baa97fbcd4393564c1d7bd8336ebd15928135bbcf575cd1a71a1')), m.invoice([2, 'BRC2 Test'], '42'))
        self.assertEqual(list(ec.hmac_sha256(key, b'BRC-2 HMAC Compliance Validated!')), [81, 240, 18, 153, 163, 45, 174, 85, 9, 246, 142, 125, 209, 133, 82, 76, 254, 103, 46, 182, 86, 59, 219, 61, 126, 30, 176, 232, 233, 100, 234, 14])

    def test_point_validation_and_rejections(self):
        valid = ec.compress(ec.P256, ec.base_mul(ec.P256, 7))
        self.assertEqual(ec.compress(ec.P256, ec.decode_point(ec.P256, valid)), valid)
        for encoding, code in (
            (b'\x02' + b'\xff' * 32, 'point-x-range'), (b'\x02' + ec.int32(ec.P256.p), 'point-x-range'),
            (b'\x02' + ec.int32(1), 'point-not-on-curve'), (b'\x04' + valid[1:], 'point-prefix'),
            (valid + b'\x00', 'point-length'), (b'\x00', 'point-length'), (b'', 'point-length'),
        ):
            with self.assertRaises(ec.EcError) as raised:
                ec.decode_point(ec.P256, encoding)
            self.assertEqual(raised.exception.code, code)
        for curve in (ec.P256, ec.SECP256K1):
            for value in (0, curve.n, curve.n + 1, (1 << 256) - 1):
                self.assertRaises(ec.EcError, ec.check_offset, curve, ec.int32(value))
            for value in (1, curve.n - 1):
                self.assertEqual(ec.check_offset(curve, ec.int32(value)), value)
        self.assertEqual(ec.mul(ec.P256, ec.P256.n, ec.P256.g), None)
        self.assertEqual(ec.add(ec.P256, ec.P256.g, ec.neg(ec.P256, ec.P256.g)), None)

    def test_hkdf_and_concat_kdf(self):
        # RFC 5869 Appendix A.1.
        okm = ec.hkdf_sha256(bytes([0x0b] * 22), bytes(range(13)), bytes(range(0xf0, 0xfa)), 42)
        self.assertEqual(okm.hex(), '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865')
        # RFC 7518 Appendix C (ECDH-ES, A128GCM) Concat KDF example.
        z = bytes([158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196])
        self.assertEqual(ec.concat_kdf_sha256(z, 128, b'A128GCM', b'Alice', b'Bob'), bytes([86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26]))

    def test_aes_known_answers(self):
        key = bytes(range(32))
        keys = ec.aes256_round_keys(key)
        # FIPS 197 Appendix C.3 (AES-256).
        block = ec.aes256_encrypt_block(keys, bytes.fromhex('00112233445566778899aabbccddeeff'))
        self.assertEqual(block.hex(), '8ea2b7ca516745bfeafc49904b496089')
        self.assertEqual(ec.aes256_decrypt_block(keys, block).hex(), '00112233445566778899aabbccddeeff')
        # RFC 3394 §4.6: 256 bits of key data wrapped with a 256-bit KEK.
        wrapped = bytes.fromhex('28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21')
        self.assertEqual(ec.aes_key_unwrap(key, wrapped).hex(), '00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f')
        with self.assertRaises(ec.EcError) as raised:
            ec.aes_key_unwrap(key, wrapped[:-1] + bytes([wrapped[-1] ^ 1]))
        self.assertEqual(raised.exception.code, 'decrypt-failed')
        # The GCM specification (McGrew and Viega), test case 16: AES-256, 96-bit IV, with AAD.
        gcm_key = bytes.fromhex('feffe9928665731c6d6a8f9467308308' * 2)
        iv, aad = bytes.fromhex('cafebabefacedbaddecaf888'), bytes.fromhex('feedfacedeadbeeffeedfacedeadbeefabaddad2')
        ciphertext = bytes.fromhex('522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662')
        tag = bytes.fromhex('76fc6ece0f4e1768cddf8853bb2d551b')
        self.assertEqual(ec.aes_gcm_decrypt(gcm_key, iv, aad, ciphertext, tag).hex(), 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39')
        for bad in ((iv, aad[:-1], ciphertext, tag), (iv, aad, ciphertext, tag[:-1] + bytes([tag[-1] ^ 1]))):
            with self.assertRaises(ec.EcError) as raised:
                ec.aes_gcm_decrypt(gcm_key, *bad)
            self.assertEqual(raised.exception.code, 'decrypt-failed')

    def test_strict_cbor_decoder(self):
        good = m.cbor_input({'path': 'abc', 'peer': b'\x01\x02'})
        self.assertEqual(m.decode_input(good), {'path': 'abc', 'peer': b'\x01\x02'})
        self.assertEqual(m.cbor_input({'ep': 1, 'path': 'abc'}).hex(), 'a262657001647061746863616263')
        self.assertEqual(m.decode_input(m.cbor_input({'ep': 1 << 40})), {'ep': 1 << 40})
        self.assertEqual(m.decode_input(m.cbor_input({'ep': -1})), {'ep': -1})
        path_entry, peer_entry = m.cbor_input({'path': 'abc'})[1:], m.cbor_input({'peer': b'\x01\x02'})[1:]
        for bad in (b'\xa1', b'\xa2' + peer_entry + path_entry, b'\xa2' + path_entry + path_entry,
                    b'\xa1\x78\x04path' + path_entry[5:], good + b'\x00', b'\xbf' + path_entry + b'\xff',
                    b'\xa1' + path_entry[:5] + b'\x62\xc3\x28', bytes.fromhex('a16265701801'), bytes.fromhex('a1626570190001'),
                    b'\xa1' + path_entry[:5] + b'\xf9\x3c\x00'):
            with self.assertRaises(ec.EcError) as raised:
                m.decode_input(bad)
            self.assertEqual(raised.exception.code, 'input-encoding')


if __name__ == '__main__':
    unittest.main()
