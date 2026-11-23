"""LAB_SELF_TEST_ONLY: standard-library checker for the VC-SDX-K1 suite.

Every value is recomputed here with test/sdx_ec.py and test/sdx_module.py,
independently of the generator and of the node:crypto checker: secp256k1 child
keys and the BRC-100 getPublicKey results they equal, RFC 6979 nonces, low-S
DER signatures and their verification, account and epoch selection, the KEYS
§1.12 item 7 offset range, point validation, the namespace and key-path rules,
request rules, and the BIP-143 preimage and spend of the commitment-spend
transaction. No case needs AES.
"""

import copy
import hashlib
import json
import unittest
from pathlib import Path

import sdx_ec as ec
import sdx_module as m

ROOT = Path(__file__).resolve().parents[1]
K1 = json.loads((ROOT / 'fixtures/sdx/v1/vc-sdx-k1/vectors.json').read_text(encoding='utf-8'))
unhex = m.unhex
N = ec.SECP256K1.n


def sha256d(data):
    return ec.sha256(ec.sha256(data))


def read_varint(data, at):
    first = data[at]
    if first < 0xfd:
        return first, at + 1
    width = {0xfd: 2, 0xfe: 4, 0xff: 8}[first]
    return int.from_bytes(data[at + 1:at + 1 + width], 'little'), at + 1 + width


def parse_tx(data):
    """A serialised transaction: version, inputs, outputs and lock time; txid in internal byte order."""
    at = 4
    version = int.from_bytes(data[:4], 'little')
    count, at = read_varint(data, at)
    inputs = []
    for _ in range(count):
        prev, vout = data[at:at + 32], int.from_bytes(data[at + 32:at + 36], 'little')
        length, at = read_varint(data, at + 36)
        script = data[at:at + length]
        sequence = int.from_bytes(data[at + length:at + length + 4], 'little')
        at += length + 4
        inputs.append((prev, vout, script, sequence))
    count, at = read_varint(data, at)
    outputs = []
    for _ in range(count):
        start = at
        satoshis = int.from_bytes(data[at:at + 8], 'little')
        length, at = read_varint(data, at + 8)
        outputs.append((satoshis, data[at:at + length], data[start:at + length]))
        at += length
    lock_time = int.from_bytes(data[at:at + 4], 'little')
    if at + 4 != len(data):
        raise AssertionError('trailing bytes')
    return {'version': version, 'inputs': inputs, 'outputs': outputs, 'lockTime': lock_time, 'txid': sha256d(data)}


def bip143_preimage(tx, index, script_code, satoshis, sighash):
    """SIGHASH_ALL|FORKID preimage (the only type the suite uses)."""
    if sighash != 0x41:
        raise AssertionError('only SIGHASH_ALL|FORKID is used')
    prevouts = sha256d(b''.join(prev + vout.to_bytes(4, 'little') for prev, vout, _, _ in tx['inputs']))
    sequences = sha256d(b''.join(seq.to_bytes(4, 'little') for _, _, _, seq in tx['inputs']))
    outputs = sha256d(b''.join(raw for _, _, raw in tx['outputs']))
    prev, vout, _, sequence = tx['inputs'][index]
    length = bytes([len(script_code)]) if len(script_code) < 0xfd else b'\xfd' + len(script_code).to_bytes(2, 'little')
    return (tx['version'].to_bytes(4, 'little') + prevouts + sequences + prev + vout.to_bytes(4, 'little') + length + script_code
            + satoshis.to_bytes(8, 'little') + sequence.to_bytes(4, 'little') + outputs + tx['lockTime'].to_bytes(4, 'little') + sighash.to_bytes(4, 'little'))


def brc100_public_key(root, args):
    """Stock BRC-100 getPublicKey for a wallet whose root is the selected root's secp256k1 seed."""
    if args.get('identityKey') is True:
        return root.K
    counterparty = root.K if args['counterparty'] == 'self' else unhex(args['counterparty'])
    point = ec.decode_point(ec.SECP256K1, counterparty)
    invoice = m.invoice(args['protocolID'], args['keyID'])
    if args.get('forSelf') is True:
        return ec.compress(ec.SECP256K1, ec.base_mul(ec.SECP256K1, ec.brc42_child_private(root.k, point, invoice)))
    return ec.compress(ec.SECP256K1, ec.brc42_child_public(root.k, point, invoice))


class VcSdxK1(unittest.TestCase):
    """VC-SDX-K1: K1-01..05."""

    def test_vectors_recomputed(self):
        _, wallets = m.check_header(self, K1, 'VC-SDX-K1', ['K1-01', 'K1-02', 'K1-03', 'K1-04', 'K1-05'])
        by_id = {entry['id']: entry for entry in K1['cases']}
        behavioural = 0
        for entry in K1['cases']:
            with self.subTest(case=entry['id']):
                kind = entry['kind']
                if kind == 'module':
                    self.check_module(wallets, by_id, entry)
                elif kind == 'offset-range':
                    self.assertEqual((entry['curve'], entry['injected']), ('secp256k1', True))
                    values = [int(value['hmac'], 16) for value in entry['values']]
                    self.assertTrue(all(v in values for v in (0, 1, N - 1, N, N + 1)))
                    for value in entry['values']:
                        h = int(value['hmac'], 16)
                        self.assertEqual(value['expected'] == 'accept', 0 < h < N)
                        if value['expected'] == 'accept':
                            self.assertEqual(ec.check_offset(ec.SECP256K1, unhex(value['hmac'])), h)
                        else:
                            with self.assertRaises(ec.EcError) as raised:
                                ec.check_offset(ec.SECP256K1, unhex(value['hmac']))
                            self.assertEqual(str(raised.exception), 'scalar-rejected: secp256k1')
                elif kind == 'point-rejection':
                    self.assertEqual(entry['curve'], 'secp256k1')
                    encoding = unhex(entry['encoding'])
                    with self.assertRaises(ec.EcError) as raised:
                        ec.decode_point(ec.SECP256K1, encoding)
                    self.assertEqual(raised.exception.code, entry['expected']['error'])
                    if 'reducesTo' in entry:
                        x = int.from_bytes(encoding[1:], 'big') % ec.SECP256K1.p
                        self.assertEqual(ec.int32(x).hex(), entry['reducesTo']['x'])
                        self.assertEqual(ec.sqrt_mod(ec.SECP256K1, x ** 3 + 7) is not None, entry['reducesTo']['validX'])
                    self.assertEqual(len(entry['requests']), 3)
                    for request in entry['requests']:
                        self.assertEqual(m.request_fields(self, request)[request['field']], encoding)
                        with self.assertRaises(ec.EcError) as raised:
                            m.dispatch(wallets[entry['wallet']], request['method'], request['args'])
                        self.assertEqual(raised.exception.code, entry['expected']['error'])
                elif kind == 'request-rejection':
                    m.request_fields(self, entry['request'])
                    with self.assertRaises(ec.EcError) as raised:
                        m.dispatch(wallets[entry['wallet']], entry['request']['method'], entry['request']['args'])
                    self.assertEqual(raised.exception.code, entry['expected']['error'])
                elif kind == 'behaviour':
                    self.assertTrue(all(isinstance(entry[k], str) and entry[k] for k in ('given', 'when', 'then')))
                    behavioural += 1
                else:
                    self.fail(f'unknown kind {kind}')
        self.assertEqual((len(K1['cases']), behavioural), (72, 6))

    def check_module(self, wallets, by_id, entry):
        wallet, request = wallets[entry['wallet']], entry['request']
        fields = m.request_fields(self, request)
        operation = request['args']['protocolID'][1].split(' ')[2]
        self.assertIn(operation, ('k1key', 'k1peer', 'k1sign'))
        root = m.selected_root(K1, wallets, entry['wallet'], request)
        result = m.dispatch(wallet, request['method'], request['args'])
        self.assertEqual(result.hex(), entry['expected']['ciphertext'])
        for variant in entry.get('variants', []):
            self.assertEqual(m.dispatch(wallet, request['method'], {**request['args'], **variant}).hex(), entry['expected']['ciphertext'])
        if 'sameAs' in entry:
            self.assertEqual(by_id[entry['sameAs']]['expected']['ciphertext'], entry['expected']['ciphertext'])
        if 'differsFrom' in entry:
            self.assertNotEqual(by_id[entry['differsFrom']]['expected']['ciphertext'], entry['expected']['ciphertext'])
        if 'path' not in fields:
            self.assertEqual(result, root.K)
            self.assertEqual(entry['brc100']['args'], {'identityKey': True})
        else:
            peer = fields.get('peer') or root.K
            shared, digest, _ = m.derive(ec.SECP256K1, root.k, peer, fields['path'])
            known = entry['intermediate']
            self.assertEqual((shared.hex(), digest.hex()), (known['sharedPoint'], known['hmac']))
            if 'childPrivate' in known:
                self.assertEqual(ec.int32(m.own_child(ec.SECP256K1, root.k, peer, fields['path'])).hex(), known['childPrivate'])
            level, namespace, key_path = m.IDENTIFIER.fullmatch(fields['path']).groups()
            stock = entry['brc100']['args']
            self.assertEqual((stock['protocolID'], stock['keyID'], stock['counterparty']), ([int(level), namespace], key_path, fields['peer'].hex() if 'peer' in fields else 'self'))
        if operation == 'k1sign':
            self.check_signature(by_id, entry, root, fields, result)
            return
        self.assertEqual(entry['brc100']['method'], 'getPublicKey')
        self.assertEqual(entry['brc100'].get('args', {}).get('forSelf') is True, operation == 'k1key' and 'path' in fields)
        self.assertEqual(brc100_public_key(root, entry['brc100']['args']).hex(), entry['brc100']['publicKey'])
        self.assertEqual(entry['brc100']['publicKey'], entry['expected']['ciphertext'])

    def check_signature(self, by_id, entry, root, fields, signature):
        known = entry['intermediate']
        peer = fields.get('peer') or root.K
        child = m.own_child(ec.SECP256K1, root.k, peer, fields['path'])
        public = ec.base_mul(ec.SECP256K1, child)
        self.assertEqual(ec.compress(ec.SECP256K1, public).hex(), known['publicKey'])
        r, s = ec.der_decode(signature)
        self.assertLessEqual(s, N // 2)
        self.assertTrue(ec.ecdsa_verify(ec.SECP256K1, public, fields['hash'], r, s))
        self.assertFalse(ec.ecdsa_verify(ec.SECP256K1, public, ec.sha256(fields['hash']), r, s), 'the hash is not hashed again')
        raw_r, raw_s, _ = ec.ecdsa_sign_rfc6979(ec.SECP256K1, child, fields['hash'])
        self.assertEqual((ec.int32(raw_r) + ec.int32(raw_s)).hex(), known['rfc6979'])
        self.assertEqual((raw_r, N - raw_s if raw_s > N // 2 else raw_s), (r, s))
        self.assertEqual(raw_s > N // 2, known['normalised'])
        self.assertEqual(entry['brc100']['method'], 'createSignature')
        self.assertEqual(entry['brc100']['args']['hashToDirectlySign'], fields['hash'].hex())
        self.assertEqual(entry['brc100']['signature'], entry['expected']['ciphertext'])
        if 'transaction' in entry:
            tx = entry['transaction']
            previous, spending = parse_tx(unhex(tx['previous'])), parse_tx(unhex(tx['spending']))
            prev, vout, unlocking, _ = spending['inputs'][tx['inputIndex']]
            self.assertEqual((prev, vout), (previous['txid'], 0))
            satoshis, lock, _ = previous['outputs'][0]
            # ANC §2.1: <record-bytes> DROP <commitment-key> CHECKSIG, the push minimal.
            length = lock[0]
            self.assertTrue(1 < length <= 75)
            self.assertEqual(lock[1 + length:], b'\x75\x21' + unhex(by_id['k1key-commitment-key']['expected']['ciphertext']) + b'\xac')
            preimage = bip143_preimage(spending, tx['inputIndex'], lock, satoshis, tx['sighashType'])
            self.assertEqual(preimage.hex(), tx['preimage'])
            self.assertEqual(sha256d(preimage), fields['hash'])
            self.assertEqual(unlocking, bytes([len(signature) + 1]) + signature + bytes([tx['sighashType']]))
            key = ec.decode_point(ec.SECP256K1, lock[length + 3:length + 36])
            self.assertTrue(ec.ecdsa_verify(ec.SECP256K1, key, sha256d(preimage), r, s), 'the spend verifies under the container key')


    def test_altered_vectors_fail(self):
        def flip(text):
            return text[:-1] + ('1' if text[-1] == '0' else '0')

        mutations = [
            lambda c, d: c['k1key-commitment-key']['expected'].update(ciphertext=flip(c['k1key-commitment-key']['expected']['ciphertext'])),
            lambda c, d: c['k1peer-handoff-lock']['brc100'].update(publicKey=flip(c['k1peer-handoff-lock']['brc100']['publicKey'])),
            lambda c, d: c['k1key-handoff-recipient-side']['brc100']['args'].pop('forSelf'),
            lambda c, d: c['k1sign-unchanged']['intermediate'].update(normalised=True),
            lambda c, d: c['k1sign-normalised']['expected'].update(ciphertext=ec.der_encode(*(lambda rs: (rs[0], N - rs[1]))(ec.der_decode(unhex(c['k1sign-normalised']['expected']['ciphertext'])))).hex()),
            lambda c, d: c['k1sign-commitment-spend']['transaction'].update(preimage=flip(c['k1sign-commitment-spend']['transaction']['preimage'])),
            lambda c, d: c['k1key-second-account-epoch-0']['expected'].update(ciphertext=c['k1key-second-account-root']['expected']['ciphertext']),
            lambda c, d: c['k1-unknown-epoch']['expected'].update(error='unknown-account'),
            lambda c, d: c['k1-no-grant-from-sign']['expected'].update(error='unknown-account'),
            lambda c, d: c['k1-no-grant-unheld-account']['expected'].update(error='unknown-account'),
            lambda c, d: c['k1-point-x-equals-p']['expected'].update(error='point-not-on-curve'),
            lambda c, d: c['offset-range-secp256k1']['values'][0].update(expected='accept'),
            lambda c, d: c['k1key-namespace-rotation']['expected'].update(error='path-not-granted'),
            lambda c, d: c['k1key-purpose-unregistered']['expected'].update(error='key-path-grammar'),
            lambda c, d: c['k1key-path-record-keyword']['expected'].update(error='path-not-granted'),
            lambda c, d: c['k1sign-encryption-namespace']['expected'].update(error='path-not-granted'),
            lambda c, d: d['wallets']['entries']['account']['accounts'][1]['epochs'][0].update(K=d['wallets']['entries']['account']['accounts'][1]['epochs'][1]['K']),
            lambda c, d: d.update(claim='CONFORMANT'),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                global K1
                doc = copy.deepcopy(K1)
                mutate({entry['id']: entry for entry in doc['cases']}, doc)
                saved, K1 = K1, doc
                try:
                    result = unittest.TestResult()
                    VcSdxK1('test_vectors_recomputed').run(result)
                    self.assertGreater(len(result.failures) + len(result.errors), 0)
                finally:
                    K1 = saved


class Primitives(unittest.TestCase):
    """secp256k1 signing and DER, against a published known answer."""

    def test_rfc6979_secp256k1_known_answer(self):
        # Private key 1, hash SHA-256("Satoshi Nakamoto"): the secp256k1 RFC 6979 known
        # answer that bitcoinjs-lib and python-ecdsa publish.
        digest = hashlib.sha256(b'Satoshi Nakamoto').digest()
        r, s, k = ec.ecdsa_sign_rfc6979(ec.SECP256K1, 1, digest, low_s=True)
        self.assertEqual(hex(k), '0x8f8a276c19f4149656b280621e358cce24f5f52542772691ee69063b74f15d15')
        self.assertEqual((hex(r), hex(s)), ('0x934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8', '0x2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5'))
        self.assertEqual(ec.der_decode(ec.der_encode(r, s)), (r, s))
        self.assertTrue(ec.ecdsa_verify(ec.SECP256K1, ec.SECP256K1.g, digest, r, N - s), 'verifiers accept either S')

    def test_der_and_point_rejections(self):
        for bad in ('300602010102010100', '300602010002010101', '30060201ff020101', '30070202000102010100', '3006020101020101'[:-2]):
            with self.assertRaises(ec.EcError):
                ec.der_decode(bytes.fromhex(bad))
        for encoding, code in ((b'\x02' + ec.int32(ec.SECP256K1.p), 'point-x-range'), (b'\x03' + b'\xff' * 32, 'point-x-range'),
                               (b'\x04' + ec.int32(1), 'point-prefix'), (b'\x02' * 32, 'point-length')):
            with self.assertRaises(ec.EcError) as raised:
                ec.decode_point(ec.SECP256K1, encoding)
            self.assertEqual(raised.exception.code, code)


if __name__ == '__main__':
    unittest.main()
