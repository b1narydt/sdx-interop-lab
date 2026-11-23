"""LAB_SELF_TEST_ONLY: the Python standard-library checker (test/sdx_anc.py) reproduces every
VA-ANC outcome and every laboratory-derived VA-ENC case, reading only the suite files and the
laboratory deployment profile."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sdx_anc  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(rel):
    with open(os.path.join(ROOT, rel), 'rb') as handle:
        return json.loads(handle.read())


VA_ANC = load('fixtures/sdx/v1/va-anc/vectors.json')
VA_ENC = load('fixtures/sdx/v1/va-enc/vectors.json')
PROFILE = load('fixtures/sdx/v1/deployment-profile.json')


def materialize(spec):
    kind = spec['kind']
    if kind == 'value':
        return spec['value']
    if kind == 'uint8array':
        return bytes(spec['bytes'])
    if kind == 'object':
        return {k: materialize(v) for k, v in spec['fields'].items()}
    if kind == 'absent':
        return sdx_anc.UNDEFINED
    if kind == 'timestamp':
        return spec['ms']  # ENV §3 rule 7: integer milliseconds, untagged
    if kind == 'array':
        return [materialize(item) for item in spec['items']]
    raise ValueError(kind)


class VaAncTest(unittest.TestCase):
    def test_suite_identity(self):
        self.assertEqual(VA_ANC['claim'], 'LAB_SELF_TEST_ONLY')
        self.assertEqual(VA_ANC['profile']['id'], PROFILE['profile'])
        self.assertEqual(VA_ANC['profile']['path'], 'fixtures/sdx/v1/deployment-profile.json')

    def test_every_case(self):
        results = {}
        for item in VA_ANC['cases']:
            with self.subTest(case=item['id']):
                got = sdx_anc.run_case(VA_ANC, PROFILE, item)
                self.assertEqual(got, item['expected'])
                results[item['verifier']] = results.get(item['verifier'], 0) + 1
        self.assertGreaterEqual(results.get('reference', 0), 15)
        self.assertGreaterEqual(results.get('walk', 0), 15)

    def test_commitment_key_of_the_worked_example(self):
        identifier = sdx_anc.commitment_identifier(PROFILE, '3MNQpxFAsp', '8kRt2wVbZq', '01JB8ZK3QN7T4YVX2C9M5RDPWA')
        self.assertEqual(identifier, '2-sdx sign-account/3MNQpxFAsp/runtime/8kRt2wVbZq/action/01JB8ZK3QN7T4YVX2C9M5RDPWA')
        root = bytes.fromhex(VA_ANC['testKeys']['roots']['participant']['0']['root'])
        beef = sdx_anc.parse_beef(bytes.fromhex(VA_ANC['transactions']['M0']['beef']))
        tx = beef['txs'][beef['subject']]['tx']
        ok, _, _, key = sdx_anc.check_container(tx['outputs'][VA_ANC['transactions']['M0']['entryOutput']]['script'])
        self.assertTrue(ok)
        self.assertEqual(key, sdx_anc.commitment_key(PROFILE, root, '3MNQpxFAsp', '8kRt2wVbZq', '01JB8ZK3QN7T4YVX2C9M5RDPWA'))


class VaEncLabCasesTest(unittest.TestCase):
    def test_laboratory_derived_cases(self):
        lab = [item for item in VA_ENC['cases'] if item['origin'] == 'lab-derived']
        self.assertGreaterEqual(len(lab), 30)
        for item in lab:
            with self.subTest(case=item['id']):
                if item['direction'] == 'encode':
                    spec = item['input']
                    if spec['kind'] == 'set':
                        data = sdx_anc.encode_set([materialize(i) for i in spec['items']])
                    else:
                        data = sdx_anc.encode(materialize(spec))
                    self.assertEqual(data.hex(), item['expected']['encodedHex'])
                    continue
                data = bytes.fromhex(item['input']['hex'])
                for expected, decoder in ((item['expected'], sdx_anc.decode), (item['informative']['strict'], sdx_anc.decode_strict)):
                    try:
                        value = decoder(data)
                        got = {'result': 'ACCEPT', 'canonicalHex': sdx_anc.encode(value).hex()}
                    except sdx_anc.CborError as error:
                        got = {'result': 'REJECT', 'reason': error.code}
                    self.assertEqual(got, expected)


if __name__ == '__main__':
    unittest.main()
