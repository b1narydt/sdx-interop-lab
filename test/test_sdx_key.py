"""LAB_SELF_TEST_ONLY: the Python standard-library oracle (test/sdx_key.py) reproduces every
VA-KEY known answer under the laboratory deployment profile, and the curve-independence roots
differ in at least 100 of 256 bits (KEYS §1.12 item 6)."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sdx_key  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(rel):
    with open(os.path.join(ROOT, rel), 'rb') as handle:
        return json.loads(handle.read())


PROFILE = load('fixtures/sdx/v1/deployment-profile.json')
VA_KEY = load('fixtures/sdx/v1/va-key/vectors.json')


class KeyOracle(unittest.TestCase):
    def test_every_case(self):
        self.assertEqual(VA_KEY['claim'], 'LAB_SELF_TEST_ONLY')
        self.assertEqual(VA_KEY['caseCount'], len(VA_KEY['cases']))
        for case in VA_KEY['cases']:
            with self.subTest(case=case['id']):
                ok, actual = sdx_key.run_case(PROFILE, case)
                self.assertTrue(ok, f"{case['id']} {case['title']}: {actual}")

    def test_items_and_independence(self):
        items = {case['item'] for case in VA_KEY['cases']}
        self.assertEqual(items, {1, 2, 3, 5, 6, 7, 8, 9, 10, 11})  # item 4 is exercised by VA-SIG
        for case in VA_KEY['cases']:
            if case['item'] == 6:
                a, b = bytes.fromhex(case['expect']['secp256k1Seed']), bytes.fromhex(case['expect']['p256Seed'])
                self.assertGreaterEqual(sum(bin(x ^ y).count('1') for x, y in zip(a, b)), 100)


if __name__ == '__main__':
    unittest.main()
