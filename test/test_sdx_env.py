"""LAB_SELF_TEST_ONLY: the Python standard-library oracle (test/sdx_env.py) reproduces every
VA-ENV and VA-SIG outcome, including the laboratory refusal detail, and the write checks fail
exactly where each write-check qualification sample says. It reads only the suite files and the
laboratory deployment profile."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sdx_env  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(rel):
    with open(os.path.join(ROOT, rel), 'rb') as handle:
        return json.loads(handle.read())


PROFILE = load('fixtures/sdx/v1/deployment-profile.json')
SUITES = {name: load(f'fixtures/sdx/v1/{name}/vectors.json') for name in ('va-env', 'va-sig')}


class EnvelopeOracle(unittest.TestCase):
    def test_every_case(self):
        for name, suite in SUITES.items():
            self.assertEqual(suite['claim'], 'LAB_SELF_TEST_ONLY')
            self.assertEqual(suite['caseCount'], len(suite['cases']))
            for case in suite['cases']:
                with self.subTest(case=case['id']):
                    ok, actual, failures = sdx_env.run_case(PROFILE, case)
                    self.assertTrue(ok, f"{case['id']} {case['title']}: {failures} {actual if not isinstance(actual, list) else ''}")

    def test_write_check_qualification(self):
        # The end-of-stream marker check is the Node oracle's alone (Python's lzma cannot see it).
        for name, suite in SUITES.items():
            cases = {c['id']: c for c in suite['cases']}
            for sample in suite['writeCheckQualification']:
                with self.subTest(sample=sample['title']):
                    results = sdx_env.check_write(PROFILE, cases[sample['writeCase']], sample['envelope'])
                    failing = sorted(r['check'] for r in results if not r['ok'])
                    expected = sorted(c for c in sample['failingChecks'] if not c.endswith('-lzma-no-marker'))
                    self.assertEqual(failing, expected)

    def test_refusals_and_tags(self):
        classes = {'format', 'structure', 'integrity', 'signature', 'decode', 'root-pk-mismatch', 'delegation-invalid'}
        for suite in SUITES.values():
            for case in suite['cases']:
                self.assertIn(case['tag'], ('required', 'labChoice'))
                if case['expect'].get('verdict') == 'refused':
                    self.assertIn(case['expect']['refusal']['class'], classes)


if __name__ == '__main__':
    unittest.main()
