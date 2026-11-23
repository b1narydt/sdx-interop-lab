"""LAB_SELF_TEST_ONLY: the Python standard-library oracle (test/sdx_adm.py) reproduces every
VA-ADM admission and index outcome, reading only the suite file and the laboratory profile."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sdx_adm  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(rel):
    with open(os.path.join(ROOT, rel), 'rb') as handle:
        return json.loads(handle.read())


PROFILE = load('fixtures/sdx/v1/deployment-profile.json')
VA_ADM = load('fixtures/sdx/v1/va-adm/vectors.json')


class AdmissionOracle(unittest.TestCase):
    def test_every_case(self):
        self.assertEqual(VA_ADM['claim'], 'LAB_SELF_TEST_ONLY')
        self.assertEqual(VA_ADM['caseCount'], len(VA_ADM['cases']))
        for case in VA_ADM['cases']:
            with self.subTest(case=case['id']):
                ok, step, actual = sdx_adm.run_case(PROFILE, case)
                self.assertTrue(ok, f"{case['id']} {case['title']}: step {step}: {actual}")

    def test_constants(self):
        self.assertEqual(VA_ADM['constants']['topicPrefix'], 'tm_')
        self.assertEqual(VA_ADM['constants']['indexPrefix'], 'ls_')
        for topic, index in VA_ADM['constants']['topics'].items():
            self.assertEqual(index, 'ls_' + topic[3:])


if __name__ == '__main__':
    unittest.main()
