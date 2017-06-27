import os
import unittest

from common_helper_yara.yara_scan import _parse_yara_output, scan

DIR_OF_CURRENT_FILE = os.path.dirname(os.path.abspath(__file__))


class TestYaraScan(unittest.TestCase):

    def test_parse_yara_output(self):
        with open(os.path.join(DIR_OF_CURRENT_FILE, 'data', 'yara_matches'), 'r') as fd:
            match_file = fd.read()
        matches = _parse_yara_output(match_file)

        self.assertIsInstance(matches, dict, 'matches should be dict')
        self.assertIn('PgpPublicKeyBlock', matches.keys(), 'Pgp block should have been matched')
        self.assertIn(0, matches['PgpPublicKeyBlock']['strings'][0], 'first block should start at 0x0')

    def test_scan(self):
        signature_file = os.path.join(DIR_OF_CURRENT_FILE, 'data/rules', 'signatures.yara')
        scan_file = os.path.join(DIR_OF_CURRENT_FILE, 'data/data_files', 'scan_file')

        result = scan(signature_file, scan_file)
        self.assertIsInstance(result, dict, "result is not a dict")
        self.assertEqual(len(result), 2, "number of matches not correct")
        self.assertEqual(result['another_test_rule']['meta']['description'], 'test rule', 'meta data not correct')

    def test_scan_ext_variable_and_magic(self):
        signature_file = os.path.join(DIR_OF_CURRENT_FILE, 'data/rules', 'signatures_ext_var.yara')
        scan_file = os.path.join(DIR_OF_CURRENT_FILE, 'data/data_files', 'scan_file')

        result = scan(signature_file, scan_file, external_variables={'test_flag': "true"})
        self.assertEqual(len(result), 1, "number of results not correct")

        result = scan(signature_file, scan_file, external_variables={'test_flag': "false"})
        self.assertEqual(len(result), 0, "number of results not correct")

    def test_scan_recursive(self):
        signature_file = os.path.join(DIR_OF_CURRENT_FILE, 'data/rules', 'signatures.yara')
        scan_file = os.path.join(DIR_OF_CURRENT_FILE, 'data/data_files')

        result = scan(signature_file, scan_file, recursive=True)
        self.assertEqual(len(result['another_test_rule']['strings']), 2, 'string in second file not found')
