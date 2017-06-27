import os
import unittest
from common_helper_yara.yara_compile import compile_rules
from common_helper_yara.yara_scan import scan
from tempfile import TemporaryDirectory


DIR_OF_CURRENT_FILE = os.path.dirname(os.path.abspath(__file__))


class TestYaraCompile(unittest.TestCase):

    def test_compile_and_scan(self):
        tmp_dir = TemporaryDirectory(prefix="common_helper_yara_test_")
        input_dir = os.path.join(DIR_OF_CURRENT_FILE, 'data/rules')
        signature_file = os.path.join(tmp_dir.name, 'test.yc')
        data_files = os.path.join(DIR_OF_CURRENT_FILE, 'data/data_files')

        compile_rules(input_dir, signature_file, external_variables={'test_flag': 'true'})
        self.assertTrue(os.path.exists(signature_file), "file not created")

        result = scan(signature_file, data_files, recursive=True)
        self.assertIn('lighttpd', result.keys(), "at least one match missing")
        self.assertIn('lighttpd_simple', result.keys(), "at least one match missing")
