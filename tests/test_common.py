import unittest

from common_helper_yara.common import convert_external_variables


class TestYaraCommon(unittest.TestCase):

    def test_convert_external_variables(self):
        self.assertEqual(convert_external_variables({'a': 'b'}), '-d a=b', 'converted output not correct')
        self.assertEqual(convert_external_variables({'a': 1, 'b': 'c'}), '-d a=1 -d b=c', 'converted output not correct')
