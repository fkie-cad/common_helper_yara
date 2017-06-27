import unittest
from common_helper_yara.yara_interpretation import get_all_matched_strings


class TestYaraInterpretation(unittest.TestCase):

    def test_get_all_matched_strings(self):
        test_data = {
            'test_rule': {'rule': 'test_rule', 'meta': {}, 'strings': [(0, '$a', b'test_1'), (10, '$b', b'test_2')], 'matches': True},
            'test_rule2': {'rule': 'test_rule2', 'meta': {}, 'strings': [(0, '$a', b'test_1'), (10, '$b', b'test_3')], 'matches': True},
            }
        result = get_all_matched_strings(test_data)
        self.assertEqual(result, set(['test_1', 'test_2', 'test_3']), "resulting strings not correct")
