from common_helper_yara.yara_interpretation import get_all_matched_strings

TEST_DATA = {
    'test_rule': {
        'rule': 'test_rule', 'meta': {},
        'strings': [(0, '$a', b'test_1'), (10, '$b', b'test_2')],
        'matches': True
    },
    'test_rule2': {
        'rule': 'test_rule2',
        'meta': {},
        'strings': [(0, '$a', b'test_1'), (10, '$b', b'test_3')], 'matches': True
    },
}


def test_get_all_matched_strings():
    assert get_all_matched_strings(TEST_DATA) == {'test_1', 'test_2', 'test_3'}, "resulting strings not correct"
