from typing import Set


def get_all_matched_strings(yara_result_dict: dict) -> Set[str]:
    '''
    Get all strings matched by the yara rules

    :param yara_result_dict: a yara result dict
    :return: a set of all matched strings
    '''
    return {
        string
        for matched_rule in yara_result_dict.values()
        for string in _get_matched_strings_of_single_rule(matched_rule)
    }


def _get_matched_strings_of_single_rule(yara_match):
    return {
        string_item[2].decode('utf-8', 'replace')
        for string_item in yara_match['strings']
    }
