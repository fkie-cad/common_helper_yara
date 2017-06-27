def get_all_matched_strings(yara_result_dict):
    '''
    returns a set of all matched strings

    :param yara_result_dict: a result dict
    :type yara_result_dict: dict
    :return: set
    '''
    matched_strings = set()
    for matched_rule in yara_result_dict:
        matched_strings.update(_get_matched_strings_of_single_rule(yara_result_dict[matched_rule]))
    return matched_strings


def _get_matched_strings_of_single_rule(yara_match):
    matched_strings = set()
    print(yara_match['strings'])
    for string_item in yara_match['strings']:
        matched_strings.add(string_item[2])
    return matched_strings
