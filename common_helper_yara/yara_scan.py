import logging
import re
from pathlib import Path
from subprocess import check_output, CalledProcessError, STDOUT
from typing import Any, Dict, List, Optional, Tuple, Union

from .common import convert_external_variables


_RULE_BLOCK_REGEX = re.compile(r'^(?P<rule>\w+)\s+\[(?P<raw_meta>.*)\]\s+(?P<scanned_file>.*)\n(?P<raw_matches>(?:0x[a-f0-9]+.*(?:[\n]|$))+)', flags=re.MULTILINE)
_YARA_MATCH_REGEX = re.compile(r'^(?P<offset>0x[a-f0-9]+):(?P<tag>\S+):\s(?P<string>.+)$', flags=re.MULTILINE)


def scan(
    signature_path: Union[str, Path],
    file_path: Union[str, Path],
    external_variables: Optional[Dict[str, Any]] = None,
    recursive: bool = False,
    compiled: bool = False
) -> dict:
    '''
    Scan files and return matches

    :param signature_path: path to signature file
    :param file_path: files to scan
    :param external_variables: define external variables
    :param recursive: scan recursively
    :param compiled: rule is in compiled form (Yara >= 4 only!)
    :return: a dict containing the scan results
    '''
    if external_variables is None:
        external_variables = {}

    variables = convert_external_variables(external_variables)
    recursive_flag = '-r' if recursive else ''
    compiled_flag = '-C' if compiled else ''
    try:
        command = f'yara {variables} {recursive_flag} {compiled_flag} -m -s {signature_path} {file_path}'
        scan_result = check_output(command, shell=True, stderr=STDOUT)
        return _parse_yara_output(scan_result.decode())
    except CalledProcessError as e:
        logging.error(f'There seems to be an error in the rule file:\n{e.output.decode()}', exc_info=True)
        return {}
    except Exception as e:
        logging.error(f'Could not parse yara result: {e}', exc_info=True)
        return {}


def _add_yara_rule_match(rule_block: dict, block: dict):
    # the file path that that is scanned does not reflect in the result set?
    # rule_block['strings'] += [(*yara_match, block['scanned_file']) for yara_match in parse_matches(block['raw_matches'])]
    rule_block['strings'] += [yara_match for yara_match in _parse_matches(block['raw_matches'])]


def _parse_yara_output(output: str) -> dict:
    results = dict()
    for block in _find_rule_blocks(output):
        rule_block = _init_rule_block_entry(results, block)
        _add_yara_rule_match(rule_block, block)
    return results


def _find_rule_blocks(output: str) -> List[Dict[str, str]]:
    return [match.groupdict() for match in _RULE_BLOCK_REGEX.finditer(output)]


def _init_rule_block_entry(results: dict, block: dict) -> dict:
    rule_name = block['rule']
    if rule_name not in results:
        meta = _parse_meta_data(block)
        results[rule_name] = dict(rule=rule_name, matches=True, meta=meta, strings=list())
    return results[rule_name]


def _parse_matches(raw_matches: str) -> List[Tuple[int, str, bytes]]:
    groups = [match.groupdict() for match in _YARA_MATCH_REGEX.finditer(raw_matches)]
    return [(int(group['offset'], 16), group['tag'], group['string'].encode()) for group in groups]


def _parse_meta_data(block: dict) -> Dict[str, str]:
    '''
    Will be of form 'item0=lowercaseboolean0,item1="value1",item2=value2,..'
    '''
    meta_data = dict()
    for item in block['raw_meta'].split(','):
        if '=' in item:
            key, value = item.split('=', maxsplit=1)
            value = value == 'true' if value in ['true', 'false'] else value.strip('"')
            meta_data[key] = value
        else:
            logging.warning(f'Malformed meta string \'{block["raw_meta"]}\'')
    return meta_data
