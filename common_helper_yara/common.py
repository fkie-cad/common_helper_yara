import logging
from distutils.version import LooseVersion
from shlex import split
from subprocess import check_output
from typing import Any, Dict, Optional


def convert_external_variables(ext_var_dict: Dict[str, Any]) -> str:
    output = [f'-d {variable}={value}' for variable, value in ext_var_dict.items()]
    return ' '.join(sorted(output))


def get_yara_version() -> Optional[LooseVersion]:
    '''
    Returns the YARA version as `distutils.version.LooseVersion` or None if YARA is not found.

    :return: The installed YARA version or `None`
    '''
    try:
        return LooseVersion(check_output(split('yara --version')).decode().strip())
    except FileNotFoundError:
        logging.warning('YARA not found. Is YARA installed?', exc_info=True)
        return None
