from pathlib import Path
from shlex import split
from typing import Dict, Optional, Any, Union

import logging
import subprocess
from tempfile import NamedTemporaryFile

from .common import convert_external_variables


def compile_rules(
    input_dir: Union[str, Path],
    out_file: Union[str, Path],
    external_variables: Optional[Dict[str, Any]] = None,
):
    '''
    compile yara files in input dir

    :param input_dir: directory with yara rules
    :param out_file: path to store the compiled yara rules
    :param external_variables: define external variables
    '''
    if external_variables is None:
        external_variables = {}
    with NamedTemporaryFile(mode='w') as tmp_file:
        _create_joint_signature_file(Path(input_dir), tmp_file)
        _create_compiled_signature_file(out_file, tmp_file, external_variables)


def _create_joint_signature_file(directory: Path, tmp_file: NamedTemporaryFile):
    all_signatures = [
        signature_file.read_bytes()
        for signature_file in sorted(directory.iterdir())
    ]
    Path(tmp_file.name).write_bytes(b'\n'.join(all_signatures))


def _create_compiled_signature_file(out_file: Path, tmp_file: NamedTemporaryFile, external_variables: dict):
    variables = convert_external_variables(external_variables)
    try:
        subprocess.run(split(f'yarac {variables} {tmp_file.name} {out_file}'), check=True)
    except subprocess.CalledProcessError:
        logging.error(f'Creation of {out_file} failed!')
