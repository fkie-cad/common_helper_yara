from common_helper_files.fail_safe_file_operations import get_files_in_dir
import logging
import subprocess
from tempfile import NamedTemporaryFile

from .common import convert_external_variables


def compile_rules(input_dir, out_file, external_variables={}):
    '''
    compile yara files in input dir

    :param input_dir: directory with yara rules
    :type input_dir: string
    :param out_file: path to store the compiled yara rules
    :type out_file: string
    :return: None
    '''
    with NamedTemporaryFile(mode='w') as tmp_file:
        _create_joint_signature_file(input_dir, tmp_file)
        _create_compiled_signature_file(out_file, tmp_file, external_variables)
    return None


def _create_joint_signature_file(directory, tmp_file):
    all_signatures = list()
    for signature_file in get_files_in_dir(directory):
        with open(signature_file, 'rb') as fd:
            all_signatures.append(fd.read())
    with open(tmp_file.name, 'wb') as fd:
        fd.write(b'\x0a'.join(all_signatures))


def _create_compiled_signature_file(out_file, tmp_file, external_variables):
    variables = convert_external_variables(external_variables)
    try:
        subprocess.run('yarac {} {} {}'.format(variables, tmp_file.name, out_file), shell=True, check=True)
    except subprocess.CalledProcessError:
        logging.error('Creation of {} failed !!'.format(out_file))
