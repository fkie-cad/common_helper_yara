from distutils.version import LooseVersion
from pathlib import Path
from tempfile import TemporaryDirectory

from common_helper_yara.common import get_yara_version
from common_helper_yara.yara_compile import compile_rules
from common_helper_yara.yara_scan import scan

DIR_OF_CURRENT_FILE = Path(__file__).parent
COMPILED_FLAG = get_yara_version() >= LooseVersion('3.9')


def test_compile_and_scan():
    with TemporaryDirectory(prefix="common_helper_yara_test_") as tmp_dir:
        input_dir = DIR_OF_CURRENT_FILE / 'data/rules'
        signature_file = Path(tmp_dir) / 'test.yc'
        data_files = DIR_OF_CURRENT_FILE / 'data/data_files'

        compile_rules(input_dir, signature_file, external_variables={'test_flag': 'true'})
        assert signature_file.exists(), "file not created"

        result = scan(signature_file, data_files, recursive=True, compiled=COMPILED_FLAG)
        assert 'lighttpd' in result.keys(), "at least one match missing"
        assert 'lighttpd_simple' in result.keys(), "at least one match missing"
