from distutils.version import LooseVersion

import pytest

import common_helper_yara.common as common
from common_helper_yara.common import convert_external_variables, get_yara_version


@pytest.mark.parametrize('test_input, expected_output', [
    ({'a': 'b'}, '-d a=b'),
    ({'a': 1, 'b': 'c'}, '-d a=1 -d b=c'),
])
def test_convert_external_variables(test_input, expected_output):
    assert convert_external_variables(test_input) == expected_output


def test_get_yara_version():
    assert LooseVersion('3.0') < get_yara_version() < LooseVersion('5.0')


@pytest.fixture()
def yara_not_found(monkeypatch):
    def raise_error(_):
        raise FileNotFoundError
    monkeypatch.setattr(common, 'check_output', raise_error)


def test_get_yara_version_error(yara_not_found):
    assert get_yara_version() is None
