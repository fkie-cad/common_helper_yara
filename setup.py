from setuptools import setup, find_packages

VERSION = "0.4"

setup(
    name="common_helper_yara",
    version=VERSION,
    packages=find_packages(),
    extras_require={
        'dev': [
            'pytest',
            'pytest-pycodestyle',
            'pytest-cov'
        ]
    },
    description="Yara command line binding",
    author="Fraunhofer FKIE",
    author_email="peter.weidenbach@fkie.fraunhofer.de",
    url="http://www.fkie.fraunhofer.de",
    license="MIT License"
)
