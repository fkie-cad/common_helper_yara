from setuptools import setup, find_packages

VERSION = "0.2"

setup(
    name="common_helper_yara",
    version=VERSION,
    packages=find_packages(),
    install_requires=[
        'common_helper_files @ git+https://github.com/fkie-cad/common_helper_files.git'
    ],
    description="Yara command line binding",
    author="Fraunhofer FKIE",
    author_email="peter.weidenbach@fkie.fraunhofer.de",
    url="http://www.fkie.fraunhofer.de",
    license="MIT License"
)
