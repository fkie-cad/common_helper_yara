from setuptools import setup, find_packages

VERSION = "0.2"

setup(
    name="common_helper_yara",
    version=VERSION,
    packages=find_packages(),
    install_requires=[
        'common_helper_files'
    ],
    dependency_links=[
        'git+https://github.com/mass-project/common_helper_files.git#common_helper_files'
    ],
    description="Yara command line binding",
    author="Fraunhofer FKIE",
    author_email="peter.weidenbach@fkie.fraunhofer.de",
    url="http://www.fkie.fraunhofer.de",
    license="MIT License"
)
