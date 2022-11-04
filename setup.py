#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2010-2022 OneLogin, Inc.
# MIT License

from setuptools import setup

requirements = []
with open("requirements.txt") as f:
    requirements = f.read().splitlines()

test_requirements = None
with open("requirements-test.txt") as f:
    test_requirements = (item for item in f.read().splitlines())

extra_requirements = {"test": test_requirements}

setup(
    name="python3-saml",
    version="1.15.0",
    description="Add SAML support to your Python software using this library",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    author="Alloy",
    license="MIT",
    url="https://github.com/UseAlloy/python3-saml",
    packages=["saml2"],
    include_package_data=True,
    package_data={
        "saml2/schemas": ["*.xsd"],
    },
    package_dir={
        "": "src",
    },
    test_suite="tests",
    install_requires=requirements,
    dependency_links=["http://github.com/mehcode/python-xmlsec/tarball/master"],
    extras_require=extra_requirements,
    keywords="saml saml2 xmlsec django flask pyramid python3",
)
