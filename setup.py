#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2014, OneLogin, Inc.
# All rights reserved.

from setuptools import setup


setup(
    name='python-saml',
    version='2.0.0',
    description='Onelogin Python Toolkit. Add SAML support to your Python software using this library',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.7',
    ],
    author='OneLogin',
    author_email='support@onelogin.com',
    license='MIT',
    url='https://github.com/onelogin/python-saml',
    packages=['onelogin','onelogin/saml2'],
    include_package_data=True,
    package_data = {
            'onelogin/saml2/schemas': ['*.xsd'],
    },
    package_dir={
        '': 'src',
    },
    test_suite='tests',
    install_requires=[
        'M2Crypto==0.22.3',
        'dm.xmlsec.binding==1.3.1',
        'isodate==0.5.0',
        'defusedxml==0.4.1',
    ],
    extras_require={
        'test': (
            'coverage==3.7.1',
            'pylint==1.3.1',
            'pep8==1.5.7',
            'pyflakes==0.8.1',
            'coveralls==0.4.4',
        ),
    },
    keywords='saml saml2 xmlsec django flask',
)
