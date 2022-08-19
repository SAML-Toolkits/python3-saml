#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2010-2022 OneLogin, Inc.
# MIT License

from setuptools import setup


setup(
    name='python3-saml',
    version='1.14.0',
    description='Onelogin Python Toolkit. Add SAML support to your Python software using this library',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
    ],
    author='OneLogin',
    author_email='support@onelogin.com',
    license='MIT',
    url='https://github.com/onelogin/python3-saml',
    packages=['onelogin', 'onelogin/saml2'],
    include_package_data=True,
    package_data={
        'onelogin/saml2/schemas': ['*.xsd'],
    },
    package_dir={
        '': 'src',
    },
    test_suite='tests',
    install_requires=[
        'lxml<=4.9.1',
        'isodate>=0.6.1',
        'xmlsec>=1.3.9'
    ],
    dependency_links=['http://github.com/mehcode/python-xmlsec/tarball/master'],
    extras_require={
        'test': (
            'coverage>=4.5.2',
            'freezegun>=0.3.11, <=1.1.0',
            'pylint==1.9.4',
            'flake8>=3.6.0',
            'pytest>=4.6',
        ),
    },
    keywords='saml saml2 xmlsec django flask pyramid python3',
)
