#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2010-2018 OneLogin, Inc.
# MIT License

from setuptools import setup


setup(
    name='python3-saml',
    version='1.4.1',
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
        'isodate>=0.5.0',
        'xmlsec>=0.6.0',
        'defusedxml==0.5.0'
    ],
    dependency_links=['http://github.com/mehcode/python-xmlsec/tarball/master'],
    extras_require={
        'test': (
            'coverage>=3.6',
            'freezegun==0.3.5',
            'pylint==1.3.1',
            'pep8==1.5.7',
            'pyflakes==0.8.1',
            'coveralls==1.1',
        ),
    },
    keywords='saml saml2 xmlsec django flask pyramid python3',
)
