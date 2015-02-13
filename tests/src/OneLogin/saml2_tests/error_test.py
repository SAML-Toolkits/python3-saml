# -*- coding: utf-8 -*-

# Copyright (c) 2014, OneLogin, Inc.
# All rights reserved.

import unittest
from onelogin.saml2.errors import OneLogin_Saml2_Error


class OneLogin_Saml2_Error_Test(unittest.TestCase):
    """
    Tests the OneLogin_Saml2_Error Constructor.
    """

    def runTest(self):
        exception = OneLogin_Saml2_Error('test')
        self.assertEqual(str(exception), 'test')
