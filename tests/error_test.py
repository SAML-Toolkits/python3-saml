# -*- coding: utf-8 -*-

# Copyright (c) 2010-2021 OneLogin, Inc.
# MIT License

import unittest
from saml2.errors import Saml2_Error


class Saml2_Error_Test(unittest.TestCase):
    """
    Tests the Saml2_Error Constructor.
    """

    def runTest(self):
        exception = Saml2_Error("test")
        self.assertEqual(str(exception), "test")
