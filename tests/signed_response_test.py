# -*- coding: utf-8 -*-

# Copyright (c) 2010-2021 OneLogin, Inc.
# MIT License

import json
from pathlib import Path
import unittest

from saml2.response import Saml2_Response
from saml2.settings import Saml2_Settings
from saml2.utils import Saml2_Utils


class Saml2_SignedResponse_Test(unittest.TestCase):

    root_path = Path().absolute()
    data_path = root_path / "data"
    settings_path = root_path / "settings"

    def loadSettingsJSON(self, name="settings1.json"):
        filename = self.settings_path / name
        if filename.exists():
            stream = open(filename, "r")
            settings = json.load(stream)
            stream.close()
            return settings

    def file_contents(self, filename):
        f = open(filename, "r")
        content = f.read()
        f.close()
        return content

    def testResponseSignedAssertionNot(self):
        """
        Tests the getNameId method of the Saml2_Response
        Case valid signed response, unsigned assertion
        """
        settings = Saml2_Settings(self.loadSettingsJSON())
        message = self.file_contents(self.data_path / "responses" / "open_saml_response.xml")
        response = Saml2_Response(settings, Saml2_Utils.b64encode(message))

        self.assertEqual("someone@example.org", response.get_nameid())

    def testResponseAndAssertionSigned(self):
        """
        Tests the getNameId method of the Saml2_Response
        Case valid signed response, signed assertion
        """
        settings = Saml2_Settings(self.loadSettingsJSON())
        message = self.file_contents(self.data_path / "responses" / "simple_saml_php.xml")
        response = Saml2_Response(settings, Saml2_Utils.b64encode(message))

        self.assertEqual("someone@example.com", response.get_nameid())
