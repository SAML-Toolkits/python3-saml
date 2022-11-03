# -*- coding: utf-8 -*-

# Copyright (c) 2010-2021 OneLogin, Inc.
# MIT License

import json
from os.path import dirname, join, exists
import unittest

from saml2 import compat
from saml2.authn_request import Saml2_Authn_Request
from saml2.constants import Saml2_Constants
from saml2.settings import Saml2_Settings
from saml2.utils import Saml2_Utils
from saml2.xml_utils import Saml2_XML

from urllib.parse import urlparse, parse_qs


class Saml2_Authn_Request_Test(unittest.TestCase):
    settings_path = join(dirname(dirname(dirname(dirname(__file__)))), "settings")

    # assertRegexpMatches deprecated on python3
    def assertRegex(self, text, regexp, msg=None):
        if hasattr(unittest.TestCase, "assertRegex"):
            return super(Saml2_Authn_Request_Test, self).assertRegex(text, regexp, msg)
        else:
            return self.assertRegexpMatches(text, regexp, msg)

    def loadSettingsJSON(self, name="settings1.json"):
        filename = join(self.settings_path, name)
        if exists(filename):
            stream = open(filename, "r")
            settings = json.load(stream)
            stream.close()
            return settings
        else:
            raise Exception("Settings json file does not exist")

    def setUp(self):
        self.__settings = Saml2_Settings(self.loadSettingsJSON())

    def testCreateRequest(self):
        """
        Tests the Saml2_Authn_Request Constructor.
        The creation of a deflated SAML Request
        """

        saml_settings = self.loadSettingsJSON()
        settings = Saml2_Settings(saml_settings)
        settings._organization = {"en-US": {"url": "http://sp.example.com", "name": "sp_test"}}

        authn_request = Saml2_Authn_Request(settings)
        authn_request_encoded = authn_request.get_request()
        inflated = compat.to_string(Saml2_Utils.decode_base64_and_inflate(authn_request_encoded))
        self.assertRegex(inflated, "^<samlp:AuthnRequest")
        self.assertNotIn('ProviderName="SP test"', inflated)

        saml_settings["organization"] = {}
        settings = Saml2_Settings(saml_settings)

        authn_request = Saml2_Authn_Request(settings)
        authn_request_encoded = authn_request.get_request()
        inflated = compat.to_string(Saml2_Utils.decode_base64_and_inflate(authn_request_encoded))
        self.assertRegex(inflated, "^<samlp:AuthnRequest")
        self.assertNotIn('ProviderName="SP test"', inflated)

    def testGetXML(self):
        """
        Tests that we can get the request XML directly without
        going through intermediate steps
        """
        saml_settings = self.loadSettingsJSON()
        saml_settings["organization"] = {
            "en-US": {
                "url": "http://sp.example.com",
                "name": "sp_test",
                "displayname": "SP test",
            }
        }
        settings = Saml2_Settings(saml_settings)

        authn_request = Saml2_Authn_Request(settings)
        inflated = authn_request.get_xml()
        self.assertRegex(inflated, "^<samlp:AuthnRequest")
        self.assertIn('ProviderName="SP test"', inflated)

        saml_settings["organization"] = {}
        settings = Saml2_Settings(saml_settings)

        authn_request = Saml2_Authn_Request(settings)
        inflated = authn_request.get_xml()
        self.assertRegex(inflated, "^<samlp:AuthnRequest")
        self.assertNotIn('ProviderName="SP test"', inflated)

    def testCreateRequestAuthContext(self):
        """
        Tests the Saml2_Authn_Request Constructor.
        The creation of a deflated SAML Request with defined AuthContext
        """
        saml_settings = self.loadSettingsJSON()
        settings = Saml2_Settings(saml_settings)
        authn_request = Saml2_Authn_Request(settings)
        authn_request_encoded = authn_request.get_request()
        inflated = compat.to_string(Saml2_Utils.decode_base64_and_inflate(authn_request_encoded))
        self.assertRegex(inflated, "^<samlp:AuthnRequest")
        self.assertIn(Saml2_Constants.AC_PASSWORD, inflated)
        self.assertNotIn(Saml2_Constants.AC_X509, inflated)

        saml_settings["security"]["requestedAuthnContext"] = True
        settings = Saml2_Settings(saml_settings)
        authn_request = Saml2_Authn_Request(settings)
        authn_request_encoded = authn_request.get_request()
        inflated = compat.to_string(Saml2_Utils.decode_base64_and_inflate(authn_request_encoded))
        self.assertRegex(inflated, "^<samlp:AuthnRequest")
        self.assertIn(Saml2_Constants.AC_PASSWORD_PROTECTED, inflated)
        self.assertNotIn(Saml2_Constants.AC_X509, inflated)

        del saml_settings["security"]["requestedAuthnContext"]
        settings = Saml2_Settings(saml_settings)
        authn_request = Saml2_Authn_Request(settings)
        authn_request_encoded = authn_request.get_request()
        inflated = compat.to_string(Saml2_Utils.decode_base64_and_inflate(authn_request_encoded))
        self.assertRegex(inflated, "^<samlp:AuthnRequest")
        self.assertIn(Saml2_Constants.AC_PASSWORD_PROTECTED, inflated)
        self.assertNotIn(Saml2_Constants.AC_X509, inflated)

        saml_settings["security"]["requestedAuthnContext"] = False
        settings = Saml2_Settings(saml_settings)
        authn_request = Saml2_Authn_Request(settings)
        authn_request_encoded = authn_request.get_request()
        inflated = compat.to_string(Saml2_Utils.decode_base64_and_inflate(authn_request_encoded))
        self.assertRegex(inflated, "^<samlp:AuthnRequest")
        self.assertNotIn(Saml2_Constants.AC_PASSWORD_PROTECTED, inflated)
        self.assertNotIn(Saml2_Constants.AC_X509, inflated)

        saml_settings["security"]["requestedAuthnContext"] = (
            Saml2_Constants.AC_PASSWORD_PROTECTED,
            Saml2_Constants.AC_X509,
        )
        settings = Saml2_Settings(saml_settings)
        authn_request = Saml2_Authn_Request(settings)
        authn_request_encoded = authn_request.get_request()
        inflated = compat.to_string(Saml2_Utils.decode_base64_and_inflate(authn_request_encoded))
        self.assertRegex(inflated, "^<samlp:AuthnRequest")
        self.assertIn(Saml2_Constants.AC_PASSWORD_PROTECTED, inflated)
        self.assertIn(Saml2_Constants.AC_X509, inflated)

    def testCreateRequestAuthContextComparision(self):
        """
        Tests the Saml2_Authn_Request Constructor.
        The creation of a deflated SAML Request with defined AuthnContextComparison
        """
        saml_settings = self.loadSettingsJSON()
        settings = Saml2_Settings(saml_settings)
        authn_request = Saml2_Authn_Request(settings)
        authn_request_encoded = authn_request.get_request()
        inflated = compat.to_string(Saml2_Utils.decode_base64_and_inflate(authn_request_encoded))
        self.assertRegex(inflated, "^<samlp:AuthnRequest")
        self.assertIn(Saml2_Constants.AC_PASSWORD, inflated)
        self.assertNotIn(Saml2_Constants.AC_X509, inflated)

        saml_settings["security"]["requestedAuthnContext"] = True
        settings = Saml2_Settings(saml_settings)
        authn_request = Saml2_Authn_Request(settings)
        authn_request_encoded = authn_request.get_request()
        inflated = compat.to_string(Saml2_Utils.decode_base64_and_inflate(authn_request_encoded))
        self.assertRegex(inflated, "^<samlp:AuthnRequest")
        self.assertIn('RequestedAuthnContext Comparison="exact"', inflated)

        saml_settings["security"]["requestedAuthnContextComparison"] = "minimun"
        settings = Saml2_Settings(saml_settings)
        authn_request = Saml2_Authn_Request(settings)
        authn_request_encoded = authn_request.get_request()
        inflated = compat.to_string(Saml2_Utils.decode_base64_and_inflate(authn_request_encoded))
        self.assertRegex(inflated, "^<samlp:AuthnRequest")
        self.assertIn('RequestedAuthnContext Comparison="minimun"', inflated)

    def testCreateRequestForceAuthN(self):
        """
        Tests the Saml2_Authn_Request Constructor.
        The creation of a deflated SAML Request with ForceAuthn="true"
        """
        saml_settings = self.loadSettingsJSON()
        settings = Saml2_Settings(saml_settings)
        authn_request = Saml2_Authn_Request(settings)
        authn_request_encoded = authn_request.get_request()
        inflated = compat.to_string(Saml2_Utils.decode_base64_and_inflate(authn_request_encoded))
        self.assertRegex(inflated, "^<samlp:AuthnRequest")
        self.assertNotIn('ForceAuthn="true"', inflated)

        authn_request_2 = Saml2_Authn_Request(settings, False, False)
        authn_request_encoded_2 = authn_request_2.get_request()
        inflated_2 = compat.to_string(
            Saml2_Utils.decode_base64_and_inflate(authn_request_encoded_2)
        )
        self.assertRegex(inflated_2, "^<samlp:AuthnRequest")
        self.assertNotIn('ForceAuthn="true"', inflated_2)

        authn_request_3 = Saml2_Authn_Request(settings, True, False)
        authn_request_encoded_3 = authn_request_3.get_request()
        inflated_3 = compat.to_string(
            Saml2_Utils.decode_base64_and_inflate(authn_request_encoded_3)
        )
        self.assertRegex(inflated_3, "^<samlp:AuthnRequest")
        self.assertIn('ForceAuthn="true"', inflated_3)

    def testCreateRequestIsPassive(self):
        """
        Tests the Saml2_Authn_Request Constructor.
        The creation of a deflated SAML Request with IsPassive="true"
        """
        saml_settings = self.loadSettingsJSON()
        settings = Saml2_Settings(saml_settings)
        authn_request = Saml2_Authn_Request(settings)
        authn_request_encoded = authn_request.get_request()
        inflated = compat.to_string(Saml2_Utils.decode_base64_and_inflate(authn_request_encoded))
        self.assertRegex(inflated, "^<samlp:AuthnRequest")
        self.assertNotIn('IsPassive="true"', inflated)

        authn_request_2 = Saml2_Authn_Request(settings, False, False)
        authn_request_encoded_2 = authn_request_2.get_request()
        inflated_2 = compat.to_string(
            Saml2_Utils.decode_base64_and_inflate(authn_request_encoded_2)
        )
        self.assertRegex(inflated_2, "^<samlp:AuthnRequest")
        self.assertNotIn('IsPassive="true"', inflated_2)

        authn_request_3 = Saml2_Authn_Request(settings, False, True)
        authn_request_encoded_3 = authn_request_3.get_request()
        inflated_3 = compat.to_string(
            Saml2_Utils.decode_base64_and_inflate(authn_request_encoded_3)
        )
        self.assertRegex(inflated_3, "^<samlp:AuthnRequest")
        self.assertIn('IsPassive="true"', inflated_3)

    def testCreateRequestSetNameIDPolicy(self):
        """
        Tests the Saml2_Authn_Request Constructor.
        The creation of a deflated SAML Request with and without NameIDPolicy
        """
        saml_settings = self.loadSettingsJSON()
        settings = Saml2_Settings(saml_settings)
        authn_request = Saml2_Authn_Request(settings)
        authn_request_encoded = authn_request.get_request()
        inflated = compat.to_string(Saml2_Utils.decode_base64_and_inflate(authn_request_encoded))
        self.assertRegex(inflated, "^<samlp:AuthnRequest")
        self.assertIn("<samlp:NameIDPolicy", inflated)

        authn_request_2 = Saml2_Authn_Request(settings, False, False, True)
        authn_request_encoded_2 = authn_request_2.get_request()
        inflated_2 = compat.to_string(
            Saml2_Utils.decode_base64_and_inflate(authn_request_encoded_2)
        )
        self.assertRegex(inflated_2, "^<samlp:AuthnRequest")
        self.assertIn("<samlp:NameIDPolicy", inflated_2)

        authn_request_3 = Saml2_Authn_Request(settings, False, False, False)
        authn_request_encoded_3 = authn_request_3.get_request()
        inflated_3 = compat.to_string(
            Saml2_Utils.decode_base64_and_inflate(authn_request_encoded_3)
        )
        self.assertRegex(inflated_3, "^<samlp:AuthnRequest")
        self.assertNotIn("<samlp:NameIDPolicy", inflated_3)

    def testCreateRequestSubject(self):
        """
        Tests the Saml2_Authn_Request Constructor.
        The creation of a deflated SAML Request with and without Subject
        """
        saml_settings = self.loadSettingsJSON()
        settings = Saml2_Settings(saml_settings)
        authn_request = Saml2_Authn_Request(settings)
        authn_request_encoded = authn_request.get_request()
        inflated = compat.to_string(Saml2_Utils.decode_base64_and_inflate(authn_request_encoded))
        self.assertRegex(inflated, "^<samlp:AuthnRequest")
        self.assertNotIn("<saml:Subject>", inflated)

        authn_request_2 = Saml2_Authn_Request(settings, name_id_value_req="testuser@example.com")
        authn_request_encoded_2 = authn_request_2.get_request()
        inflated_2 = compat.to_string(
            Saml2_Utils.decode_base64_and_inflate(authn_request_encoded_2)
        )
        self.assertRegex(inflated_2, "^<samlp:AuthnRequest")
        self.assertIn("<saml:Subject>", inflated_2)
        self.assertIn(
            'Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">testuser@example.com</saml:NameID>',
            inflated_2,
        )
        self.assertIn(
            '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">', inflated_2
        )

        saml_settings["sp"][
            "NameIDFormat"
        ] = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        settings = Saml2_Settings(saml_settings)
        authn_request_3 = Saml2_Authn_Request(settings, name_id_value_req="testuser@example.com")
        authn_request_encoded_3 = authn_request_3.get_request()
        inflated_3 = compat.to_string(
            Saml2_Utils.decode_base64_and_inflate(authn_request_encoded_3)
        )
        self.assertRegex(inflated_3, "^<samlp:AuthnRequest")
        self.assertIn("<saml:Subject>", inflated_3)
        self.assertIn(
            'Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">testuser@example.com</saml:NameID>',
            inflated_3,
        )
        self.assertIn(
            '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">', inflated_3
        )

    def testCreateDeflatedSAMLRequestURLParameter(self):
        """
        Tests the Saml2_Authn_Request Constructor.
        The creation of a deflated SAML Request
        """
        authn_request = Saml2_Authn_Request(self.__settings)
        parameters = {"SAMLRequest": authn_request.get_request()}
        auth_url = Saml2_Utils.redirect("http://idp.example.com/SSOService.php", parameters, True)
        self.assertRegex(auth_url, r"^http://idp\.example\.com\/SSOService\.php\?SAMLRequest=")
        exploded = urlparse(auth_url)
        exploded = parse_qs(exploded[4])
        payload = exploded["SAMLRequest"][0]
        inflated = compat.to_string(Saml2_Utils.decode_base64_and_inflate(payload))
        self.assertRegex(inflated, "^<samlp:AuthnRequest")

    def testCreateEncSAMLRequest(self):
        """
        Tests the Saml2_Authn_Request Constructor.
        The creation of a deflated SAML Request
        """
        settings = self.loadSettingsJSON()
        settings["organization"] = {
            "es": {"name": "sp_prueba", "displayname": "SP prueba", "url": "http://sp.example.com"}
        }
        settings["security"]["wantNameIdEncrypted"] = True
        settings = Saml2_Settings(settings)

        authn_request = Saml2_Authn_Request(settings)
        parameters = {"SAMLRequest": authn_request.get_request()}
        auth_url = Saml2_Utils.redirect("http://idp.example.com/SSOService.php", parameters, True)
        self.assertRegex(auth_url, r"^http://idp\.example\.com\/SSOService\.php\?SAMLRequest=")
        exploded = urlparse(auth_url)
        exploded = parse_qs(exploded[4])
        payload = exploded["SAMLRequest"][0]
        inflated = compat.to_string(Saml2_Utils.decode_base64_and_inflate(payload))
        self.assertRegex(inflated, "^<samlp:AuthnRequest")
        self.assertRegex(
            inflated, 'AssertionConsumerServiceURL="http://stuff.com/endpoints/endpoints/acs.php">'
        )
        self.assertRegex(
            inflated, "<saml:Issuer>http://stuff.com/endpoints/metadata.php</saml:Issuer>"
        )
        self.assertRegex(inflated, 'Format="urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted"')
        self.assertRegex(inflated, 'ProviderName="SP prueba"')

    def testGetID(self):
        """
        Tests the get_id method of the Saml2_Authn_Request.
        """
        saml_settings = self.loadSettingsJSON()
        settings = Saml2_Settings(saml_settings)
        authn_request = Saml2_Authn_Request(settings)
        authn_request_encoded = authn_request.get_request()
        inflated = compat.to_string(Saml2_Utils.decode_base64_and_inflate(authn_request_encoded))
        document = Saml2_XML.to_etree(inflated)
        self.assertEqual(authn_request.get_id(), document.get("ID", None))

    def testAttributeConsumingService(self):
        """
        Tests that the attributeConsumingServiceIndex is present as an attribute
        """
        saml_settings = self.loadSettingsJSON()
        settings = Saml2_Settings(saml_settings)

        authn_request = Saml2_Authn_Request(settings)
        authn_request_encoded = authn_request.get_request()
        inflated = compat.to_string(Saml2_Utils.decode_base64_and_inflate(authn_request_encoded))

        self.assertNotIn('AttributeConsumingServiceIndex="1"', inflated)

        saml_settings = self.loadSettingsJSON("settings4.json")
        settings = Saml2_Settings(saml_settings)

        authn_request = Saml2_Authn_Request(settings)
        authn_request_encoded = authn_request.get_request()
        inflated = compat.to_string(Saml2_Utils.decode_base64_and_inflate(authn_request_encoded))

        self.assertRegex(inflated, 'AttributeConsumingServiceIndex="1"')
