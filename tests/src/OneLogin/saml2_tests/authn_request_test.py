# -*- coding: utf-8 -*-

# Copyright (c) 2014, OneLogin, Inc.
# All rights reserved.

from base64 import b64decode
import json
from os.path import dirname, join, exists
import unittest
from urlparse import urlparse, parse_qs
from zlib import decompress

from onelogin.saml2.authn_request import OneLogin_Saml2_Authn_Request
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils


class OneLogin_Saml2_Authn_Request_Test(unittest.TestCase):
    def loadSettingsJSON(self):
        filename = join(dirname(__file__), '..', '..', '..', 'settings', 'settings1.json')
        if exists(filename):
            stream = open(filename, 'r')
            settings = json.load(stream)
            stream.close()
            return settings
        else:
            raise Exception('Settings json file does not exist')

    def setUp(self):
        self.__settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())

    def testCreateRequest(self):
        """
        Tests the OneLogin_Saml2_Authn_Request Constructor.
        The creation of a deflated SAML Request
        """

        saml_settings = self.loadSettingsJSON()
        settings = OneLogin_Saml2_Settings(saml_settings)
        settings._OneLogin_Saml2_Settings__organization = {
            u'en-US': {
                u'url': u'http://sp.example.com',
                u'name': u'sp_test'
            }
        }

        authn_request = OneLogin_Saml2_Authn_Request(settings)
        authn_request_encoded = authn_request.get_request()
        decoded = b64decode(authn_request_encoded)
        inflated = decompress(decoded, -15)
        self.assertRegexpMatches(inflated, '^<samlp:AuthnRequest')
        self.assertNotIn('ProviderName="SP test"', inflated)

        saml_settings['organization'] = {}
        settings = OneLogin_Saml2_Settings(saml_settings)

        authn_request = OneLogin_Saml2_Authn_Request(settings)
        authn_request_encoded = authn_request.get_request()
        decoded = b64decode(authn_request_encoded)
        inflated = decompress(decoded, -15)
        self.assertRegexpMatches(inflated, '^<samlp:AuthnRequest')
        self.assertNotIn('ProviderName="SP test"', inflated)

    def testCreateRequestAuthContext(self):
        """
        Tests the OneLogin_Saml2_Authn_Request Constructor.
        The creation of a deflated SAML Request with defined AuthContext
        """
        saml_settings = self.loadSettingsJSON()
        settings = OneLogin_Saml2_Settings(saml_settings)
        authn_request = OneLogin_Saml2_Authn_Request(settings)
        authn_request_encoded = authn_request.get_request()
        decoded = b64decode(authn_request_encoded)
        inflated = decompress(decoded, -15)
        self.assertRegexpMatches(inflated, '^<samlp:AuthnRequest')
        self.assertIn(OneLogin_Saml2_Constants.AC_PASSWORD, inflated)
        self.assertNotIn(OneLogin_Saml2_Constants.AC_X509, inflated)

        saml_settings['sp']['AuthnContextClassRef'] = OneLogin_Saml2_Constants.AC_X509
        settings = OneLogin_Saml2_Settings(saml_settings)
        authn_request = OneLogin_Saml2_Authn_Request(settings)
        authn_request_encoded = authn_request.get_request()
        decoded = b64decode(authn_request_encoded)
        inflated = decompress(decoded, -15)
        self.assertRegexpMatches(inflated, '^<samlp:AuthnRequest')
        self.assertNotIn(OneLogin_Saml2_Constants.AC_PASSWORD, inflated)
        self.assertIn(OneLogin_Saml2_Constants.AC_X509, inflated)

    def testCreateDeflatedSAMLRequestURLParameter(self):
        """
        Tests the OneLogin_Saml2_Authn_Request Constructor.
        The creation of a deflated SAML Request
        """
        authn_request = OneLogin_Saml2_Authn_Request(self.__settings)
        parameters = {
            'SAMLRequest': authn_request.get_request()
        }
        auth_url = OneLogin_Saml2_Utils.redirect('http://idp.example.com/SSOService.php', parameters, True)
        self.assertRegexpMatches(auth_url, '^http://idp\.example\.com\/SSOService\.php\?SAMLRequest=')
        exploded = urlparse(auth_url)
        exploded = parse_qs(exploded[4])
        payload = exploded['SAMLRequest'][0]
        decoded = b64decode(payload)
        inflated = decompress(decoded, -15)
        self.assertRegexpMatches(inflated, '^<samlp:AuthnRequest')

    def testCreateEncSAMLRequest(self):
        """
        Tests the OneLogin_Saml2_Authn_Request Constructor.
        The creation of a deflated SAML Request
        """
        settings = self.loadSettingsJSON()
        settings['organization'] = {
            'es': {
                'name': 'sp_prueba',
                'displayname': 'SP prueba',
                'url': 'http://sp.example.com'
            }
        }
        settings['security']['wantNameIdEncrypted'] = True
        settings = OneLogin_Saml2_Settings(settings)

        authn_request = OneLogin_Saml2_Authn_Request(settings)
        parameters = {
            'SAMLRequest': authn_request.get_request()
        }
        auth_url = OneLogin_Saml2_Utils.redirect('http://idp.example.com/SSOService.php', parameters, True)
        self.assertRegexpMatches(auth_url, '^http://idp\.example\.com\/SSOService\.php\?SAMLRequest=')
        exploded = urlparse(auth_url)
        exploded = parse_qs(exploded[4])
        payload = exploded['SAMLRequest'][0]
        decoded = b64decode(payload)
        inflated = decompress(decoded, -15)

        self.assertRegexpMatches(inflated, '^<samlp:AuthnRequest')
        self.assertRegexpMatches(inflated, 'AssertionConsumerServiceURL="http://stuff.com/endpoints/endpoints/acs.php">')
        self.assertRegexpMatches(inflated, '<saml:Issuer>http://stuff.com/endpoints/metadata.php</saml:Issuer>')
        self.assertRegexpMatches(inflated, 'Format="urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted"')
        self.assertRegexpMatches(inflated, 'ProviderName="SP prueba"')
