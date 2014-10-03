# -*- coding: utf-8 -*-

# Copyright (c) 2014, OneLogin, Inc.
# All rights reserved.

import json
from os.path import dirname, join, exists
import unittest
from urlparse import urlparse, parse_qs
from xml.dom.minidom import parseString

from onelogin.saml2.logout_request import OneLogin_Saml2_Logout_Request
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils


class OneLogin_Saml2_Logout_Request_Test(unittest.TestCase):
    data_path = join(dirname(__file__), '..', '..', '..', 'data')

    def loadSettingsJSON(self):
        filename = join(dirname(__file__), '..', '..', '..', 'settings', 'settings1.json')
        if exists(filename):
            stream = open(filename, 'r')
            settings = json.load(stream)
            stream.close()
            return settings
        else:
            raise Exception('Settings json file does not exist')

    def file_contents(self, filename):
        f = open(filename, 'r')
        content = f.read()
        f.close()
        return content

    def testConstructor(self):
        """
        Tests the OneLogin_Saml2_LogoutRequest Constructor.
        """
        settings_info = self.loadSettingsJSON()
        settings_info['security']['nameIdEncrypted'] = True
        settings = OneLogin_Saml2_Settings(settings_info)

        logout_request = OneLogin_Saml2_Logout_Request(settings)

        parameters = {'SAMLRequest': logout_request.get_request()}
        logout_url = OneLogin_Saml2_Utils.redirect('http://idp.example.com/SingleLogoutService.php', parameters, True)
        self.assertRegexpMatches(logout_url, '^http://idp\.example\.com\/SingleLogoutService\.php\?SAMLRequest=')
        url_parts = urlparse(logout_url)
        exploded = parse_qs(url_parts.query)
        payload = exploded['SAMLRequest'][0]
        inflated = OneLogin_Saml2_Utils.decode_base64_and_inflate(payload)
        self.assertRegexpMatches(inflated, '^<samlp:LogoutRequest')

    def testCreateDeflatedSAMLLogoutRequestURLParameter(self):
        """
        Tests the OneLogin_Saml2_LogoutRequest Constructor.
        The creation of a deflated SAML Logout Request
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        logout_request = OneLogin_Saml2_Logout_Request(settings)

        parameters = {'SAMLRequest': logout_request.get_request()}
        logout_url = OneLogin_Saml2_Utils.redirect('http://idp.example.com/SingleLogoutService.php', parameters, True)
        self.assertRegexpMatches(logout_url, '^http://idp\.example\.com\/SingleLogoutService\.php\?SAMLRequest=')
        url_parts = urlparse(logout_url)
        exploded = parse_qs(url_parts.query)
        payload = exploded['SAMLRequest'][0]
        inflated = OneLogin_Saml2_Utils.decode_base64_and_inflate(payload)
        self.assertRegexpMatches(inflated, '^<samlp:LogoutRequest')

    def testGetIDFromSAMLLogoutRequest(self):
        """
        Tests the get_id method of the OneLogin_Saml2_LogoutRequest
        """
        logout_request = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request.xml'))
        id = OneLogin_Saml2_Logout_Request.get_id(logout_request)
        self.assertEqual('ONELOGIN_21584ccdfaca36a145ae990442dcd96bfe60151e', id)

        dom = parseString(logout_request)
        id2 = OneLogin_Saml2_Logout_Request.get_id(dom)
        self.assertEqual('ONELOGIN_21584ccdfaca36a145ae990442dcd96bfe60151e', id2)

    def testGetIDFromDeflatedSAMLLogoutRequest(self):
        """
        Tests the get_id method of the OneLogin_Saml2_LogoutRequest
        """
        deflated_logout_request = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request_deflated.xml.base64'))
        logout_request = OneLogin_Saml2_Utils.decode_base64_and_inflate(deflated_logout_request)
        id = OneLogin_Saml2_Logout_Request.get_id(logout_request)
        self.assertEqual('ONELOGIN_21584ccdfaca36a145ae990442dcd96bfe60151e', id)

    def testGetNameIdData(self):
        """
        Tests the get_name_id_data method of the OneLogin_Saml2_LogoutRequest
        """
        expected_name_id_data = {
            'Value': 'ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c',
            'Format': 'urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified',
            'SPNameQualifier': 'http://idp.example.com/'
        }

        request = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request.xml'))
        name_id_data = OneLogin_Saml2_Logout_Request.get_name_id_data(request)
        self.assertEqual(expected_name_id_data, name_id_data)

        dom = parseString(request)
        name_id_data_2 = OneLogin_Saml2_Logout_Request.get_name_id_data(dom)
        self.assertEqual(expected_name_id_data, name_id_data_2)

        request_2 = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request_encrypted_nameid.xml'))
        try:
            OneLogin_Saml2_Logout_Request.get_name_id_data(request_2)
            self.assertTrue(False)
        except Exception as e:
            self.assertIn('Key is required in order to decrypt the NameID', e.message)

        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        key = settings.get_sp_key()
        name_id_data_4 = OneLogin_Saml2_Logout_Request.get_name_id_data(request_2, key)
        expected_name_id_data = {
            'Value': 'ONELOGIN_9c86c4542ab9d6fce07f2f7fd335287b9b3cdf69',
            'Format': 'urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress',
            'SPNameQualifier': 'https://pitbulk.no-ip.org/newonelogin/demo1/metadata.php'
        }
        self.assertEqual(expected_name_id_data, name_id_data_4)

        dom_2 = parseString(request_2)
        encrypted_id_nodes = dom_2.getElementsByTagName('saml:EncryptedID')
        encrypted_data = encrypted_id_nodes[0].firstChild.nextSibling
        encrypted_id_nodes[0].removeChild(encrypted_data)
        try:
            OneLogin_Saml2_Logout_Request.get_name_id_data(dom_2.toxml(), key)
            self.assertTre(False)
        except Exception as e:
            self.assertIn('Not NameID found in the Logout Request', e.message)

        inv_request = self.file_contents(join(self.data_path, 'logout_requests', 'invalids', 'no_nameId.xml'))
        try:
            OneLogin_Saml2_Logout_Request.get_name_id_data(inv_request)
            self.assertTre(False)
        except Exception as e:
            self.assertIn('Not NameID found in the Logout Request', e.message)

    def testGetNameId(self):
        """
        Tests the get_name_id of the OneLogin_Saml2_LogoutRequest
        """
        request = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request.xml'))
        name_id = OneLogin_Saml2_Logout_Request.get_name_id(request)
        self.assertEqual(name_id, 'ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c')

        request_2 = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request_encrypted_nameid.xml'))
        try:
            OneLogin_Saml2_Logout_Request.get_name_id(request_2)
            self.assertTrue(False)
        except Exception as e:
            self.assertIn('Key is required in order to decrypt the NameID', e.message)

        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        key = settings.get_sp_key()
        name_id_3 = OneLogin_Saml2_Logout_Request.get_name_id(request_2, key)
        self.assertEqual('ONELOGIN_9c86c4542ab9d6fce07f2f7fd335287b9b3cdf69', name_id_3)

    def testGetIssuer(self):
        """
        Tests the get_issuer of the OneLogin_Saml2_LogoutRequest
        """
        request = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request.xml'))

        issuer = OneLogin_Saml2_Logout_Request.get_issuer(request)
        self.assertEqual('http://idp.example.com/', issuer)

        dom = parseString(request)
        issuer_2 = OneLogin_Saml2_Logout_Request.get_issuer(dom)
        self.assertEqual('http://idp.example.com/', issuer_2)

        issuer_node = dom.getElementsByTagName('saml:Issuer')[0]
        issuer_node.parentNode.removeChild(issuer_node)
        issuer_3 = OneLogin_Saml2_Logout_Request.get_issuer(dom)
        self.assertIsNone(issuer_3)

    def testGetSessionIndexes(self):
        """
        Tests the get_session_indexes of the OneLogin_Saml2_LogoutRequest
        """
        request = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request.xml'))

        session_indexes = OneLogin_Saml2_Logout_Request.get_session_indexes(request)
        self.assertEqual(len(session_indexes), 0)

        dom = parseString(request)
        session_indexes_2 = OneLogin_Saml2_Logout_Request.get_session_indexes(dom)
        self.assertEqual(len(session_indexes_2), 0)

        request_2 = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request_with_sessionindex.xml'))
        session_indexes_3 = OneLogin_Saml2_Logout_Request.get_session_indexes(request_2)
        self.assertEqual(['_ac72a76526cb6ca19f8438e73879a0e6c8ae5131'], session_indexes_3)

    def testIsInvalidXML(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_LogoutRequest
        Case Invalid XML
        """
        request = '<xml>invalid</xml>'
        request_data = {
            'http_host': 'example.com',
            'script_name': 'index.html'
        }
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())

        self.assertTrue(OneLogin_Saml2_Logout_Request.is_valid(settings, request, request_data))
        settings.set_strict(True)
        self.assertFalse(OneLogin_Saml2_Logout_Request.is_valid(settings, request, request_data))

    def testIsInvalidIssuer(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_LogoutRequest
        Case Invalid Issuer
        """
        request = self.file_contents(join(self.data_path, 'logout_requests', 'invalids', 'invalid_issuer.xml'))
        request_data = {
            'http_host': 'example.com',
            'script_name': 'index.html'
        }
        current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)
        request = request.replace('http://stuff.com/endpoints/endpoints/sls.php', current_url)
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        self.assertTrue(OneLogin_Saml2_Logout_Request.is_valid(settings, request, request_data))

        settings.set_strict(True)
        try:
            valid = OneLogin_Saml2_Logout_Request.is_valid(settings, request, request_data)
            self.assertFalse(valid)
        except Exception as e:
            self.assertIn('Invalid issuer in the Logout Request', e.message)

    def testIsInvalidDestination(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_LogoutRequest
        Case Invalid Destination
        """
        request_data = {
            'http_host': 'example.com',
            'script_name': 'index.html'
        }
        request = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request.xml'))
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        self.assertTrue(OneLogin_Saml2_Logout_Request.is_valid(settings, request, request_data))

        settings.set_strict(True)
        try:
            valid = OneLogin_Saml2_Logout_Request.is_valid(settings, request, request_data)
            self.assertFalse(valid)
        except Exception as e:
            self.assertIn('The LogoutRequest was received at', e.message)

        dom = parseString(request)
        dom.documentElement.setAttribute('Destination', None)
        self.assertTrue(OneLogin_Saml2_Logout_Request.is_valid(settings, dom.toxml(), request_data))

        dom.documentElement.removeAttribute('Destination')
        self.assertTrue(OneLogin_Saml2_Logout_Request.is_valid(settings, dom.toxml(), request_data))

    def testIsInvalidNotOnOrAfter(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_LogoutRequest
        Case Invalid NotOnOrAfter
        """
        request_data = {
            'http_host': 'example.com',
            'script_name': 'index.html'
        }
        request = self.file_contents(join(self.data_path, 'logout_requests', 'invalids', 'not_after_failed.xml'))
        current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)
        request = request.replace('http://stuff.com/endpoints/endpoints/sls.php', current_url)
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        self.assertTrue(OneLogin_Saml2_Logout_Request.is_valid(settings, request, request_data))

        settings.set_strict(True)
        try:
            valid = OneLogin_Saml2_Logout_Request.is_valid(settings, request, request_data)
            self.assertFalse(valid)
        except Exception as e:
            self.assertIn('Timing issues (please check your clock settings)', e.message)

    def testIsValid(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_LogoutRequest
        """
        request_data = {
            'http_host': 'example.com',
            'script_name': 'index.html'
        }
        request = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request.xml'))
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())

        self.assertTrue(OneLogin_Saml2_Logout_Request.is_valid(settings, request, request_data))

        settings.set_strict(True)
        self.assertFalse(OneLogin_Saml2_Logout_Request.is_valid(settings, request, request_data))

        settings.set_strict(False)
        dom = parseString(request)
        self.assertTrue(OneLogin_Saml2_Logout_Request.is_valid(settings, dom, request_data))

        settings.set_strict(True)
        self.assertFalse(OneLogin_Saml2_Logout_Request.is_valid(settings, dom, request_data))

        current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)
        request_2 = request.replace('http://stuff.com/endpoints/endpoints/sls.php', current_url)
        self.assertTrue(OneLogin_Saml2_Logout_Request.is_valid(settings, request_2, request_data))

    def testIsValidSign(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_LogoutRequest
        """
        request_data = {
            'http_host': 'example.com',
            'script_name': 'index.html',
            'SAMLRequest': 'lVLBitswEP0Vo7tjeWzJtki8LIRCYLvbNksPewmyPc6K2pJqyXQ/v1LSQlroQi/DMJr33rwZbZ2cJysezNms/gt+X9H55G2etBOXlx1ZFy2MdMoJLWd0wvfieP/xQcCGCrsYb3ozkRvI+wjpHC5eGU2Sw35HTg3lA8hqZFwWFcMKsStpxbEsxoLXeQN9OdY1VAgk+YqLC8gdCUQB7tyKB+281D6UaF6mtEiBPudcABcMXkiyD26Ulv6CevXeOpFlVvlunb5ttEmV3ZjlnGn8YTRO5qx0NuBs8kzpAd829tXeucmR5NH4J/203I8el6gFRUqbFPJnyEV51Wq30by4TLW0/9ZyarYTxt4sBsjUYLMZvRykl1Fxm90SXVkfwx4P++T4KSafVzmpUcVJ/sfSrQZJPphllv79W8WKGtLx0ir8IrVTqD1pT2MH3QAMSs4KTvui71jeFFiwirOmprwPkYW063+5uRq4urHiiC4e8hCX3J5wqAEGaPpw9XB5JmkBdeDqSlkz6CmUXdl0Qae5kv2F/1384wu3PwE=',
            'RelayState': '_1037fbc88ec82ce8e770b2bed1119747bb812a07e6',
            'SigAlg': 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
            'Signature': 'XCwCyI5cs7WhiJlB5ktSlWxSBxv+6q2xT3c8L7dLV6NQG9LHWhN7gf8qNsahSXfCzA0Ey9dp5BQ0EdRvAk2DIzKmJY6e3hvAIEp1zglHNjzkgcQmZCcrkK9Czi2Y1WkjOwR/WgUTUWsGJAVqVvlRZuS3zk3nxMrLH6f7toyvuJc='
        }
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)

        request = OneLogin_Saml2_Utils.decode_base64_and_inflate(request_data['SAMLRequest'])

        settings.set_strict(False)
        self.assertTrue(OneLogin_Saml2_Logout_Request.is_valid(settings, request, request_data))

        relayState = request_data['RelayState']
        del request_data['RelayState']
        self.assertFalse(OneLogin_Saml2_Logout_Request.is_valid(settings, request, request_data))
        request_data['RelayState'] = relayState

        settings.set_strict(True)
        try:
            valid = OneLogin_Saml2_Logout_Request.is_valid(settings, request, request_data)
            self.assertFalse(valid)
        except Exception as e:
            self.assertIn('The LogoutRequest was received at', e.message)

        settings.set_strict(False)
        old_signature = request_data['Signature']
        request_data['Signature'] = 'vfWbbc47PkP3ejx4bjKsRX7lo9Ml1WRoE5J5owF/0mnyKHfSY6XbhO1wwjBV5vWdrUVX+xp6slHyAf4YoAsXFS0qhan6txDiZY4Oec6yE+l10iZbzvie06I4GPak4QrQ4gAyXOSzwCrRmJu4gnpeUxZ6IqKtdrKfAYRAcVf3333='
        try:
            valid = OneLogin_Saml2_Logout_Request.is_valid(settings, request, request_data)
            self.assertFalse(valid)
        except Exception as e:
            self.assertIn('Signature validation failed. Logout Request rejected', e.message)

        request_data['Signature'] = old_signature
        old_signature_algorithm = request_data['SigAlg']
        del request_data['SigAlg']
        self.assertTrue(OneLogin_Saml2_Logout_Request.is_valid(settings, request, request_data))

        request_data['RelayState'] = 'http://example.com/relaystate'
        try:
            valid = OneLogin_Saml2_Logout_Request.is_valid(settings, request, request_data)
            self.assertFalse(valid)
        except Exception as e:
            self.assertIn('Signature validation failed. Logout Request rejected', e.message)

        settings.set_strict(True)
        request_2 = request.replace('https://pitbulk.no-ip.org/newonelogin/demo1/index.php?sls', current_url)
        request_2 = request_2.replace('https://pitbulk.no-ip.org/simplesaml/saml2/idp/metadata.php', 'http://idp.example.com/')
        request_data['SAMLRequest'] = OneLogin_Saml2_Utils.deflate_and_base64_encode(request_2)
        try:
            valid = OneLogin_Saml2_Logout_Request.is_valid(settings, request_2, request_data)
            self.assertFalse(valid)
        except Exception as e:
            self.assertIn('Signature validation failed. Logout Request rejected', e.message)

        settings.set_strict(False)
        try:
            valid = OneLogin_Saml2_Logout_Request.is_valid(settings, request_2, request_data)
            self.assertFalse(valid)
        except Exception as e:
            self.assertIn('Signature validation failed. Logout Request rejected', e.message)

        request_data['SigAlg'] = 'http://www.w3.org/2000/09/xmldsig#dsa-sha1'
        try:
            valid = OneLogin_Saml2_Logout_Request.is_valid(settings, request_2, request_data)
            self.assertFalse(valid)
        except Exception as e:
            self.assertIn('Invalid signAlg in the recieved Logout Request', e.message)

        settings_info = self.loadSettingsJSON()
        settings_info['strict'] = True
        settings_info['security']['wantMessagesSigned'] = True
        settings = OneLogin_Saml2_Settings(settings_info)
        request_data['SigAlg'] = old_signature_algorithm
        old_signature = request_data['Signature']
        del request_data['Signature']
        try:
            valid = OneLogin_Saml2_Logout_Request.is_valid(settings, request_2, request_data)
            self.assertFalse(valid)
        except Exception as e:
            self.assertIn('The Message of the Logout Request is not signed and the SP require it', e.message)

        request_data['Signature'] = old_signature
        settings_info['idp']['certFingerprint'] = 'afe71c28ef740bc87425be13a2263d37971da1f9'
        del settings_info['idp']['x509cert']
        settings_2 = OneLogin_Saml2_Settings(settings_info)
        try:
            valid = OneLogin_Saml2_Logout_Request.is_valid(settings_2, request_2, request_data)
            self.assertFalse(valid)
        except Exception as e:
            self.assertIn('In order to validate the sign on the Logout Request, the x509cert of the IdP is required', e.message)
