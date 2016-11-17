# -*- coding: utf-8 -*-

# Copyright (c) 2014, OneLogin, Inc.
# All rights reserved.

import json
from os.path import dirname, join, exists
import unittest
from xml.dom.minidom import parseString

from onelogin.saml2 import compat
from onelogin.saml2.logout_request import OneLogin_Saml2_Logout_Request
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils

try:
    from urllib.parse import urlparse, parse_qs
except ImportError:
    from urlparse import urlparse, parse_qs


class OneLogin_Saml2_Logout_Request_Test(unittest.TestCase):
    data_path = join(dirname(__file__), '..', '..', '..', 'data')

    # assertRegexpMatches deprecated on python3
    def assertRegex(self, text, regexp, msg=None):
        if hasattr(unittest.TestCase, 'assertRegex'):
            return super(OneLogin_Saml2_Logout_Request_Test, self).assertRegex(text, regexp, msg)
        else:
            return self.assertRegexpMatches(text, regexp, msg)

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
        self.assertRegex(logout_url, '^http://idp\.example\.com\/SingleLogoutService\.php\?SAMLRequest=')
        url_parts = urlparse(logout_url)
        exploded = parse_qs(url_parts.query)
        payload = exploded['SAMLRequest'][0]
        inflated = compat.to_string(OneLogin_Saml2_Utils.decode_base64_and_inflate(payload))
        self.assertRegex(inflated, '^<samlp:LogoutRequest')

    def testCreateDeflatedSAMLLogoutRequestURLParameter(self):
        """
        Tests the OneLogin_Saml2_LogoutRequest Constructor.
        The creation of a deflated SAML Logout Request
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        logout_request = OneLogin_Saml2_Logout_Request(settings)

        parameters = {'SAMLRequest': logout_request.get_request()}
        logout_url = OneLogin_Saml2_Utils.redirect('http://idp.example.com/SingleLogoutService.php', parameters, True)
        self.assertRegex(logout_url, '^http://idp\.example\.com\/SingleLogoutService\.php\?SAMLRequest=')
        url_parts = urlparse(logout_url)
        exploded = parse_qs(url_parts.query)
        payload = exploded['SAMLRequest'][0]
        inflated = compat.to_string(OneLogin_Saml2_Utils.decode_base64_and_inflate(payload))
        self.assertRegex(inflated, '^<samlp:LogoutRequest')

    def testGetIDFromSAMLLogoutRequest(self):
        """
        Tests the get_id method of the OneLogin_Saml2_LogoutRequest
        """
        logout_request = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request.xml'))
        id1 = OneLogin_Saml2_Logout_Request.get_id(logout_request)
        self.assertEqual('ONELOGIN_21584ccdfaca36a145ae990442dcd96bfe60151e', id1)

        dom = parseString(logout_request)
        id2 = OneLogin_Saml2_Logout_Request.get_id(dom.toxml())
        self.assertEqual('ONELOGIN_21584ccdfaca36a145ae990442dcd96bfe60151e', id2)

    def testGetIDFromDeflatedSAMLLogoutRequest(self):
        """
        Tests the get_id method of the OneLogin_Saml2_LogoutRequest
        """
        deflated_logout_request = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request_deflated.xml.base64'))
        logout_request = OneLogin_Saml2_Utils.decode_base64_and_inflate(deflated_logout_request)
        id1 = OneLogin_Saml2_Logout_Request.get_id(logout_request)
        self.assertEqual('ONELOGIN_21584ccdfaca36a145ae990442dcd96bfe60151e', id1)

    def testGetNameIdData(self):
        """
        Tests the get_nameid_data method of the OneLogin_Saml2_LogoutRequest
        """
        expected_name_id_data = {
            'Value': 'ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c',
            'Format': 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
            'SPNameQualifier': 'http://idp.example.com/'
        }

        request = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request.xml'))
        name_id_data = OneLogin_Saml2_Logout_Request.get_nameid_data(request)
        self.assertEqual(expected_name_id_data, name_id_data)

        dom = parseString(request)
        name_id_data_2 = OneLogin_Saml2_Logout_Request.get_nameid_data(dom.toxml())
        self.assertEqual(expected_name_id_data, name_id_data_2)

        request_2 = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request_encrypted_nameid.xml'))
        with self.assertRaisesRegexp(Exception, 'Key is required in order to decrypt the NameID'):
            OneLogin_Saml2_Logout_Request.get_nameid(request_2)

        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        key = settings.get_sp_key()
        name_id_data_4 = OneLogin_Saml2_Logout_Request.get_nameid_data(request_2, key)
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
        with self.assertRaisesRegexp(Exception, 'Not NameID found in the Logout Request'):
            OneLogin_Saml2_Logout_Request.get_nameid(dom_2.toxml(), key)

        inv_request = self.file_contents(join(self.data_path, 'logout_requests', 'invalids', 'no_nameId.xml'))
        with self.assertRaisesRegexp(Exception, 'Not NameID found in the Logout Request'):
            OneLogin_Saml2_Logout_Request.get_nameid(inv_request)

    def testGetNameId(self):
        """
        Tests the get_nameid of the OneLogin_Saml2_LogoutRequest
        """
        request = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request.xml'))
        name_id = OneLogin_Saml2_Logout_Request.get_nameid(request)
        self.assertEqual(name_id, 'ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c')

        request_2 = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request_encrypted_nameid.xml'))
        with self.assertRaisesRegexp(Exception, 'Key is required in order to decrypt the NameID'):
            OneLogin_Saml2_Logout_Request.get_nameid(request_2)

        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        key = settings.get_sp_key()
        name_id_3 = OneLogin_Saml2_Logout_Request.get_nameid(request_2, key)
        self.assertEqual('ONELOGIN_9c86c4542ab9d6fce07f2f7fd335287b9b3cdf69', name_id_3)

    def testGetIssuer(self):
        """
        Tests the get_issuer of the OneLogin_Saml2_LogoutRequest
        """
        request = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request.xml'))

        issuer = OneLogin_Saml2_Logout_Request.get_issuer(request)
        self.assertEqual('http://idp.example.com/', issuer)

        dom = parseString(request)
        issuer_2 = OneLogin_Saml2_Logout_Request.get_issuer(dom.toxml())
        self.assertEqual('http://idp.example.com/', issuer_2)

        issuer_node = dom.getElementsByTagName('saml:Issuer')[0]
        issuer_node.parentNode.removeChild(issuer_node)
        issuer_3 = OneLogin_Saml2_Logout_Request.get_issuer(dom.toxml())
        self.assertIsNone(issuer_3)

    def testGetSessionIndexes(self):
        """
        Tests the get_session_indexes of the OneLogin_Saml2_LogoutRequest
        """
        request = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request.xml'))

        session_indexes = OneLogin_Saml2_Logout_Request.get_session_indexes(request)
        self.assertEqual(len(session_indexes), 0)

        dom = parseString(request)
        session_indexes_2 = OneLogin_Saml2_Logout_Request.get_session_indexes(dom.toxml())
        self.assertEqual(len(session_indexes_2), 0)

        request_2 = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request_with_sessionindex.xml'))
        session_indexes_3 = OneLogin_Saml2_Logout_Request.get_session_indexes(request_2)
        self.assertEqual(['_ac72a76526cb6ca19f8438e73879a0e6c8ae5131'], session_indexes_3)

    def testIsInvalidXML(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_LogoutRequest
        Case Invalid XML
        """
        request = OneLogin_Saml2_Utils.b64encode('<xml>invalid</xml>')
        request_data = {
            'http_host': 'example.com',
            'script_name': 'index.html',
        }
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())

        logout_request = OneLogin_Saml2_Logout_Request(settings, request)

        self.assertTrue(logout_request.is_valid(request_data))

        settings.set_strict(True)
        logout_request2 = OneLogin_Saml2_Logout_Request(settings, request)
        self.assertFalse(logout_request2.is_valid(request_data))

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
        logout_request = OneLogin_Saml2_Logout_Request(settings, OneLogin_Saml2_Utils.b64encode(request))
        self.assertTrue(logout_request.is_valid(request_data))

        settings.set_strict(True)
        logout_request2 = OneLogin_Saml2_Logout_Request(settings, OneLogin_Saml2_Utils.b64encode(request))
        with self.assertRaisesRegexp(Exception, 'Invalid issuer in the Logout Request'):
            logout_request2.is_valid(request_data, raises=True)

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
        logout_request = OneLogin_Saml2_Logout_Request(settings, OneLogin_Saml2_Utils.b64encode(request))
        self.assertTrue(logout_request.is_valid(request_data))

        settings.set_strict(True)
        logout_request2 = OneLogin_Saml2_Logout_Request(settings, OneLogin_Saml2_Utils.b64encode(request))
        with self.assertRaisesRegexp(Exception, 'The LogoutRequest was received at'):
            logout_request2.is_valid(request_data, raises=True)

        dom = parseString(request)
        dom.documentElement.setAttribute('Destination', None)
        logout_request3 = OneLogin_Saml2_Logout_Request(settings, OneLogin_Saml2_Utils.b64encode(dom.toxml()))
        self.assertTrue(logout_request3.is_valid(request_data))

        dom.documentElement.removeAttribute('Destination')
        logout_request4 = OneLogin_Saml2_Logout_Request(settings, OneLogin_Saml2_Utils.b64encode(dom.toxml()))
        self.assertTrue(logout_request4.is_valid(request_data))

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

        logout_request = OneLogin_Saml2_Logout_Request(settings, OneLogin_Saml2_Utils.b64encode(request))
        self.assertTrue(logout_request.is_valid(request_data))

        settings.set_strict(True)
        logout_request2 = OneLogin_Saml2_Logout_Request(settings, OneLogin_Saml2_Utils.b64encode(request))
        with self.assertRaisesRegexp(Exception, 'Timing issues \(please check your clock settings\)'):
            logout_request2.is_valid(request_data, raises=True)

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

        logout_request = OneLogin_Saml2_Logout_Request(settings, OneLogin_Saml2_Utils.b64encode(request))
        self.assertTrue(logout_request.is_valid(request_data))

        settings.set_strict(True)
        logout_request2 = OneLogin_Saml2_Logout_Request(settings, OneLogin_Saml2_Utils.b64encode(request))
        self.assertFalse(logout_request2.is_valid(request_data))

        settings.set_strict(False)
        dom = parseString(request)
        logout_request3 = OneLogin_Saml2_Logout_Request(settings, OneLogin_Saml2_Utils.b64encode(dom.toxml()))
        self.assertTrue(logout_request3.is_valid(request_data))

        settings.set_strict(True)
        logout_request4 = OneLogin_Saml2_Logout_Request(settings, OneLogin_Saml2_Utils.b64encode(dom.toxml()))
        self.assertFalse(logout_request4.is_valid(request_data))

        current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)
        request = request.replace('http://stuff.com/endpoints/endpoints/sls.php', current_url)
        logout_request5 = OneLogin_Saml2_Logout_Request(settings, OneLogin_Saml2_Utils.b64encode(request))
        self.assertTrue(logout_request5.is_valid(request_data))

    def testIsValidRaisesExceptionWhenRaisesArgumentIsTrue(self):
        request = OneLogin_Saml2_Utils.b64encode('<xml>invalid</xml>')
        request_data = {
            'http_host': 'example.com',
            'script_name': 'index.html',
        }
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        settings.set_strict(True)

        logout_request = OneLogin_Saml2_Logout_Request(settings, request)

        self.assertFalse(logout_request.is_valid(request_data))

        with self.assertRaises(Exception):
            logout_request.is_valid(request_data, raises=True)
