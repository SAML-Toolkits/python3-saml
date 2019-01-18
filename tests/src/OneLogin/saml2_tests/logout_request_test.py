# -*- coding: utf-8 -*-

# Copyright (c) 2010-2018 OneLogin, Inc.
# MIT License

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
    data_path = join(dirname(dirname(dirname(dirname(__file__)))), 'data')
    settings_path = join(dirname(dirname(dirname(dirname(__file__)))), 'settings')

    # assertRegexpMatches deprecated on python3
    def assertRegex(self, text, regexp, msg=None):
        if hasattr(unittest.TestCase, 'assertRegex'):
            return super(OneLogin_Saml2_Logout_Request_Test, self).assertRegex(text, regexp, msg)
        else:
            return self.assertRegexpMatches(text, regexp, msg)

    # assertRaisesRegexp deprecated on python3
    def assertRaisesRegex(self, exception, regexp, msg=None):
        if hasattr(unittest.TestCase, 'assertRaisesRegex'):
            return super(OneLogin_Saml2_Logout_Request_Test, self).assertRaisesRegex(exception, regexp, msg=msg)
        else:
            return self.assertRaisesRegexp(exception, regexp)

    def loadSettingsJSON(self, name='settings1.json'):
        filename = join(self.settings_path, name)
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
        self.assertRegex(logout_url, r'^http://idp\.example\.com\/SingleLogoutService\.php\?SAMLRequest=')
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
        self.assertRegex(logout_url, r'^http://idp\.example\.com\/SingleLogoutService\.php\?SAMLRequest=')
        url_parts = urlparse(logout_url)
        exploded = parse_qs(url_parts.query)
        payload = exploded['SAMLRequest'][0]
        inflated = compat.to_string(OneLogin_Saml2_Utils.decode_base64_and_inflate(payload))
        self.assertRegex(inflated, '^<samlp:LogoutRequest')

    def testConstructorWithNameIdFormatOnSettings(self):
        """
        Tests the OneLogin_Saml2_LogoutRequest Constructor.
        Case: Defines NameIDFormat from settings
        """
        settings_info = self.loadSettingsJSON()
        name_id = 'ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c'
        name_id_format = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'
        settings_info['sp']['NameIDFormat'] = name_id_format
        settings = OneLogin_Saml2_Settings(settings_info)
        logout_request = OneLogin_Saml2_Logout_Request(settings, name_id=name_id)
        logout_request_xml = OneLogin_Saml2_Utils.decode_base64_and_inflate(logout_request.get_request())
        name_id_data = OneLogin_Saml2_Logout_Request.get_nameid_data(logout_request_xml)
        expected_name_id_data = {
            'Value': name_id,
            'Format': name_id_format
        }
        self.assertEqual(expected_name_id_data, name_id_data)

    def testConstructorWithoutNameIdFormat(self):
        """
        Tests the OneLogin_Saml2_LogoutRequest Constructor.
        Case: Checks that NameIDFormat is not added
        """
        settings_info = self.loadSettingsJSON()
        name_id = 'ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c'
        name_id_format = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'
        settings_info['sp']['NameIDFormat'] = name_id_format
        settings = OneLogin_Saml2_Settings(settings_info)
        logout_request = OneLogin_Saml2_Logout_Request(settings, name_id=name_id)
        logout_request_xml = OneLogin_Saml2_Utils.decode_base64_and_inflate(logout_request.get_request())
        name_id_data = OneLogin_Saml2_Logout_Request.get_nameid_data(logout_request_xml)
        expected_name_id_data = {
            'Value': name_id
        }
        self.assertEqual(expected_name_id_data, name_id_data)

    def testConstructorEncryptIdUsingX509certMulti(self):
        """
        Tests the OneLogin_Saml2_LogoutRequest Constructor.
        Case: Able to generate encryptedID with MultiCert
        """
        settings_info = self.loadSettingsJSON('settings8.json')
        settings_info['security']['nameIdEncrypted'] = True
        settings = OneLogin_Saml2_Settings(settings_info)

        logout_request = OneLogin_Saml2_Logout_Request(settings)

        parameters = {'SAMLRequest': logout_request.get_request()}
        logout_url = OneLogin_Saml2_Utils.redirect('http://idp.example.com/SingleLogoutService.php', parameters, True)
        self.assertRegex(logout_url, r'^http://idp\.example\.com\/SingleLogoutService\.php\?SAMLRequest=')
        url_parts = urlparse(logout_url)
        exploded = parse_qs(url_parts.query)
        payload = exploded['SAMLRequest'][0]
        inflated = compat.to_string(OneLogin_Saml2_Utils.decode_base64_and_inflate(payload))
        self.assertRegex(inflated, '^<samlp:LogoutRequest')
        self.assertRegex(inflated, '<saml:EncryptedID>')

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
        with self.assertRaisesRegex(Exception, 'Key is required in order to decrypt the NameID'):
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
        with self.assertRaisesRegex(Exception, 'NameID not found in the Logout Request'):
            OneLogin_Saml2_Logout_Request.get_nameid(dom_2.toxml(), key)

        inv_request = self.file_contents(join(self.data_path, 'logout_requests', 'invalids', 'no_nameId.xml'))
        with self.assertRaisesRegex(Exception, 'NameID not found in the Logout Request'):
            OneLogin_Saml2_Logout_Request.get_nameid(inv_request)

        idp_data = settings.get_idp_data()
        expected_name_id_data = {
            'Format': 'urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress',
            'NameQualifier': idp_data['entityId'],
            'SPNameQualifier': 'http://stuff.com/endpoints/metadata.php',
            'Value': 'ONELOGIN_9c86c4542ab9d6fce07f2f7fd335287b9b3cdf69'
        }

        logout_request = OneLogin_Saml2_Logout_Request(settings, None, expected_name_id_data['Value'], None, idp_data['entityId'], expected_name_id_data['Format'])
        name_id_data_3 = OneLogin_Saml2_Logout_Request.get_nameid_data(logout_request.get_xml())
        self.assertEqual(expected_name_id_data, name_id_data_3)

        expected_name_id_data = {
            'Format': 'urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress',
            'Value': 'ONELOGIN_9c86c4542ab9d6fce07f2f7fd335287b9b3cdf69'
        }
        logout_request = OneLogin_Saml2_Logout_Request(settings, None, expected_name_id_data['Value'], None, None, expected_name_id_data['Format'])
        name_id_data_4 = OneLogin_Saml2_Logout_Request.get_nameid_data(logout_request.get_xml())
        self.assertEqual(expected_name_id_data, name_id_data_4)

        expected_name_id_data = {
            'Format': 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity',
            'Value': 'http://idp.example.com/'
        }
        logout_request = OneLogin_Saml2_Logout_Request(settings)
        name_id_data_5 = OneLogin_Saml2_Logout_Request.get_nameid_data(logout_request.get_xml())
        self.assertEqual(expected_name_id_data, name_id_data_5)

    def testGetNameId(self):
        """
        Tests the get_nameid of the OneLogin_Saml2_LogoutRequest
        """
        request = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request.xml'))
        name_id = OneLogin_Saml2_Logout_Request.get_nameid(request)
        self.assertEqual(name_id, 'ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c')

        request_2 = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request_encrypted_nameid.xml'))
        with self.assertRaisesRegex(Exception, 'Key is required in order to decrypt the NameID'):
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
        with self.assertRaisesRegex(Exception, 'Invalid issuer in the Logout Request'):
            logout_request2.is_valid(request_data, raise_exceptions=True)

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
        with self.assertRaisesRegex(Exception, 'The LogoutRequest was received at'):
            logout_request2.is_valid(request_data, raise_exceptions=True)

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
        with self.assertRaisesRegex(Exception, 'Could not validate timestamp: expired. Check system clock.'):
            logout_request2.is_valid(request_data, raise_exceptions=True)

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
            logout_request.is_valid(request_data, raise_exceptions=True)

    def testGetXML(self):
        """
        Tests that we can get the logout request XML directly without
        going through intermediate steps
        """
        request = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request.xml'))
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())

        logout_request_generated = OneLogin_Saml2_Logout_Request(settings)
        expectedFragment = (
            'Destination="http://idp.example.com/SingleLogoutService.php">\n'
            '    <saml:Issuer>http://stuff.com/endpoints/metadata.php</saml:Issuer>\n'
            '    <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://idp.example.com/</saml:NameID>\n'
            '    \n</samlp:LogoutRequest>'
        )
        self.assertIn(expectedFragment, logout_request_generated.get_xml())

        logout_request_processed = OneLogin_Saml2_Logout_Request(settings, OneLogin_Saml2_Utils.b64encode(request))
        self.assertEqual(request, logout_request_processed.get_xml())
