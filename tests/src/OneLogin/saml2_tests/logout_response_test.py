# -*- coding: utf-8 -*-

# Copyright (c) 2010-2018 OneLogin, Inc.
# MIT License

import json
from os.path import dirname, join, exists
import unittest
from xml.dom.minidom import parseString

from onelogin.saml2 import compat
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.logout_response import OneLogin_Saml2_Logout_Response
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from onelogin.saml2.utils import OneLogin_Saml2_XML

try:
    from urllib.parse import urlparse, parse_qs
except ImportError:
    from urlparse import urlparse, parse_qs


class OneLogin_Saml2_Logout_Response_Test(unittest.TestCase):
    data_path = join(dirname(dirname(dirname(dirname(__file__)))), 'data')
    settings_path = join(dirname(dirname(dirname(dirname(__file__)))), 'settings')

    # assertRegexpMatches deprecated on python3
    def assertRegex(self, text, regexp, msg=None):
        if hasattr(unittest.TestCase, 'assertRegex'):
            return super(OneLogin_Saml2_Logout_Response_Test, self).assertRegex(text, regexp, msg)
        else:
            return self.assertRegexpMatches(text, regexp, msg)

    # assertRaisesRegexp deprecated on python3
    def assertRaisesRegex(self, exception, regexp, msg=None):
        if hasattr(unittest.TestCase, 'assertRaisesRegex'):
            return super(OneLogin_Saml2_Logout_Response_Test, self).assertRaisesRegex(exception, regexp, msg=msg)
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
        Tests the OneLogin_Saml2_LogoutResponse Constructor.
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        message = self.file_contents(join(self.data_path, 'logout_responses', 'logout_response_deflated.xml.base64'))
        response = OneLogin_Saml2_Logout_Response(settings, message)
        self.assertRegex(compat.to_string(OneLogin_Saml2_XML.to_string(response.document)), '<samlp:LogoutResponse')

    def testCreateDeflatedSAMLLogoutResponseURLParameter(self):
        """
        Tests the OneLogin_Saml2_LogoutResponse Constructor.
        The creation of a deflated SAML Logout Response
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        in_response_to = 'ONELOGIN_21584ccdfaca36a145ae990442dcd96bfe60151e'
        response_builder = OneLogin_Saml2_Logout_Response(settings)
        response_builder.build(in_response_to)
        parameters = {'SAMLResponse': response_builder.get_response()}

        logout_url = OneLogin_Saml2_Utils.redirect('http://idp.example.com/SingleLogoutService.php', parameters, True)

        self.assertRegex(logout_url, r'^http://idp\.example\.com\/SingleLogoutService\.php\?SAMLResponse=')
        url_parts = urlparse(logout_url)
        exploded = parse_qs(url_parts.query)
        inflated = compat.to_string(OneLogin_Saml2_Utils.decode_base64_and_inflate(exploded['SAMLResponse'][0]))
        self.assertRegex(inflated, '^<samlp:LogoutResponse')

    def testGetStatus(self):
        """
        Tests the get_status method of the OneLogin_Saml2_LogoutResponse
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        message = self.file_contents(join(self.data_path, 'logout_responses', 'logout_response_deflated.xml.base64'))
        response = OneLogin_Saml2_Logout_Response(settings, message)
        status = response.get_status()
        self.assertEqual(status, OneLogin_Saml2_Constants.STATUS_SUCCESS)

        dom = parseString(OneLogin_Saml2_Utils.decode_base64_and_inflate(message))
        status_code_node = dom.getElementsByTagName('samlp:StatusCode')[0]
        status_code_node.parentNode.removeChild(status_code_node)
        xml = dom.toxml()
        message_2 = OneLogin_Saml2_Utils.deflate_and_base64_encode(xml)
        response_2 = OneLogin_Saml2_Logout_Response(settings, message_2)
        self.assertIsNone(response_2.get_status())

    def testGetIssuer(self):
        """
        Tests the get_issuer of the OneLogin_Saml2_LogoutResponse
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        message = self.file_contents(join(self.data_path, 'logout_responses', 'logout_response_deflated.xml.base64'))
        response = OneLogin_Saml2_Logout_Response(settings, message)

        issuer = response.get_issuer()
        self.assertEqual('http://idp.example.com/', issuer)

        dom = parseString(OneLogin_Saml2_Utils.decode_base64_and_inflate(message))
        issuer_node = dom.getElementsByTagName('saml:Issuer')[0]
        issuer_node.parentNode.removeChild(issuer_node)
        xml = dom.toxml()
        message_2 = OneLogin_Saml2_Utils.deflate_and_base64_encode(xml)
        response_2 = OneLogin_Saml2_Logout_Response(settings, message_2)
        issuer_2 = response_2.get_issuer()
        self.assertIsNone(issuer_2)

    def testQuery(self):
        """
        Tests the private method __query of the OneLogin_Saml2_LogoutResponse
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        message = self.file_contents(join(self.data_path, 'logout_responses', 'logout_response_deflated.xml.base64'))
        response = OneLogin_Saml2_Logout_Response(settings, message)

        issuer = response.get_issuer()
        self.assertEqual('http://idp.example.com/', issuer)

    def testIsInvalidXML(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_LogoutResponse
        Case Invalid XML
        """
        message = OneLogin_Saml2_Utils.deflate_and_base64_encode('<xml>invalid</xml>')
        request_data = {
            'http_host': 'example.com',
            'script_name': 'index.html',
            'get_data': {}
        }
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())

        response = OneLogin_Saml2_Logout_Response(settings, message)
        self.assertTrue(response.is_valid(request_data))

        settings.set_strict(True)
        response_2 = OneLogin_Saml2_Logout_Response(settings, message)
        self.assertFalse(response_2.is_valid(request_data))

    def testIsInValidRequestId(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_LogoutResponse
        Case invalid request Id
        """
        request_data = {
            'http_host': 'example.com',
            'script_name': 'index.html',
            'get_data': {}
        }
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        message = self.file_contents(join(self.data_path, 'logout_responses', 'logout_response_deflated.xml.base64'))

        plain_message = compat.to_string(OneLogin_Saml2_Utils.decode_base64_and_inflate(message))
        current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)
        plain_message = plain_message.replace('http://stuff.com/endpoints/endpoints/sls.php', current_url)
        message = OneLogin_Saml2_Utils.deflate_and_base64_encode(plain_message)

        request_id = 'invalid_request_id'

        settings.set_strict(False)
        response = OneLogin_Saml2_Logout_Response(settings, message)
        self.assertTrue(response.is_valid(request_data, request_id))

        settings.set_strict(True)
        response_2 = OneLogin_Saml2_Logout_Response(settings, message)
        self.assertFalse(response_2.is_valid(request_data, request_id))
        self.assertIn('The InResponseTo of the Logout Response:', response_2.get_error())
        with self.assertRaisesRegex(Exception, 'The InResponseTo of the Logout Response:'):
            response_2.is_valid(request_data, request_id, raise_exceptions=True)

    def testIsInValidIssuer(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_LogoutResponse
        Case invalid Issuer
        """
        request_data = {
            'http_host': 'example.com',
            'script_name': 'index.html',
            'get_data': {}
        }
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        message = self.file_contents(join(self.data_path, 'logout_responses', 'logout_response_deflated.xml.base64'))

        plain_message = compat.to_string(OneLogin_Saml2_Utils.decode_base64_and_inflate(message))
        current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)
        plain_message = plain_message.replace('http://stuff.com/endpoints/endpoints/sls.php', current_url)
        plain_message = plain_message.replace('http://idp.example.com/', 'http://invalid.issuer.example.com')
        message = OneLogin_Saml2_Utils.deflate_and_base64_encode(plain_message)

        settings.set_strict(False)
        response = OneLogin_Saml2_Logout_Response(settings, message)
        self.assertTrue(response.is_valid(request_data))

        settings.set_strict(True)
        response_2 = OneLogin_Saml2_Logout_Response(settings, message)
        with self.assertRaisesRegex(Exception, 'Invalid issuer in the Logout Response'):
            response_2.is_valid(request_data, raise_exceptions=True)

    def testIsInValidDestination(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_LogoutResponse
        Case invalid Destination
        """
        request_data = {
            'http_host': 'example.com',
            'script_name': 'index.html',
            'get_data': {}
        }
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        message = self.file_contents(join(self.data_path, 'logout_responses', 'logout_response_deflated.xml.base64'))

        settings.set_strict(False)
        response = OneLogin_Saml2_Logout_Response(settings, message)
        self.assertTrue(response.is_valid(request_data))

        settings.set_strict(True)
        response_2 = OneLogin_Saml2_Logout_Response(settings, message)
        with self.assertRaisesRegex(Exception, 'The LogoutResponse was received at'):
            response_2.is_valid(request_data, raise_exceptions=True)

        # Empty destination
        dom = parseString(OneLogin_Saml2_Utils.decode_base64_and_inflate(message))
        dom.firstChild.setAttribute('Destination', '')
        xml = dom.toxml()
        message_3 = OneLogin_Saml2_Utils.deflate_and_base64_encode(xml)
        response_3 = OneLogin_Saml2_Logout_Response(settings, message_3)
        self.assertTrue(response_3.is_valid(request_data))

        # No destination
        dom.firstChild.removeAttribute('Destination')
        xml = dom.toxml()
        message_4 = OneLogin_Saml2_Utils.deflate_and_base64_encode(xml)
        response_4 = OneLogin_Saml2_Logout_Response(settings, message_4)
        self.assertTrue(response_4.is_valid(request_data))

    def testIsValid(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_LogoutResponse
        """
        request_data = {
            'http_host': 'example.com',
            'script_name': 'index.html',
            'get_data': {}
        }
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        message = self.file_contents(join(self.data_path, 'logout_responses', 'logout_response_deflated.xml.base64'))

        response = OneLogin_Saml2_Logout_Response(settings, message)
        self.assertTrue(response.is_valid(request_data))

        settings.set_strict(True)
        response_2 = OneLogin_Saml2_Logout_Response(settings, message)
        with self.assertRaisesRegex(Exception, 'The LogoutResponse was received at'):
            response_2.is_valid(request_data, raise_exceptions=True)

        plain_message = compat.to_string(OneLogin_Saml2_Utils.decode_base64_and_inflate(message))
        current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)
        plain_message = plain_message.replace('http://stuff.com/endpoints/endpoints/sls.php', current_url)
        message_3 = OneLogin_Saml2_Utils.deflate_and_base64_encode(plain_message)

        response_3 = OneLogin_Saml2_Logout_Response(settings, message_3)
        self.assertTrue(response_3.is_valid(request_data))

    def testIsValidRaisesExceptionWhenRaisesArgumentIsTrue(self):
        message = OneLogin_Saml2_Utils.deflate_and_base64_encode('<xml>invalid</xml>')
        request_data = {
            'http_host': 'example.com',
            'script_name': 'index.html',
            'get_data': {}
        }
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        settings.set_strict(True)

        response = OneLogin_Saml2_Logout_Response(settings, message)

        self.assertFalse(response.is_valid(request_data))

        with self.assertRaises(Exception):
            response.is_valid(request_data, raise_exceptions=True)

    def testGetXML(self):
        """
        Tests that we can get the logout response XML directly without
        going through intermediate steps
        """
        response = self.file_contents(join(self.data_path, 'logout_responses', 'logout_response.xml'))
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())

        logout_response_generated = OneLogin_Saml2_Logout_Response(settings)
        logout_response_generated.build("InResponseValue")
        expectedFragment = (
            'Destination="http://idp.example.com/SingleLogoutService.php"\n'
            '  InResponseTo="InResponseValue">\n'
            '    <saml:Issuer>http://stuff.com/endpoints/metadata.php</saml:Issuer>\n'
            '    <samlp:Status>\n'
            '        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />\n'
            '    </samlp:Status>\n'
            '</samlp:LogoutResponse>'
        )
        self.assertIn(expectedFragment, logout_response_generated.get_xml())

        logout_response_processed = OneLogin_Saml2_Logout_Response(settings, OneLogin_Saml2_Utils.deflate_and_base64_encode(response))
        self.assertEqual(response, logout_response_processed.get_xml())
