# -*- coding: utf-8 -*-

# Copyright (c) 2014, OneLogin, Inc.
# All rights reserved.

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
        Tests the OneLogin_Saml2_LogoutResponse Constructor.
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        message = self.file_contents(join(self.data_path, 'logout_responses', 'logout_response_deflated.xml.base64'))
        response = OneLogin_Saml2_Logout_Response(settings, message)
        self.assertRegexpMatches(compat.to_string(OneLogin_Saml2_XML.to_string(response.document)),
                                 '<samlp:LogoutResponse')

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

        self.assertRegexpMatches(logout_url, '^http://idp\.example\.com\/SingleLogoutService\.php\?SAMLResponse=')
        url_parts = urlparse(logout_url)
        exploded = parse_qs(url_parts.query)
        inflated = compat.to_string(OneLogin_Saml2_Utils.decode_base64_and_inflate(exploded['SAMLResponse'][0]))
        self.assertRegexpMatches(inflated, '^<samlp:LogoutResponse')

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
        try:
            valid = response_2.is_valid(request_data, request_id)
            self.assertFalse(valid)
        except Exception as e:
            self.assertIn('The InResponseTo of the Logout Response:', str(e))

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
        try:
            valid = response_2.is_valid(request_data)
            self.assertFalse(valid)
        except Exception as e:
            self.assertIn('Invalid issuer in the Logout Request', str(e))

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
        try:
            valid = response_2.is_valid(request_data)
            self.assertFalse(valid)
        except Exception as e:
            self.assertIn('The LogoutRequest was received at', str(e))

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

    def testIsInValidSign(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_LogoutResponse
        """
        request_data = {
            'http_host': 'example.com',
            'script_name': 'index.html',
            'get_data': {}
        }
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())

        settings.set_strict(False)
        request_data['get_data'] = {
            'SAMLResponse': 'fZJva8IwEMa/Ssl7TZrW/gnqGHMMwSlM8cXeyLU9NaxNQi9lfvxVZczB5ptwSe733MPdjQma2qmFPdjOvyE5awiDU1MbUpevCetaoyyQJmWgQVK+VOvH14WSQ6Fca70tbc1ukPsEEGHrtTUsmM8mbDfKUhnFci8gliGINI/yXIAAiYnsw6JIRgWWAKlkwRZb6skJ64V6nKjDuSEPxvdPIowHIhpIsQkTFaYqSt9ZMEPy2oC/UEfvHSnOnfZFV38MjR1oN7TtgRv8tAZre9CGV9jYkGtT4Wnoju6Bauprme/ebOyErZbPi9XLfLnDoohwhHGc5WVSVhjCKM6rBMpYQpWJrIizfZ4IZNPxuTPqYrmd/m+EdONqPOfy8yG5rhxv0EMFHs52xvxWaHyd3tqD7+j37clWGGyh7vD+POiSrdZdWSIR49NrhR9R/teGTL8A',
            'RelayState': 'https://pitbulk.no-ip.org/newonelogin/demo1/index.php',
            'SigAlg': 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
            'Signature': 'vfWbbc47PkP3ejx4bjKsRX7lo9Ml1WRoE5J5owF/0mnyKHfSY6XbhO1wwjBV5vWdrUVX+xp6slHyAf4YoAsXFS0qhan6txDiZY4Oec6yE+l10iZbzvie06I4GPak4QrQ4gAyXOSzwCrRmJu4gnpeUxZ6IqKtdrKfAYRAcVfNKGA='
        }
        response = OneLogin_Saml2_Logout_Response(settings, request_data['get_data']['SAMLResponse'])
        self.assertTrue(response.is_valid(request_data))

        relay_state = request_data['get_data']['RelayState']
        del request_data['get_data']['RelayState']
        inv_response = OneLogin_Saml2_Logout_Response(settings, request_data['get_data']['SAMLResponse'])
        self.assertFalse(inv_response.is_valid(request_data))
        request_data['get_data']['RelayState'] = relay_state

        settings.set_strict(True)
        response_2 = OneLogin_Saml2_Logout_Response(settings, request_data['get_data']['SAMLResponse'])
        try:
            valid = response_2.is_valid(request_data)
            self.assertFalse(valid)
        except Exception as e:
            self.assertIn('Invalid issuer in the Logout Request', str(e))

        settings.set_strict(False)
        old_signature = request_data['get_data']['Signature']
        request_data['get_data']['Signature'] = 'vfWbbc47PkP3ejx4bjKsRX7lo9Ml1WRoE5J5owF/0mnyKHfSY6XbhO1wwjBV5vWdrUVX+xp6slHyAf4YoAsXFS0qhan6txDiZY4Oec6yE+l10iZbzvie06I4GPak4QrQ4gAyXOSzwCrRmJu4gnpeUxZ6IqKtdrKfAYRAcVf3333='
        response_3 = OneLogin_Saml2_Logout_Response(settings, request_data['get_data']['SAMLResponse'])
        try:
            valid = response_3.is_valid(request_data)
            self.assertFalse(valid)
        except Exception as e:
            self.assertIn('Signature validation failed. Logout Response rejected', str(e))

        request_data['get_data']['Signature'] = old_signature
        old_signature_algorithm = request_data['get_data']['SigAlg']
        del request_data['get_data']['SigAlg']
        response_4 = OneLogin_Saml2_Logout_Response(settings, request_data['get_data']['SAMLResponse'])
        self.assertTrue(response_4.is_valid(request_data))

        request_data['get_data']['RelayState'] = 'http://example.com/relaystate'
        response_5 = OneLogin_Saml2_Logout_Response(settings, request_data['get_data']['SAMLResponse'])
        try:
            valid = response_5.is_valid(request_data)
            self.assertFalse(valid)
        except Exception as e:
            self.assertIn('Signature validation failed. Logout Response rejected', str(e))

        settings.set_strict(True)
        current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)
        plain_message_6 = compat.to_string(OneLogin_Saml2_Utils.decode_base64_and_inflate(request_data['get_data']['SAMLResponse']))
        plain_message_6 = plain_message_6.replace('https://pitbulk.no-ip.org/newonelogin/demo1/index.php?sls', current_url)
        plain_message_6 = plain_message_6.replace('https://pitbulk.no-ip.org/simplesaml/saml2/idp/metadata.php', 'http://idp.example.com/')
        request_data['get_data']['SAMLResponse'] = compat.to_string(OneLogin_Saml2_Utils.deflate_and_base64_encode(plain_message_6))

        response_6 = OneLogin_Saml2_Logout_Response(settings, request_data['get_data']['SAMLResponse'])
        try:
            valid = response_6.is_valid(request_data)
            self.assertFalse(valid)
        except Exception as e:
            self.assertIn('Signature validation failed. Logout Response rejected', str(e))

        settings.set_strict(False)
        response_7 = OneLogin_Saml2_Logout_Response(settings, request_data['get_data']['SAMLResponse'])
        try:
            valid = response_7.is_valid(request_data)
            self.assertFalse(valid)
        except Exception as e:
            self.assertIn('Signature validation failed. Logout Response rejected', str(e))

        request_data['get_data']['SigAlg'] = 'http://www.w3.org/2000/09/xmldsig#dsa-sha1'
        response_8 = OneLogin_Saml2_Logout_Response(settings, request_data['get_data']['SAMLResponse'])
        try:
            valid = response_8.is_valid(request_data)
            self.assertFalse(valid)
        except Exception as e:
            self.assertIn('Invalid signAlg in the recieved Logout Response', str(e))

        settings_info = self.loadSettingsJSON()
        settings_info['strict'] = True
        settings_info['security']['wantMessagesSigned'] = True
        settings = OneLogin_Saml2_Settings(settings_info)

        request_data['get_data']['SigAlg'] = old_signature_algorithm
        old_signature = request_data['get_data']['Signature']
        del request_data['get_data']['Signature']
        request_data['get_data']['SAMLResponse'] = OneLogin_Saml2_Utils.deflate_and_base64_encode(plain_message_6)
        response_9 = OneLogin_Saml2_Logout_Response(settings, request_data['get_data']['SAMLResponse'])
        try:
            valid = response_9.is_valid(request_data)
            self.assertFalse(valid)
        except Exception as e:
            self.assertIn('The Message of the Logout Response is not signed and the SP require it', str(e))

        request_data['get_data']['Signature'] = old_signature
        settings_info['idp']['certFingerprint'] = 'afe71c28ef740bc87425be13a2263d37971da1f9'
        del settings_info['idp']['x509cert']
        settings_2 = OneLogin_Saml2_Settings(settings_info)

        response_10 = OneLogin_Saml2_Logout_Response(settings_2, request_data['get_data']['SAMLResponse'])
        try:
            valid = response_10.is_valid(request_data)
            self.assertFalse(valid)
        except Exception as e:
            self.assertIn('In order to validate the sign on the Logout Response, the x509cert of the IdP is required', str(e))

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
        try:
            valid = response_2.is_valid(request_data)
            self.assertFalse(valid)
        except Exception as e:
            self.assertIn('The LogoutRequest was received at', str(e))

        plain_message = compat.to_string(OneLogin_Saml2_Utils.decode_base64_and_inflate(message))
        current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)
        plain_message = plain_message.replace('http://stuff.com/endpoints/endpoints/sls.php', current_url)
        message_3 = OneLogin_Saml2_Utils.deflate_and_base64_encode(plain_message)

        response_3 = OneLogin_Saml2_Logout_Response(settings, message_3)
        self.assertTrue(response_3.is_valid(request_data))
