# -*- coding: utf-8 -*-

# Copyright (c) 2010-2018 OneLogin, Inc.
# MIT License

from base64 import b64decode, b64encode
import json
from os.path import dirname, join, exists
import unittest

from onelogin.saml2 import compat
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils, OneLogin_Saml2_Error
from onelogin.saml2.logout_request import OneLogin_Saml2_Logout_Request

try:
    from urllib.parse import urlparse, parse_qs
except ImportError:
    from urlparse import urlparse, parse_qs


class OneLogin_Saml2_Auth_Test(unittest.TestCase):
    data_path = join(dirname(dirname(dirname(dirname(__file__)))), 'data')
    settings_path = join(dirname(dirname(dirname(dirname(__file__)))), 'settings')

    # assertRaisesRegexp deprecated on python3
    def assertRaisesRegex(self, exception, regexp, msg=None):
        if hasattr(unittest.TestCase, 'assertRaisesRegex'):
            return super(OneLogin_Saml2_Auth_Test, self).assertRaisesRegex(exception, regexp, msg=msg)
        else:
            return self.assertRaisesRegexp(exception, regexp)

    def loadSettingsJSON(self, name='settings1.json'):
        filename = join(self.settings_path, name)
        if exists(filename):
            stream = open(filename, 'r')
            settings = json.load(stream)
            stream.close()
            return settings

    def file_contents(self, filename):
        f = open(filename, 'r')
        content = f.read()
        f.close()
        return content

    def get_request(self):
        return {
            'http_host': 'example.com',
            'script_name': '/index.html',
            'get_data': {}
        }

    def testGetSettings(self):
        """
        Tests the get_settings method of the OneLogin_Saml2_Auth class
        Build a OneLogin_Saml2_Settings object with a setting array
        and compare the value returned from the method of the
        auth object
        """
        settings_info = self.loadSettingsJSON()
        settings = OneLogin_Saml2_Settings(settings_info)
        auth = OneLogin_Saml2_Auth(self.get_request(), old_settings=settings_info)

        auth_settings = auth.get_settings()
        self.assertEqual(settings.get_sp_data(), auth_settings.get_sp_data())

    def testGetSSOurl(self):
        """
        Tests the get_sso_url method of the OneLogin_Saml2_Auth class
        """
        settings_info = self.loadSettingsJSON()
        auth = OneLogin_Saml2_Auth(self.get_request(), old_settings=settings_info)

        sso_url = settings_info['idp']['singleSignOnService']['url']
        self.assertEqual(auth.get_sso_url(), sso_url)

    def testGetSLOurl(self):
        """
        Tests the get_slo_url method of the OneLogin_Saml2_Auth class
        """
        settings_info = self.loadSettingsJSON()
        auth = OneLogin_Saml2_Auth(self.get_request(), old_settings=settings_info)

        slo_url = settings_info['idp']['singleLogoutService']['url']
        self.assertEqual(auth.get_slo_url(), slo_url)

    def testGetSessionIndex(self):
        """
        Tests the get_session_index method of the OneLogin_Saml2_Auth class
        """
        settings_info = self.loadSettingsJSON()
        auth = OneLogin_Saml2_Auth(self.get_request(), old_settings=settings_info)
        self.assertIsNone(auth.get_session_index())

        request_data = self.get_request()
        message = self.file_contents(join(self.data_path, 'responses', 'valid_response.xml.base64'))
        del request_data['get_data']
        request_data['post_data'] = {
            'SAMLResponse': message
        }
        auth2 = OneLogin_Saml2_Auth(request_data, old_settings=self.loadSettingsJSON())
        self.assertIsNone(auth2.get_session_index())

        auth2.process_response()
        self.assertEqual('_6273d77b8cde0c333ec79d22a9fa0003b9fe2d75cb', auth2.get_session_index())

    def testGetSessionExpiration(self):
        """
        Tests the get_session_expiration method of the OneLogin_Saml2_Auth class
        """
        settings_info = self.loadSettingsJSON()
        auth = OneLogin_Saml2_Auth(self.get_request(), old_settings=settings_info)
        self.assertIsNone(auth.get_session_expiration())

        request_data = self.get_request()
        message = self.file_contents(join(self.data_path, 'responses', 'valid_response.xml.base64'))
        del request_data['get_data']
        request_data['post_data'] = {
            'SAMLResponse': message
        }
        auth2 = OneLogin_Saml2_Auth(request_data, old_settings=self.loadSettingsJSON())
        self.assertIsNone(auth2.get_session_expiration())

        auth2.process_response()
        self.assertEqual(2655106621, auth2.get_session_expiration())

    def testGetLastErrorReason(self):
        """
        Tests the get_last_error_reason method of the OneLogin_Saml2_Auth class
        Case Invalid Response
        """
        request_data = self.get_request()
        message = self.file_contents(join(self.data_path, 'responses', 'response1.xml.base64'))
        del request_data['get_data']
        request_data['post_data'] = {
            'SAMLResponse': message
        }
        auth = OneLogin_Saml2_Auth(request_data, old_settings=self.loadSettingsJSON())
        auth.process_response()

        self.assertEqual(auth.get_last_error_reason(), 'Signature validation failed. SAML Response rejected')

    def testProcessNoResponse(self):
        """
        Tests the process_response method of the OneLogin_Saml2_Auth class
        Case No Response, An exception is throw
        """
        auth = OneLogin_Saml2_Auth(self.get_request(), old_settings=self.loadSettingsJSON())
        with self.assertRaisesRegex(OneLogin_Saml2_Error, 'SAML Response not found'):
            auth.process_response()
        self.assertEqual(auth.get_errors(), ['invalid_binding'])

    def testProcessResponseInvalid(self):
        """
        Tests the process_response method of the OneLogin_Saml2_Auth class
        Case Invalid Response, After processing the response the user
        is not authenticated, attributes are notreturned, no nameID and
        the error array is not empty, contains 'invalid_response
        """
        request_data = self.get_request()
        message = self.file_contents(join(self.data_path, 'responses', 'response1.xml.base64'))
        del request_data['get_data']
        request_data['post_data'] = {
            'SAMLResponse': message
        }
        auth = OneLogin_Saml2_Auth(request_data, old_settings=self.loadSettingsJSON())
        auth.process_response()

        self.assertFalse(auth.is_authenticated())
        self.assertEqual(len(auth.get_attributes()), 0)
        self.assertEqual(auth.get_nameid(), None)
        self.assertEqual(auth.get_attribute('uid'), None)
        self.assertEqual(auth.get_errors(), ['invalid_response'])

    def testProcessResponseInvalidRequestId(self):
        """
        Tests the process_response method of the OneLogin_Saml2_Auth class
        Case Invalid Response, Invalid requestID
        """
        request_data = self.get_request()
        message = self.file_contents(join(self.data_path, 'responses', 'unsigned_response.xml.base64'))
        plain_message = compat.to_string(b64decode(message))
        current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)
        plain_message = plain_message.replace('http://stuff.com/endpoints/endpoints/acs.php', current_url)
        del request_data['get_data']
        request_data['post_data'] = {
            'SAMLResponse': compat.to_string(b64encode(compat.to_bytes(plain_message)))
        }
        auth = OneLogin_Saml2_Auth(request_data, old_settings=self.loadSettingsJSON())
        request_id = 'invalid'
        auth.process_response(request_id)
        self.assertEqual('No Signature found. SAML Response rejected', auth.get_last_error_reason())

        auth.set_strict(True)
        auth.process_response(request_id)
        self.assertEqual(auth.get_errors(), ['invalid_response'])
        self.assertEqual('The InResponseTo of the Response: _57bcbf70-7b1f-012e-c821-782bcb13bb38, does not match the ID of the AuthNRequest sent by the SP: invalid', auth.get_last_error_reason())

        valid_request_id = '_57bcbf70-7b1f-012e-c821-782bcb13bb38'
        auth.process_response(valid_request_id)
        self.assertEqual('No Signature found. SAML Response rejected', auth.get_last_error_reason())

    def testProcessResponseValid(self):
        """
        Tests the process_response method of the OneLogin_Saml2_Auth class
        Case Valid Response, After processing the response the user
        is authenticated, attributes are returned, also has a nameID and
        the error array is empty
        """
        request_data = self.get_request()
        message = self.file_contents(join(self.data_path, 'responses', 'valid_response.xml.base64'))
        del request_data['get_data']
        request_data['post_data'] = {
            'SAMLResponse': message
        }
        auth = OneLogin_Saml2_Auth(request_data, old_settings=self.loadSettingsJSON())

        auth.process_response()
        self.assertTrue(auth.is_authenticated())
        self.assertEqual(len(auth.get_errors()), 0)
        self.assertEqual('492882615acf31c8096b627245d76ae53036c090', auth.get_nameid())
        attributes = auth.get_attributes()
        self.assertNotEqual(len(attributes), 0)
        self.assertEqual(auth.get_attribute('mail'), attributes['mail'])
        session_index = auth.get_session_index()
        self.assertEqual('_6273d77b8cde0c333ec79d22a9fa0003b9fe2d75cb', session_index)

    def testRedirectTo(self):
        """
        Tests the redirect_to method of the OneLogin_Saml2_Auth class
        (phpunit raises an exception when a redirect is executed, the
        exception is catched and we check that the targetURL is correct)
        Case redirect without url parameter
        """
        request_data = self.get_request()
        relay_state = 'http://sp.example.com'
        request_data['get_data']['RelayState'] = relay_state
        auth = OneLogin_Saml2_Auth(request_data, old_settings=self.loadSettingsJSON())
        target_url = auth.redirect_to()
        self.assertEqual(target_url, relay_state)

    def testRedirectTowithUrl(self):
        """
        Tests the redirect_to method of the OneLogin_Saml2_Auth class
        (phpunit raises an exception when a redirect is executed, the
        exception is catched and we check that the targetURL is correct)
        Case redirect with url parameter
        """
        request_data = self.get_request()
        relay_state = 'http://sp.example.com'
        url_2 = 'http://sp2.example.com'
        request_data['get_data']['RelayState'] = relay_state
        auth = OneLogin_Saml2_Auth(request_data, old_settings=self.loadSettingsJSON())
        target_url = auth.redirect_to(url_2)
        self.assertEqual(target_url, url_2)

    def testProcessNoSLO(self):
        """
        Tests the process_slo method of the OneLogin_Saml2_Auth class
        Case No Message, An exception is throw
        """
        auth = OneLogin_Saml2_Auth(self.get_request(), old_settings=self.loadSettingsJSON())
        with self.assertRaisesRegex(OneLogin_Saml2_Error, 'SAML LogoutRequest/LogoutResponse not found'):
            auth.process_slo(True)
        self.assertEqual(auth.get_errors(), ['invalid_binding'])

    def testProcessSLOResponseInvalid(self):
        """
        Tests the process_slo method of the OneLogin_Saml2_Auth class
        Case Invalid Logout Response
        """
        request_data = self.get_request()
        message = self.file_contents(join(self.data_path, 'logout_responses', 'logout_response_deflated.xml.base64'))
        request_data['get_data']['SAMLResponse'] = message
        auth = OneLogin_Saml2_Auth(request_data, old_settings=self.loadSettingsJSON())

        auth.process_slo(True)
        self.assertEqual(len(auth.get_errors()), 0)

        auth.set_strict(True)
        auth.process_slo(True)
        # The Destination fails
        self.assertEqual(auth.get_errors(), ['invalid_logout_response'])

        auth.set_strict(False)
        auth.process_slo(True)
        self.assertEqual(len(auth.get_errors()), 0)

    def testProcessSLOResponseNoSucess(self):
        """
        Tests the process_slo method of the OneLogin_Saml2_Auth class
        Case Logout Response not sucess
        """
        request_data = self.get_request()
        message = self.file_contents(join(self.data_path, 'logout_responses', 'invalids', 'status_code_responder.xml.base64'))
        # In order to avoid the destination problem
        plain_message = compat.to_string(OneLogin_Saml2_Utils.decode_base64_and_inflate(message))
        current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)
        plain_message = plain_message.replace('http://stuff.com/endpoints/endpoints/sls.php', current_url)
        message = OneLogin_Saml2_Utils.deflate_and_base64_encode(plain_message)
        request_data['get_data']['SAMLResponse'] = message
        auth = OneLogin_Saml2_Auth(request_data, old_settings=self.loadSettingsJSON())

        auth.set_strict(True)
        auth.process_slo(True)
        self.assertEqual(auth.get_errors(), ['logout_not_success'])

    def testProcessSLOResponseRequestId(self):
        """
        Tests the process_slo method of the OneLogin_Saml2_Auth class
        Case Logout Response with valid and invalid Request ID
        """
        request_data = self.get_request()
        message = self.file_contents(join(self.data_path, 'logout_responses', 'logout_response_deflated.xml.base64'))
        # In order to avoid the destination problem
        plain_message = compat.to_string(OneLogin_Saml2_Utils.decode_base64_and_inflate(message))
        current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)
        plain_message = plain_message.replace('http://stuff.com/endpoints/endpoints/sls.php', current_url)
        message = OneLogin_Saml2_Utils.deflate_and_base64_encode(plain_message)
        request_data['get_data']['SAMLResponse'] = message
        auth = OneLogin_Saml2_Auth(request_data, old_settings=self.loadSettingsJSON())

        request_id = 'wrongID'
        auth.set_strict(True)
        auth.process_slo(True, request_id)
        self.assertEqual(auth.get_errors(), ['invalid_logout_response'])

        request_id = 'ONELOGIN_21584ccdfaca36a145ae990442dcd96bfe60151e'
        auth.process_slo(True, request_id)
        self.assertEqual(len(auth.get_errors()), 0)

    def testProcessSLOResponseValid(self):
        """
        Tests the process_slo method of the OneLogin_Saml2_Auth class
        Case Valid Logout Response
        """
        request_data = self.get_request()
        message = self.file_contents(join(self.data_path, 'logout_responses', 'logout_response_deflated.xml.base64'))
        # In order to avoid the destination problem
        plain_message = compat.to_string(OneLogin_Saml2_Utils.decode_base64_and_inflate(message))
        current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)
        plain_message = plain_message.replace('http://stuff.com/endpoints/endpoints/sls.php', current_url)
        message = OneLogin_Saml2_Utils.deflate_and_base64_encode(plain_message)
        request_data['get_data']['SAMLResponse'] = message
        auth = OneLogin_Saml2_Auth(request_data, old_settings=self.loadSettingsJSON())

        # FIXME
        # if (!isset($_SESSION)) {
        #     $_SESSION = array();
        # }
        # $_SESSION['samltest'] = true;

        auth.set_strict(True)
        auth.process_slo(True)
        self.assertEqual(len(auth.get_errors()), 0)

        # FIXME
        # // Session keep alive
        # $this->assertTrue(isset($_SESSION['samltest']));
        # $this->assertTrue($_SESSION['samltest']);

    def testProcessSLOResponseValidDeletingSession(self):
        """
        Tests the process_slo method of the OneLogin_Saml2_Auth class
        Case Valid Logout Response, validating deleting the local session
        """
        request_data = self.get_request()
        message = self.file_contents(join(self.data_path, 'logout_responses', 'logout_response_deflated.xml.base64'))

        # FIXME
        # if (!isset($_SESSION)) {
        #     $_SESSION = array();
        # }
        # $_SESSION['samltest'] = true;

        # In order to avoid the destination problem
        plain_message = compat.to_string(OneLogin_Saml2_Utils.decode_base64_and_inflate(message))
        current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)
        plain_message = plain_message.replace('http://stuff.com/endpoints/endpoints/sls.php', current_url)
        message = OneLogin_Saml2_Utils.deflate_and_base64_encode(plain_message)
        request_data['get_data']['SAMLResponse'] = message
        auth = OneLogin_Saml2_Auth(request_data, old_settings=self.loadSettingsJSON())

        auth.set_strict(True)
        auth.process_slo(False)

        self.assertEqual(len(auth.get_errors()), 0)

        # FIXME
        # $this->assertFalse(isset($_SESSION['samltest']));

    def testProcessSLORequestInvalidValid(self):
        """
        Tests the process_slo method of the OneLogin_Saml2_Auth class
        Case Invalid Logout Request
        """
        settings_info = self.loadSettingsJSON()
        request_data = self.get_request()
        message = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request_deflated.xml.base64'))
        request_data['get_data']['SAMLRequest'] = message
        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings_info)
        target_url = auth.process_slo(True)
        parsed_query = parse_qs(urlparse(target_url)[4])
        self.assertEqual(len(auth.get_errors()), 0)
        slo_url = settings_info['idp']['singleLogoutService']['url']
        self.assertIn(slo_url, target_url)
        self.assertIn('SAMLResponse', parsed_query)
        # self.assertNotIn('RelayState', parsed_query)

        auth.set_strict(True)
        auth.process_slo(True)
        # Fail due destination missmatch
        self.assertEqual(auth.get_errors(), ['invalid_logout_request'])

        auth.set_strict(False)
        target_url_2 = auth.process_slo(True)
        parsed_query_2 = parse_qs(urlparse(target_url_2)[4])
        self.assertEqual(len(auth.get_errors()), 0)
        slo_url = settings_info['idp']['singleLogoutService']['url']
        self.assertIn(slo_url, target_url_2)
        self.assertIn('SAMLResponse', parsed_query_2)
        # self.assertNotIn('RelayState', parsed_query_2)

    def testProcessSLORequestNotOnOrAfterFailed(self):
        """
        Tests the process_slo method of the OneLogin_Saml2_Auth class
        Case Logout Request NotOnOrAfter failed
        """
        request_data = self.get_request()
        message = self.file_contents(join(self.data_path, 'logout_requests', 'invalids', 'not_after_failed.xml.base64'))
        # In order to avoid the destination problem
        plain_message = compat.to_string(OneLogin_Saml2_Utils.decode_base64_and_inflate(message))
        current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)
        plain_message = plain_message.replace('http://stuff.com/endpoints/endpoints/sls.php', current_url)
        message = OneLogin_Saml2_Utils.deflate_and_base64_encode(plain_message)
        request_data['get_data']['SAMLRequest'] = message
        auth = OneLogin_Saml2_Auth(request_data, old_settings=self.loadSettingsJSON())

        auth.set_strict(True)
        auth.process_slo(True)
        self.assertEqual(auth.get_errors(), ['invalid_logout_request'])

    def testProcessSLORequestDeletingSession(self):
        """
        Tests the process_slo method of the OneLogin_Saml2_Auth class
        Case Valid Logout Request, validating that the local session is deleted,
        a LogoutResponse is created and a redirection executed
        """
        settings_info = self.loadSettingsJSON()
        request_data = self.get_request()
        message = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request_deflated.xml.base64'))
        # In order to avoid the destination problem
        plain_message = compat.to_string(OneLogin_Saml2_Utils.decode_base64_and_inflate(message))
        current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)
        plain_message = plain_message.replace('http://stuff.com/endpoints/endpoints/sls.php', current_url)
        message = OneLogin_Saml2_Utils.deflate_and_base64_encode(plain_message)
        request_data['get_data']['SAMLRequest'] = message
        # FIXME
        # if (!isset($_SESSION)) {
        #     $_SESSION = array();
        # }
        # $_SESSION['samltest'] = true;
        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings_info)

        auth.set_strict(True)
        target_url = auth.process_slo(True)
        parsed_query = parse_qs(urlparse(target_url)[4])
        slo_url = settings_info['idp']['singleLogoutService']['url']
        self.assertIn(slo_url, target_url)
        self.assertIn('SAMLResponse', parsed_query)
        # self.assertNotIn('RelayState', parsed_query)

        # FIXME // Session is not alive
        # $this->assertFalse(isset($_SESSION['samltest']));

        # $_SESSION['samltest'] = true;

        auth.set_strict(True)
        target_url_2 = auth.process_slo(True)
        target_url_2 = auth.process_slo(True)
        parsed_query_2 = parse_qs(urlparse(target_url_2)[4])
        slo_url = settings_info['idp']['singleLogoutService']['url']
        self.assertIn(slo_url, target_url_2)
        self.assertIn('SAMLResponse', parsed_query_2)
        # self.assertNotIn('RelayState', parsed_query_2)

        # FIXME // Session is alive
        # $this->assertTrue(isset($_SESSION['samltest']));
        # $this->assertTrue($_SESSION['samltest']);

    def testProcessSLORequestRelayState(self):
        """
        Tests the process_slo method of the OneLogin_Saml2_Auth class
        Case Valid Logout Request, validating the relayState,
        a LogoutResponse is created and a redirection executed
        """
        settings_info = self.loadSettingsJSON()
        request_data = self.get_request()
        message = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request_deflated.xml.base64'))
        # In order to avoid the destination problem
        plain_message = compat.to_string(OneLogin_Saml2_Utils.decode_base64_and_inflate(message))
        current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)
        plain_message = plain_message.replace('http://stuff.com/endpoints/endpoints/sls.php', current_url)
        message = OneLogin_Saml2_Utils.deflate_and_base64_encode(plain_message)
        request_data['get_data']['SAMLRequest'] = message
        request_data['get_data']['RelayState'] = 'http://relaystate.com'
        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings_info)

        auth.set_strict(True)
        target_url = auth.process_slo(False)
        parsed_query = parse_qs(urlparse(target_url)[4])
        slo_url = settings_info['idp']['singleLogoutService']['url']
        self.assertIn(slo_url, target_url)
        self.assertIn('SAMLResponse', parsed_query)
        self.assertIn('RelayState', parsed_query)
        self.assertIn('http://relaystate.com', parsed_query['RelayState'])

    def testProcessSLORequestSignedResponse(self):
        """
        Tests the process_slo method of the OneLogin_Saml2_Auth class
        Case Valid Logout Request, validating the relayState,
        a signed LogoutResponse is created and a redirection executed
        """
        settings_info = self.loadSettingsJSON()
        settings_info['security']['logoutResponseSigned'] = True
        request_data = self.get_request()
        message = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request_deflated.xml.base64'))
        # In order to avoid the destination problem
        plain_message = compat.to_string(OneLogin_Saml2_Utils.decode_base64_and_inflate(message))
        current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)
        plain_message = plain_message.replace('http://stuff.com/endpoints/endpoints/sls.php', current_url)
        message = OneLogin_Saml2_Utils.deflate_and_base64_encode(plain_message)
        request_data['get_data']['SAMLRequest'] = message
        request_data['get_data']['RelayState'] = 'http://relaystate.com'
        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings_info)

        auth.set_strict(True)
        target_url = auth.process_slo(False)
        parsed_query = parse_qs(urlparse(target_url)[4])
        slo_url = settings_info['idp']['singleLogoutService']['url']
        self.assertIn(slo_url, target_url)
        self.assertIn('SAMLResponse', parsed_query)
        self.assertIn('RelayState', parsed_query)
        self.assertIn('SigAlg', parsed_query)
        self.assertIn('Signature', parsed_query)
        self.assertIn('http://relaystate.com', parsed_query['RelayState'])
        self.assertIn(OneLogin_Saml2_Constants.RSA_SHA1, parsed_query['SigAlg'])

    def testLogin(self):
        """
        Tests the login method of the OneLogin_Saml2_Auth class
        Case Login with no parameters. An AuthnRequest is built an redirect executed
        """
        settings_info = self.loadSettingsJSON()
        request_data = self.get_request()
        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings_info)

        target_url = auth.login()
        parsed_query = parse_qs(urlparse(target_url)[4])
        sso_url = settings_info['idp']['singleSignOnService']['url']
        self.assertIn(sso_url, target_url)
        self.assertIn('SAMLRequest', parsed_query)
        self.assertIn('RelayState', parsed_query)
        hostname = OneLogin_Saml2_Utils.get_self_host(request_data)
        self.assertIn(u'http://%s/index.html' % hostname, parsed_query['RelayState'])

    def testLoginWithRelayState(self):
        """
        Tests the login method of the OneLogin_Saml2_Auth class
        Case Login with relayState. An AuthnRequest is built with a the
        RelayState in the assertion is built and redirect executed
        """
        settings_info = self.loadSettingsJSON()
        auth = OneLogin_Saml2_Auth(self.get_request(), old_settings=settings_info)
        relay_state = 'http://sp.example.com'

        target_url = auth.login(relay_state)
        parsed_query = parse_qs(urlparse(target_url)[4])
        sso_url = settings_info['idp']['singleSignOnService']['url']
        self.assertIn(sso_url, target_url)
        self.assertIn('SAMLRequest', parsed_query)
        self.assertIn('RelayState', parsed_query)
        self.assertIn(relay_state, parsed_query['RelayState'])

    def testLoginSigned(self):
        """
        Tests the login method of the OneLogin_Saml2_Auth class
        Case Login signed. An AuthnRequest signed is built an redirect executed
        """
        settings_info = self.loadSettingsJSON()
        settings_info['security']['authnRequestsSigned'] = True
        auth = OneLogin_Saml2_Auth(self.get_request(), old_settings=settings_info)
        return_to = u'http://example.com/returnto'

        target_url = auth.login(return_to)
        parsed_query = parse_qs(urlparse(target_url)[4])
        sso_url = settings_info['idp']['singleSignOnService']['url']
        self.assertIn(sso_url, target_url)
        self.assertIn('SAMLRequest', parsed_query)
        self.assertIn('RelayState', parsed_query)
        self.assertIn('SigAlg', parsed_query)
        self.assertIn('Signature', parsed_query)
        self.assertIn(return_to, parsed_query['RelayState'])
        self.assertIn(OneLogin_Saml2_Constants.RSA_SHA1, parsed_query['SigAlg'])

    def testLoginForceAuthN(self):
        """
        Tests the login method of the OneLogin_Saml2_Auth class
        Case Logout with no parameters. A AuthN Request is built with ForceAuthn and redirect executed
        """
        settings_info = self.loadSettingsJSON()
        return_to = u'http://example.com/returnto'

        auth = OneLogin_Saml2_Auth(self.get_request(), old_settings=settings_info)
        target_url = auth.login(return_to)
        parsed_query = parse_qs(urlparse(target_url)[4])
        sso_url = settings_info['idp']['singleSignOnService']['url']
        self.assertIn(sso_url, target_url)
        self.assertIn('SAMLRequest', parsed_query)
        request = compat.to_string(OneLogin_Saml2_Utils.decode_base64_and_inflate(parsed_query['SAMLRequest'][0]))
        self.assertNotIn('ForceAuthn="true"', request)

        auth_2 = OneLogin_Saml2_Auth(self.get_request(), old_settings=settings_info)
        target_url_2 = auth_2.login(return_to, False, False)
        parsed_query_2 = parse_qs(urlparse(target_url_2)[4])
        self.assertIn(sso_url, target_url_2)
        self.assertIn('SAMLRequest', parsed_query_2)
        request_2 = compat.to_string(OneLogin_Saml2_Utils.decode_base64_and_inflate(parsed_query_2['SAMLRequest'][0]))
        self.assertNotIn('ForceAuthn="true"', request_2)

        auth_3 = OneLogin_Saml2_Auth(self.get_request(), old_settings=settings_info)
        target_url_3 = auth_3.login(return_to, True, False)
        parsed_query_3 = parse_qs(urlparse(target_url_3)[4])
        self.assertIn(sso_url, target_url_3)
        self.assertIn('SAMLRequest', parsed_query_3)
        request_3 = compat.to_string(OneLogin_Saml2_Utils.decode_base64_and_inflate(parsed_query_3['SAMLRequest'][0]))
        self.assertIn('ForceAuthn="true"', request_3)

    def testLoginIsPassive(self):
        """
        Tests the login method of the OneLogin_Saml2_Auth class
        Case Logout with no parameters. A AuthN Request is built with IsPassive and redirect executed
        """
        settings_info = self.loadSettingsJSON()
        return_to = u'http://example.com/returnto'
        settings_info['idp']['singleSignOnService']['url']

        auth = OneLogin_Saml2_Auth(self.get_request(), old_settings=settings_info)
        target_url = auth.login(return_to)
        parsed_query = parse_qs(urlparse(target_url)[4])
        sso_url = settings_info['idp']['singleSignOnService']['url']
        self.assertIn(sso_url, target_url)
        self.assertIn('SAMLRequest', parsed_query)
        request = compat.to_string(OneLogin_Saml2_Utils.decode_base64_and_inflate(parsed_query['SAMLRequest'][0]))
        self.assertNotIn('IsPassive="true"', request)

        auth_2 = OneLogin_Saml2_Auth(self.get_request(), old_settings=settings_info)
        target_url_2 = auth_2.login(return_to, False, False)
        parsed_query_2 = parse_qs(urlparse(target_url_2)[4])
        self.assertIn(sso_url, target_url_2)
        self.assertIn('SAMLRequest', parsed_query_2)
        request_2 = compat.to_string(OneLogin_Saml2_Utils.decode_base64_and_inflate(parsed_query_2['SAMLRequest'][0]))
        self.assertNotIn('IsPassive="true"', request_2)

        auth_3 = OneLogin_Saml2_Auth(self.get_request(), old_settings=settings_info)
        target_url_3 = auth_3.login(return_to, False, True)
        parsed_query_3 = parse_qs(urlparse(target_url_3)[4])
        self.assertIn(sso_url, target_url_3)
        self.assertIn('SAMLRequest', parsed_query_3)
        request_3 = compat.to_string(OneLogin_Saml2_Utils.decode_base64_and_inflate(parsed_query_3['SAMLRequest'][0]))
        self.assertIn('IsPassive="true"', request_3)

    def testLoginSetNameIDPolicy(self):
        """
        Tests the login method of the OneLogin_Saml2_Auth class
        Case Logout with no parameters. A AuthN Request is built with and without NameIDPolicy
        """
        settings_info = self.loadSettingsJSON()
        return_to = u'http://example.com/returnto'
        settings_info['idp']['singleSignOnService']['url']

        auth = OneLogin_Saml2_Auth(self.get_request(), old_settings=settings_info)
        target_url = auth.login(return_to)
        parsed_query = parse_qs(urlparse(target_url)[4])
        sso_url = settings_info['idp']['singleSignOnService']['url']
        self.assertIn(sso_url, target_url)
        self.assertIn('SAMLRequest', parsed_query)
        request = compat.to_string(OneLogin_Saml2_Utils.decode_base64_and_inflate(parsed_query['SAMLRequest'][0]))
        self.assertIn('<samlp:NameIDPolicy', request)

        auth_2 = OneLogin_Saml2_Auth(self.get_request(), old_settings=settings_info)
        target_url_2 = auth_2.login(return_to, False, False, True)
        parsed_query_2 = parse_qs(urlparse(target_url_2)[4])
        self.assertIn(sso_url, target_url_2)
        self.assertIn('SAMLRequest', parsed_query_2)
        request_2 = compat.to_string(OneLogin_Saml2_Utils.decode_base64_and_inflate(parsed_query_2['SAMLRequest'][0]))
        self.assertIn('<samlp:NameIDPolicy', request_2)

        auth_3 = OneLogin_Saml2_Auth(self.get_request(), old_settings=settings_info)
        target_url_3 = auth_3.login(return_to, False, False, False)
        parsed_query_3 = parse_qs(urlparse(target_url_3)[4])
        self.assertIn(sso_url, target_url_3)
        self.assertIn('SAMLRequest', parsed_query_3)
        request_3 = compat.to_string(OneLogin_Saml2_Utils.decode_base64_and_inflate(parsed_query_3['SAMLRequest'][0]))
        self.assertNotIn('<samlp:NameIDPolicy', request_3)

    def testLogout(self):
        """
        Tests the logout method of the OneLogin_Saml2_Auth class
        Case Logout with no parameters. A logout Request is built and redirect
        executed
        """
        settings_info = self.loadSettingsJSON()
        request_data = self.get_request()
        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings_info)

        target_url = auth.logout()
        parsed_query = parse_qs(urlparse(target_url)[4])
        slo_url = settings_info['idp']['singleLogoutService']['url']
        self.assertIn(slo_url, target_url)
        self.assertIn('SAMLRequest', parsed_query)
        self.assertIn('RelayState', parsed_query)
        hostname = OneLogin_Saml2_Utils.get_self_host(request_data)
        self.assertIn(u'http://%s/index.html' % hostname, parsed_query['RelayState'])

    def testLogoutWithRelayState(self):
        """
        Tests the logout method of the OneLogin_Saml2_Auth class
        Case Logout with relayState. A logout Request with a the RelayState in
        the assertion is built and redirect executed
        """
        settings_info = self.loadSettingsJSON()
        auth = OneLogin_Saml2_Auth(self.get_request(), old_settings=settings_info)
        relay_state = 'http://sp.example.com'

        target_url = auth.logout(relay_state)
        parsed_query = parse_qs(urlparse(target_url)[4])
        slo_url = settings_info['idp']['singleLogoutService']['url']
        self.assertIn(slo_url, target_url)
        self.assertIn('SAMLRequest', parsed_query)
        self.assertIn('RelayState', parsed_query)
        self.assertIn(relay_state, parsed_query['RelayState'])

    def testLogoutSigned(self):
        """
        Tests the logout method of the OneLogin_Saml2_Auth class
        Case Logout signed. A logout Request signed in
        the assertion is built and redirect executed
        """
        settings_info = self.loadSettingsJSON()
        settings_info['security']['logoutRequestSigned'] = True
        auth = OneLogin_Saml2_Auth(self.get_request(), old_settings=settings_info)
        return_to = u'http://example.com/returnto'

        target_url = auth.logout(return_to)
        parsed_query = parse_qs(urlparse(target_url)[4])
        slo_url = settings_info['idp']['singleLogoutService']['url']
        self.assertIn(slo_url, target_url)
        self.assertIn('SAMLRequest', parsed_query)
        self.assertIn('RelayState', parsed_query)
        self.assertIn('SigAlg', parsed_query)
        self.assertIn('Signature', parsed_query)
        self.assertIn(return_to, parsed_query['RelayState'])
        self.assertIn(OneLogin_Saml2_Constants.RSA_SHA1, parsed_query['SigAlg'])

    def testLogoutNoSLO(self):
        """
        Tests the logout method of the OneLogin_Saml2_Auth class
        Case IdP no SLO endpoint.
        """
        settings_info = self.loadSettingsJSON()
        del settings_info['idp']['singleLogoutService']
        auth = OneLogin_Saml2_Auth(self.get_request(), old_settings=settings_info)
        # The Header of the redirect produces an Exception
        with self.assertRaisesRegex(OneLogin_Saml2_Error, 'The IdP does not support Single Log Out'):
            auth.logout('http://example.com/returnto')

    def testLogoutNameIDandSessionIndex(self):
        """
        Tests the logout method of the OneLogin_Saml2_Auth class
        Case nameID and sessionIndex as parameters.
        """
        settings_info = self.loadSettingsJSON()
        request_data = self.get_request()
        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings_info)

        name_id = 'name_id_example'
        session_index = 'session_index_example'
        target_url = auth.logout(name_id=name_id, session_index=session_index)
        parsed_query = parse_qs(urlparse(target_url)[4])
        slo_url = settings_info['idp']['singleLogoutService']['url']
        self.assertIn(slo_url, target_url)
        self.assertIn('SAMLRequest', parsed_query)

        logout_request = OneLogin_Saml2_Utils.decode_base64_and_inflate(parsed_query['SAMLRequest'][0])
        name_id_from_request = OneLogin_Saml2_Logout_Request.get_nameid(logout_request)
        sessions_index_in_request = OneLogin_Saml2_Logout_Request.get_session_indexes(logout_request)
        self.assertIn(session_index, sessions_index_in_request)
        self.assertEqual(name_id, name_id_from_request)

    def testLogoutNameID(self):
        """
        Tests the logout method of the OneLogin_Saml2_Auth class
        Case nameID loaded after process SAML Response
        """
        request_data = self.get_request()
        message = self.file_contents(join(self.data_path, 'responses', 'valid_response.xml.base64'))
        del request_data['get_data']
        request_data['post_data'] = {
            'SAMLResponse': message
        }
        auth = OneLogin_Saml2_Auth(request_data, old_settings=self.loadSettingsJSON())
        auth.process_response()

        name_id_from_response = auth.get_nameid()
        name_id_format_from_response = auth.get_nameid_format()

        target_url = auth.logout()
        parsed_query = parse_qs(urlparse(target_url)[4])
        self.assertIn('SAMLRequest', parsed_query)
        logout_request = OneLogin_Saml2_Utils.decode_base64_and_inflate(parsed_query['SAMLRequest'][0])

        name_id_from_request = OneLogin_Saml2_Logout_Request.get_nameid(logout_request)
        name_id_format_from_request = OneLogin_Saml2_Logout_Request.get_nameid_format(logout_request)
        self.assertEqual(name_id_from_response, name_id_from_request)
        self.assertEqual(name_id_format_from_response, name_id_format_from_request)

        new_name_id = "new_name_id"
        new_name_id_format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        target_url_2 = auth.logout(name_id=new_name_id, name_id_format=new_name_id_format)
        parsed_query = parse_qs(urlparse(target_url_2)[4])
        self.assertIn('SAMLRequest', parsed_query)
        logout_request = OneLogin_Saml2_Utils.decode_base64_and_inflate(parsed_query['SAMLRequest'][0])

        name_id_from_request = OneLogin_Saml2_Logout_Request.get_nameid(logout_request)
        name_id_format_from_request = OneLogin_Saml2_Logout_Request.get_nameid_format(logout_request)
        self.assertEqual(new_name_id, name_id_from_request)
        self.assertEqual(new_name_id_format, name_id_format_from_request)

    def testSetStrict(self):
        """
        Tests the set_strict method of the OneLogin_Saml2_Auth
        """
        settings_info = self.loadSettingsJSON()
        settings_info['strict'] = False
        auth = OneLogin_Saml2_Auth(self.get_request(), old_settings=settings_info)

        settings = auth.get_settings()
        self.assertFalse(settings.is_strict())

        auth.set_strict(True)
        settings = auth.get_settings()
        self.assertTrue(settings.is_strict())

        auth.set_strict(False)
        settings = auth.get_settings()
        self.assertFalse(settings.is_strict())

        self.assertRaises(AssertionError, auth.set_strict, '42')

    def testIsAuthenticated(self):
        """
        Tests the is_authenticated method of the OneLogin_Saml2_Auth
        """
        request_data = self.get_request()
        del request_data['get_data']
        message = self.file_contents(join(self.data_path, 'responses', 'response1.xml.base64'))
        request_data['post_data'] = {
            'SAMLResponse': message
        }
        auth = OneLogin_Saml2_Auth(request_data, old_settings=self.loadSettingsJSON())
        auth.process_response()
        self.assertFalse(auth.is_authenticated())

        message = self.file_contents(join(self.data_path, 'responses', 'valid_response.xml.base64'))
        request_data['post_data'] = {
            'SAMLResponse': message
        }
        auth = OneLogin_Saml2_Auth(request_data, old_settings=self.loadSettingsJSON())
        auth.process_response()
        self.assertTrue(auth.is_authenticated())

    def testGetNameId(self):
        """
        Tests the get_nameid method of the OneLogin_Saml2_Auth
        """
        settings = self.loadSettingsJSON()
        request_data = self.get_request()
        del request_data['get_data']
        message = self.file_contents(join(self.data_path, 'responses', 'response1.xml.base64'))
        request_data['post_data'] = {
            'SAMLResponse': message
        }
        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings)
        auth.process_response()
        self.assertFalse(auth.is_authenticated())
        self.assertEqual(auth.get_nameid(), None)

        message = self.file_contents(join(self.data_path, 'responses', 'valid_response.xml.base64'))
        request_data['post_data'] = {
            'SAMLResponse': message
        }
        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings)
        auth.process_response()
        self.assertTrue(auth.is_authenticated())
        self.assertEqual("492882615acf31c8096b627245d76ae53036c090", auth.get_nameid())

        settings_2 = self.loadSettingsJSON('settings2.json')
        message = self.file_contents(join(self.data_path, 'responses', 'signed_message_encrypted_assertion2.xml.base64'))
        request_data['post_data'] = {
            'SAMLResponse': message
        }
        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings_2)
        auth.process_response()
        self.assertTrue(auth.is_authenticated())
        self.assertEqual("25ddd7d34a7d79db69167625cda56a320adf2876", auth.get_nameid())

    def testGetNameIdFormat(self):
        """
        Tests the get_nameid_format method of the OneLogin_Saml2_Auth
        """
        settings = self.loadSettingsJSON()
        request_data = self.get_request()
        del request_data['get_data']
        message = self.file_contents(join(self.data_path, 'responses', 'response1.xml.base64'))
        request_data['post_data'] = {
            'SAMLResponse': message
        }
        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings)
        auth.process_response()
        self.assertFalse(auth.is_authenticated())
        self.assertEqual(auth.get_nameid_format(), None)

        message = self.file_contents(join(self.data_path, 'responses', 'valid_response.xml.base64'))
        request_data['post_data'] = {
            'SAMLResponse': message
        }
        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings)
        auth.process_response()
        self.assertTrue(auth.is_authenticated())
        self.assertEqual("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", auth.get_nameid_format())

        settings_2 = self.loadSettingsJSON('settings2.json')
        message = self.file_contents(join(self.data_path, 'responses', 'signed_message_encrypted_assertion2.xml.base64'))
        request_data['post_data'] = {
            'SAMLResponse': message
        }
        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings_2)
        auth.process_response()
        self.assertTrue(auth.is_authenticated())
        self.assertEqual("urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified", auth.get_nameid_format())

    def testBuildRequestSignature(self):
        """
        Tests the build_request_signature method of the OneLogin_Saml2_Auth
        """
        settings = self.loadSettingsJSON()
        message = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request_deflated.xml.base64'))
        relay_state = 'http://relaystate.com'
        parameters = {"SAMLRequest": message, "RelayState": relay_state}
        auth = OneLogin_Saml2_Auth(self.get_request(), old_settings=settings)

        auth.add_request_signature(parameters)
        valid_signature = 'Pb1EXAX5TyipSJ1SndEKZstLQTsT+1D00IZAhEepBM+OkAZQSToivu3njgJu47HZiZAqgXZFgloBuuWE/+GdcSsRYEMkEkiSDWTpUr25zKYLJDSg6GNo6iAHsKSuFt46Z54Xe/keYxYP03Hdy97EwuuSjBzzgRc5tmpV+KC7+a0='
        self.assertEqual(valid_signature, parameters["Signature"])

        settings['sp']['privateKey'] = ''
        settings['custom_base_path'] = u'invalid/path/'
        auth2 = OneLogin_Saml2_Auth(self.get_request(), old_settings=settings)
        with self.assertRaisesRegex(OneLogin_Saml2_Error, "Trying to sign the SAMLRequest but can't load the SP private key"):
            auth2.add_request_signature(parameters)

    def testBuildResponseSignature(self):
        """
        Tests the build_response_signature method of the OneLogin_Saml2_Auth
        """
        settings = self.loadSettingsJSON()
        message = self.file_contents(join(self.data_path, 'logout_responses', 'logout_response_deflated.xml.base64'))
        relay_state = 'http://relaystate.com'
        auth = OneLogin_Saml2_Auth(self.get_request(), old_settings=settings)

        parameters = {"SAMLResponse": message, 'RelayState': relay_state}

        auth.add_response_signature(parameters)
        valid_signature = 'IcyWLRX6Dz3wHBfpcUaNLVDMGM3uo6z2Z11Gjq0/APPJaHboKGljffsgMVAGBml497yckq+eYKmmz+jpURV9yTj2sF9qfD6CwX2dEzSzMdRzB40X7pWyHgEJGIhs6BhaOt5oXEk4T+h3AczERqpVYFpL00yo7FNtyQkhZFpHFhM='
        self.assertEqual(valid_signature, parameters['Signature'])

        settings['sp']['privateKey'] = ''
        settings['custom_base_path'] = u'invalid/path/'
        auth2 = OneLogin_Saml2_Auth(self.get_request(), old_settings=settings)
        with self.assertRaisesRegex(OneLogin_Saml2_Error, "Trying to sign the SAMLResponse but can't load the SP private key"):
            auth2.add_response_signature(parameters)

    def testIsInValidLogoutResponseSign(self):
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

        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings)
        auth.process_slo()
        self.assertEqual([], auth.get_errors())

        relay_state = request_data['get_data']['RelayState']
        del request_data['get_data']['RelayState']
        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings)
        auth.process_slo()
        self.assertIn("invalid_logout_response_signature", auth.get_errors())
        request_data['get_data']['RelayState'] = relay_state

        settings.set_strict(True)
        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings)
        auth.process_slo()
        self.assertIn('invalid_logout_response', auth.get_errors())

        settings.set_strict(False)
        old_signature = request_data['get_data']['Signature']
        request_data['get_data']['Signature'] = 'vfWbbc47PkP3ejx4bjKsRX7lo9Ml1WRoE5J5owF/0mnyKHfSY6XbhO1wwjBV5vWdrUVX+xp6slHyAf4YoAsXFS0qhan6txDiZY4Oec6yE+l10iZbzvie06I4GPak4QrQ4gAyXOSzwCrRmJu4gnpeUxZ6IqKtdrKfAYRAcVf3333='
        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings)
        auth.process_slo()
        self.assertIn('invalid_logout_response_signature', auth.get_errors())

        request_data['get_data']['Signature'] = old_signature
        old_signature_algorithm = request_data['get_data']['SigAlg']
        del request_data['get_data']['SigAlg']
        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings)
        auth.process_slo()
        self.assertEqual([], auth.get_errors())

        request_data['get_data']['RelayState'] = 'http://example.com/relaystate'
        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings)
        auth.process_slo()
        self.assertIn('invalid_logout_response_signature', auth.get_errors())

        settings.set_strict(True)
        current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)
        plain_message_6 = compat.to_string(OneLogin_Saml2_Utils.decode_base64_and_inflate(request_data['get_data']['SAMLResponse']))
        plain_message_6 = plain_message_6.replace('https://pitbulk.no-ip.org/newonelogin/demo1/index.php?sls', current_url)
        plain_message_6 = plain_message_6.replace('https://pitbulk.no-ip.org/simplesaml/saml2/idp/metadata.php', 'http://idp.example.com/')
        request_data['get_data']['SAMLResponse'] = compat.to_string(OneLogin_Saml2_Utils.deflate_and_base64_encode(plain_message_6))

        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings)
        auth.process_slo()
        self.assertIn('invalid_logout_response_signature', auth.get_errors())

        settings.set_strict(False)
        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings)
        auth.process_slo()
        self.assertIn('invalid_logout_response_signature', auth.get_errors())

        request_data['get_data']['SigAlg'] = 'http://www.w3.org/2000/09/xmldsig#dsa-sha1'
        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings)
        auth.process_slo()
        self.assertIn('invalid_logout_response_signature', auth.get_errors())

        settings_info = self.loadSettingsJSON()
        settings_info['strict'] = True
        settings_info['security']['wantMessagesSigned'] = True
        settings = OneLogin_Saml2_Settings(settings_info)

        request_data['get_data']['SigAlg'] = old_signature_algorithm
        old_signature = request_data['get_data']['Signature']
        del request_data['get_data']['Signature']
        request_data['get_data']['SAMLResponse'] = OneLogin_Saml2_Utils.deflate_and_base64_encode(plain_message_6)
        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings)
        auth.process_slo()
        self.assertIn('Signature validation failed. Logout Response rejected', auth.get_errors())

        request_data['get_data']['Signature'] = old_signature
        settings_info['idp']['certFingerprint'] = 'afe71c28ef740bc87425be13a2263d37971da1f9'
        del settings_info['idp']['x509cert']
        settings_2 = OneLogin_Saml2_Settings(settings_info)

        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings_2)
        auth.process_slo()
        self.assertIn('Signature validation failed. Logout Response rejected', auth.get_errors())

    def testIsValidLogoutRequestSign(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_LogoutRequest
        """
        request_data = {
            'http_host': 'example.com',
            'script_name': 'index.html',
            'get_data': {
                'SAMLRequest': 'lVLBitswEP0Vo7tjeWzJtki8LIRCYLvbNksPewmyPc6K2pJqyXQ/v1LSQlroQi/DMJr33rwZbZ2cJysezNms/gt+X9H55G2etBOXlx1ZFy2MdMoJLWd0wvfieP/xQcCGCrsYb3ozkRvI+wjpHC5eGU2Sw35HTg3lA8hqZFwWFcMKsStpxbEsxoLXeQN9OdY1VAgk+YqLC8gdCUQB7tyKB+281D6UaF6mtEiBPudcABcMXkiyD26Ulv6CevXeOpFlVvlunb5ttEmV3ZjlnGn8YTRO5qx0NuBs8kzpAd829tXeucmR5NH4J/203I8el6gFRUqbFPJnyEV51Wq30by4TLW0/9ZyarYTxt4sBsjUYLMZvRykl1Fxm90SXVkfwx4P++T4KSafVzmpUcVJ/sfSrQZJPphllv79W8WKGtLx0ir8IrVTqD1pT2MH3QAMSs4KTvui71jeFFiwirOmprwPkYW063+5uRq4urHiiC4e8hCX3J5wqAEGaPpw9XB5JmkBdeDqSlkz6CmUXdl0Qae5kv2F/1384wu3PwE=',
                'RelayState': '_1037fbc88ec82ce8e770b2bed1119747bb812a07e6',
                'SigAlg': 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
                'Signature': 'XCwCyI5cs7WhiJlB5ktSlWxSBxv+6q2xT3c8L7dLV6NQG9LHWhN7gf8qNsahSXfCzA0Ey9dp5BQ0EdRvAk2DIzKmJY6e3hvAIEp1zglHNjzkgcQmZCcrkK9Czi2Y1WkjOwR/WgUTUWsGJAVqVvlRZuS3zk3nxMrLH6f7toyvuJc='
            }
        }
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)

        request = compat.to_string(OneLogin_Saml2_Utils.decode_base64_and_inflate(request_data['get_data']['SAMLRequest']))

        settings.set_strict(False)
        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings)
        auth.process_slo()
        self.assertEqual([], auth.get_errors())

        relay_state = request_data['get_data']['RelayState']
        del request_data['get_data']['RelayState']
        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings)
        auth.process_slo()
        self.assertIn('invalid_logout_request_signature', auth.get_errors())

        request_data['get_data']['RelayState'] = relay_state

        settings.set_strict(True)
        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings)
        auth.process_slo()
        self.assertIn('invalid_logout_request', auth.get_errors())

        settings.set_strict(False)
        old_signature = request_data['get_data']['Signature']
        request_data['get_data']['Signature'] = 'vfWbbc47PkP3ejx4bjKsRX7lo9Ml1WRoE5J5owF/0mnyKHfSY6XbhO1wwjBV5vWdrUVX+xp6slHyAf4YoAsXFS0qhan6txDiZY4Oec6yE+l10iZbzvie06I4GPak4QrQ4gAyXOSzwCrRmJu4gnpeUxZ6IqKtdrKfAYRAcVf3333='
        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings)
        auth.process_slo()
        self.assertIn('invalid_logout_request_signature', auth.get_errors())

        request_data['get_data']['Signature'] = old_signature
        old_signature_algorithm = request_data['get_data']['SigAlg']
        del request_data['get_data']['SigAlg']
        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings)
        auth.process_slo()
        self.assertEqual([], auth.get_errors())

        settings.set_strict(True)
        request_2 = request.replace('https://pitbulk.no-ip.org/newonelogin/demo1/index.php?sls', current_url)
        request_2 = request_2.replace('https://pitbulk.no-ip.org/simplesaml/saml2/idp/metadata.php', 'http://idp.example.com/')
        request_data['get_data']['SAMLRequest'] = OneLogin_Saml2_Utils.deflate_and_base64_encode(request_2)
        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings)
        auth.process_slo()
        self.assertIn('invalid_logout_request_signature', auth.get_errors())

        settings.set_strict(False)
        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings)
        auth.process_slo()
        self.assertIn('invalid_logout_request_signature', auth.get_errors())

        request_data['get_data']['SigAlg'] = 'http://www.w3.org/2000/09/xmldsig#dsa-sha1'
        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings)
        auth.process_slo()
        self.assertIn('invalid_logout_request_signature', auth.get_errors())

        settings_info = self.loadSettingsJSON()
        settings_info['strict'] = True
        settings_info['security']['wantMessagesSigned'] = True
        settings = OneLogin_Saml2_Settings(settings_info)
        request_data['get_data']['SigAlg'] = old_signature_algorithm
        old_signature = request_data['get_data']['Signature']
        del request_data['get_data']['Signature']
        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings)
        auth.process_slo()
        self.assertIn('Signature validation failed. Logout Request rejected', auth.get_errors())

        request_data['get_data']['Signature'] = old_signature
        settings_info['idp']['certFingerprint'] = 'afe71c28ef740bc87425be13a2263d37971da1f9'
        del settings_info['idp']['x509cert']
        settings_2 = OneLogin_Saml2_Settings(settings_info)
        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings_2)
        auth.process_slo()
        self.assertIn('Signature validation failed. Logout Request rejected', auth.get_errors())

    def testGetLastRequestID(self):
        settings_info = self.loadSettingsJSON()
        request_data = self.get_request()
        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings_info)

        auth.login()
        id1 = auth.get_last_request_id()
        self.assertNotEqual(id1, None)

        auth.logout()
        id2 = auth.get_last_request_id()
        self.assertNotEqual(id2, None)

        self.assertNotEqual(id1, id2)

    def testGetLastSAMLResponse(self):
        settings = self.loadSettingsJSON()
        message = self.file_contents(join(self.data_path, 'responses', 'signed_message_response.xml.base64'))
        message_wrapper = {'post_data': {'SAMLResponse': message}}
        auth = OneLogin_Saml2_Auth(message_wrapper, old_settings=settings)
        auth.process_response()
        expected_message = self.file_contents(join(self.data_path, 'responses', 'pretty_signed_message_response.xml'))
        self.assertEqual(auth.get_last_response_xml(True), expected_message)

        # with encrypted assertion
        message = self.file_contents(join(self.data_path, 'responses', 'valid_encrypted_assertion.xml.base64'))
        message_wrapper = {'post_data': {'SAMLResponse': message}}
        auth = OneLogin_Saml2_Auth(message_wrapper, old_settings=settings)
        auth.process_response()
        decrypted_response = self.file_contents(join(self.data_path, 'responses', 'decrypted_valid_encrypted_assertion.xml'))
        self.assertEqual(auth.get_last_response_xml(False), decrypted_response)
        pretty_decrypted_response = self.file_contents(join(self.data_path, 'responses', 'pretty_decrypted_valid_encrypted_assertion.xml'))
        self.assertEqual(auth.get_last_response_xml(True), pretty_decrypted_response)

    def testGetLastAuthnRequest(self):
        settings = self.loadSettingsJSON()
        auth = OneLogin_Saml2_Auth({'http_host': 'localhost', 'script_name': 'thing'}, old_settings=settings)
        auth.login()
        expectedFragment = (
            '  Destination="http://idp.example.com/SSOService.php"\n'
            '  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"\n'
            '  AssertionConsumerServiceURL="http://stuff.com/endpoints/endpoints/acs.php">\n'
            '    <saml:Issuer>http://stuff.com/endpoints/metadata.php</saml:Issuer>\n'
            '    <samlp:NameIDPolicy\n'
            '        Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"\n'
            '        AllowCreate="true" />\n'
            '    <samlp:RequestedAuthnContext Comparison="exact">\n'
            '        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>\n'
            '    </samlp:RequestedAuthnContext>\n'
        )
        self.assertIn(expectedFragment, auth.get_last_request_xml())

    def testGetLastAuthnContexts(self):
        settings = self.loadSettingsJSON()
        request_data = self.get_request()
        message = self.file_contents(
            join(self.data_path, 'responses', 'valid_response.xml.base64'))
        del request_data['get_data']
        request_data['post_data'] = {
            'SAMLResponse': message
        }
        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings)

        auth.process_response()
        self.assertEqual(auth.get_last_authn_contexts(), ['urn:oasis:names:tc:SAML:2.0:ac:classes:Password'])

    def testGetLastLogoutRequest(self):
        settings = self.loadSettingsJSON()
        auth = OneLogin_Saml2_Auth({'http_host': 'localhost', 'script_name': 'thing'}, old_settings=settings)
        auth.logout()
        expectedFragment = (
            '  Destination="http://idp.example.com/SingleLogoutService.php">\n'
            '    <saml:Issuer>http://stuff.com/endpoints/metadata.php</saml:Issuer>\n'
            '    <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://idp.example.com/</saml:NameID>\n'
            '    \n</samlp:LogoutRequest>'
        )
        self.assertIn(expectedFragment, auth.get_last_request_xml())

        request = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request.xml'))
        message = OneLogin_Saml2_Utils.deflate_and_base64_encode(request)
        message_wrapper = {'get_data': {'SAMLRequest': message}}
        auth = OneLogin_Saml2_Auth(message_wrapper, old_settings=settings)
        auth.process_slo()
        self.assertEqual(request, auth.get_last_request_xml())

    def testGetLastLogoutResponse(self):
        settings = self.loadSettingsJSON()
        request = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request.xml'))
        message = OneLogin_Saml2_Utils.deflate_and_base64_encode(request)
        message_wrapper = {'get_data': {'SAMLRequest': message}}
        auth = OneLogin_Saml2_Auth(message_wrapper, old_settings=settings)
        auth.process_slo()
        expectedFragment = (
            '  Destination="http://idp.example.com/SingleLogoutService.php"\n'
            '  InResponseTo="ONELOGIN_21584ccdfaca36a145ae990442dcd96bfe60151e">\n'
            '    <saml:Issuer>http://stuff.com/endpoints/metadata.php</saml:Issuer>\n'
            '    <samlp:Status>\n'
            '        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />\n'
            '    </samlp:Status>\n'
            '</samlp:LogoutResponse>'
        )
        self.assertIn(expectedFragment, auth.get_last_response_xml())

        response = self.file_contents(join(self.data_path, 'logout_responses', 'logout_response.xml'))
        message = OneLogin_Saml2_Utils.deflate_and_base64_encode(response)
        message_wrapper = {'get_data': {'SAMLResponse': message}}
        auth = OneLogin_Saml2_Auth(message_wrapper, old_settings=settings)
        auth.process_slo()
        self.assertEqual(response, auth.get_last_response_xml())

    def testGetInfoFromLastResponseReceived(self):
        """
        Tests the get_last_message_id, get_last_assertion_id and get_last_assertion_not_on_or_after
        of the OneLogin_Saml2_Auth class
        """
        settings = self.loadSettingsJSON()
        request_data = self.get_request()
        message = self.file_contents(join(self.data_path, 'responses', 'valid_response.xml.base64'))
        del request_data['get_data']
        request_data['post_data'] = {
            'SAMLResponse': message
        }
        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings)

        auth.process_response()
        self.assertEqual(auth.get_last_message_id(), 'pfx42be40bf-39c3-77f0-c6ae-8bf2e23a1a2e')
        self.assertEqual(auth.get_last_assertion_id(), 'pfx57dfda60-b211-4cda-0f63-6d5deb69e5bb')
        self.assertIsNone(auth.get_last_assertion_not_on_or_after())

        # NotOnOrAfter is only calculated with strict = true
        # If invalid, response id and assertion id are not obtained

        settings['strict'] = True
        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings)
        auth.process_response()
        self.assertNotEqual(len(auth.get_errors()), 0)
        self.assertIsNone(auth.get_last_message_id())
        self.assertIsNone(auth.get_last_assertion_id())
        self.assertIsNone(auth.get_last_assertion_not_on_or_after())

        request_data['https'] = 'on'
        request_data['http_host'] = 'pitbulk.no-ip.org'
        request_data['script_name'] = '/newonelogin/demo1/index.php?acs'
        auth = OneLogin_Saml2_Auth(request_data, old_settings=settings)
        auth.process_response()
        self.assertEqual(len(auth.get_errors()), 0)
        self.assertEqual(auth.get_last_message_id(), 'pfx42be40bf-39c3-77f0-c6ae-8bf2e23a1a2e')
        self.assertEqual(auth.get_last_assertion_id(), 'pfx57dfda60-b211-4cda-0f63-6d5deb69e5bb')
        self.assertEqual(auth.get_last_assertion_not_on_or_after(), 2671081021)

    def testGetIdFromLogoutRequest(self):
        """
        Tests the get_last_message_id of the OneLogin_Saml2_Auth class
        Case Valid Logout request
        """
        settings = self.loadSettingsJSON()
        request = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request.xml'))
        message = OneLogin_Saml2_Utils.deflate_and_base64_encode(request)
        message_wrapper = {'get_data': {'SAMLRequest': message}}
        auth = OneLogin_Saml2_Auth(message_wrapper, old_settings=settings)
        auth.process_slo()
        self.assertIn(auth.get_last_message_id(), 'ONELOGIN_21584ccdfaca36a145ae990442dcd96bfe60151e')

    def testGetIdFromLogoutResponse(self):
        """
        Tests the get_last_message_id of the OneLogin_Saml2_Auth class
        Case Valid Logout response
        """
        settings = self.loadSettingsJSON()
        response = self.file_contents(join(self.data_path, 'logout_responses', 'logout_response.xml'))
        message = OneLogin_Saml2_Utils.deflate_and_base64_encode(response)
        message_wrapper = {'get_data': {'SAMLResponse': message}}
        auth = OneLogin_Saml2_Auth(message_wrapper, old_settings=settings)
        auth.process_slo()
        self.assertIn(auth.get_last_message_id(), '_f9ee61bd9dbf63606faa9ae3b10548d5b3656fb859')
