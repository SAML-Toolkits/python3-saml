# -*- coding: utf-8 -*-

# Copyright (c) 2014, OneLogin, Inc.
# All rights reserved.

from base64 import b64decode, b64encode
import json
from os.path import dirname, join, exists
import unittest
from urlparse import urlparse, parse_qs

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from onelogin.saml2.logout_request import OneLogin_Saml2_Logout_Request


class OneLogin_Saml2_Auth_Test(unittest.TestCase):
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

        try:
            auth.process_response()
            self.assertFalse(True)
        except Exception as e:
            self.assertIn('SAML Response not found', e.message)

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
        plain_message = b64decode(message)
        current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)
        plain_message = plain_message.replace('http://stuff.com/endpoints/endpoints/acs.php', current_url)
        del request_data['get_data']
        request_data['post_data'] = {
            'SAMLResponse': b64encode(plain_message)
        }
        auth = OneLogin_Saml2_Auth(request_data, old_settings=self.loadSettingsJSON())
        request_id = 'invalid'
        auth.process_response(request_id)
        self.assertEqual(len(auth.get_errors()), 0)

        auth.set_strict(True)
        auth.process_response(request_id)
        self.assertEqual(auth.get_errors(), ['invalid_response'])

        valid_request_id = '_57bcbf70-7b1f-012e-c821-782bcb13bb38'
        auth.process_response(valid_request_id)
        self.assertEqual(len(auth.get_errors()), 0)

    def testProcessResponseValid(self):
        """
        Tests the process_response method of the OneLogin_Saml2_Auth class
        Case Valid Response, After processing the response the user
        is authenticated, attributes are returned, also has a nameID and
        the error array is empty
        """
        request_data = self.get_request()
        message = self.file_contents(join(self.data_path, 'responses', 'unsigned_response.xml.base64'))
        plain_message = b64decode(message)
        current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)
        plain_message = plain_message.replace('http://stuff.com/endpoints/endpoints/acs.php', current_url)
        del request_data['get_data']
        request_data['post_data'] = {
            'SAMLResponse': b64encode(plain_message)
        }
        auth = OneLogin_Saml2_Auth(request_data, old_settings=self.loadSettingsJSON())

        auth.process_response()

        self.assertTrue(auth.is_authenticated())
        self.assertEqual(len(auth.get_errors()), 0)
        self.assertEqual('someone@example.com', auth.get_nameid())
        attributes = auth.get_attributes()
        self.assertNotEqual(len(attributes), 0)
        self.assertEqual(auth.get_attribute('mail'), attributes['mail'])

        auth.set_strict(True)
        auth.process_response()
        self.assertEqual(len(auth.get_errors()), 0)

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
        try:
            auth.process_slo(True)
        except Exception as e:
            self.assertIn('SAML LogoutRequest/LogoutResponse not found', e.message)
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
        plain_message = OneLogin_Saml2_Utils.decode_base64_and_inflate(message)
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
        plain_message = OneLogin_Saml2_Utils.decode_base64_and_inflate(message)
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
        plain_message = OneLogin_Saml2_Utils.decode_base64_and_inflate(message)
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
        plain_message = OneLogin_Saml2_Utils.decode_base64_and_inflate(message)
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
        self.assertNotIn('RelayState', parsed_query)

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
        self.assertNotIn('RelayState', parsed_query_2)

    def testProcessSLORequestNotOnOrAfterFailed(self):
        """
        Tests the process_slo method of the OneLogin_Saml2_Auth class
        Case Logout Request NotOnOrAfter failed
        """
        request_data = self.get_request()
        message = self.file_contents(join(self.data_path, 'logout_requests', 'invalids', 'not_after_failed.xml.base64'))
        # In order to avoid the destination problem
        plain_message = OneLogin_Saml2_Utils.decode_base64_and_inflate(message)
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
        plain_message = OneLogin_Saml2_Utils.decode_base64_and_inflate(message)
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
        self.assertNotIn('RelayState', parsed_query)

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
        self.assertNotIn('RelayState', parsed_query_2)

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
        plain_message = OneLogin_Saml2_Utils.decode_base64_and_inflate(message)
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
        plain_message = OneLogin_Saml2_Utils.decode_base64_and_inflate(message)
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

        try:
            # The Header of the redirect produces an Exception
            auth.logout('http://example.com/returnto')
            self.assertFalse(True)
        except Exception as e:
            self.assertIn('The IdP does not support Single Log Out', e.message)

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

        target_url = auth.logout()
        parsed_query = parse_qs(urlparse(target_url)[4])
        self.assertIn('SAMLRequest', parsed_query)
        logout_request = OneLogin_Saml2_Utils.decode_base64_and_inflate(parsed_query['SAMLRequest'][0])

        name_id_from_request = OneLogin_Saml2_Logout_Request.get_nameid(logout_request)
        self.assertEqual(name_id_from_response, name_id_from_request)

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

        try:
            auth.set_strict('42')
            self.assertFalse(True)
        except Exception as e:
            self.assertTrue(isinstance(e, AssertionError))

    def testBuildRequestSignature(self):
        """
        Tests the build_request_signature method of the OneLogin_Saml2_Auth
        """
        settings = self.loadSettingsJSON()
        message = self.file_contents(join(self.data_path, 'logout_requests', 'logout_request_deflated.xml.base64'))
        relay_state = 'http://relaystate.com'
        auth = OneLogin_Saml2_Auth(self.get_request(), old_settings=settings)

        signature = auth.build_request_signature(message, relay_state)
        valid_signature = 'E17GU1STzanOXxBTKjweB1DovP8aMJdj5BEy0fnGoEslKdP6hpPc3enjT/bu7I8D8QzLoir8SxZVWdUDXgIxJIEgfK5snr+jJwfc5U2HujsOa/Xb3c4swoyPcyQhcxLRDhDjPq5cQxJfYoPeElvCuI6HAD1mtdd5PS/xDvbIxuw='
        self.assertEqual(signature, valid_signature)

        settings['sp']['privatekey'] = ''
        settings['custom_base_path'] = u'invalid/path/'
        auth2 = OneLogin_Saml2_Auth(self.get_request(), old_settings=settings)
        try:
            auth2.build_request_signature(message, relay_state)
        except Exception as e:
            self.assertIn("Trying to sign the SAMLRequest but can't load the SP private key", e.message)

    def testBuildResponseSignature(self):
        """
        Tests the build_response_signature method of the OneLogin_Saml2_Auth
        """
        settings = self.loadSettingsJSON()
        message = self.file_contents(join(self.data_path, 'logout_responses', 'logout_response_deflated.xml.base64'))
        relay_state = 'http://relaystate.com'
        auth = OneLogin_Saml2_Auth(self.get_request(), old_settings=settings)

        signature = auth.build_response_signature(message, relay_state)
        valid_signature = 'IcyWLRX6Dz3wHBfpcUaNLVDMGM3uo6z2Z11Gjq0/APPJaHboKGljffsgMVAGBml497yckq+eYKmmz+jpURV9yTj2sF9qfD6CwX2dEzSzMdRzB40X7pWyHgEJGIhs6BhaOt5oXEk4T+h3AczERqpVYFpL00yo7FNtyQkhZFpHFhM='
        self.assertEqual(signature, valid_signature)

        settings['sp']['privatekey'] = ''
        settings['custom_base_path'] = u'invalid/path/'
        auth2 = OneLogin_Saml2_Auth(self.get_request(), old_settings=settings)
        try:
            auth2.build_response_signature(message, relay_state)
        except Exception as e:
            self.assertIn("Trying to sign the SAMLResponse but can't load the SP private key", e.message)
