# -*- coding: utf-8 -*-

# Copyright (c) 2010-2018 OneLogin, Inc.
# MIT License

from base64 import b64decode
from lxml import etree
from datetime import datetime
from datetime import timedelta
from freezegun import freeze_time
import json
from os.path import dirname, join, exists
import unittest
from xml.dom.minidom import parseString

from onelogin.saml2 import compat
from onelogin.saml2.response import OneLogin_Saml2_Response
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils


class OneLogin_Saml2_Response_Test(unittest.TestCase):
    data_path = join(dirname(dirname(dirname(dirname(__file__)))), 'data')
    settings_path = join(dirname(dirname(dirname(dirname(__file__)))), 'settings')

    # assertRaisesRegexp deprecated on python3
    def assertRaisesRegex(self, exception, regexp, msg=None):
        if hasattr(unittest.TestCase, 'assertRaisesRegex'):
            return super(OneLogin_Saml2_Response_Test, self).assertRaisesRegex(exception, regexp, msg=msg)
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

    def get_request_data(self):
        return {
            'http_host': 'example.com',
            'script_name': 'index.html'
        }

    def testConstruct(self):
        """
        Tests the OneLogin_Saml2_Response Constructor.
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        xml = self.file_contents(join(self.data_path, 'responses', 'response1.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)

        self.assertIsInstance(response, OneLogin_Saml2_Response)

        xml_enc = self.file_contents(join(self.data_path, 'responses', 'valid_encrypted_assertion.xml.base64'))
        response_enc = OneLogin_Saml2_Response(settings, xml_enc)

        self.assertIsInstance(response_enc, OneLogin_Saml2_Response)

    def testGetXMLDocument(self):
        """
        Tests that we can retrieve the raw text of an encrypted XML response
        without going through intermediate steps
        """
        json_settings = self.loadSettingsJSON()
        settings = OneLogin_Saml2_Settings(json_settings)

        xml = self.file_contents(join(self.data_path, 'responses', 'signed_message_response.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)
        prety_xml = self.file_contents(join(self.data_path, 'responses', 'pretty_signed_message_response.xml'))
        self.assertEqual(etree.tostring(response.get_xml_document(), encoding='unicode', pretty_print=True), prety_xml)

        xml_2 = self.file_contents(join(self.data_path, 'responses', 'valid_encrypted_assertion.xml.base64'))
        response_2 = OneLogin_Saml2_Response(settings, xml_2)
        decrypted = self.file_contents(join(self.data_path, 'responses', 'decrypted_valid_encrypted_assertion.xml'))
        self.assertEqual(etree.tostring(response_2.get_xml_document(), encoding='unicode'), decrypted)

    def testReturnNameId(self):
        """
        Tests the get_nameid method of the OneLogin_Saml2_Response
        """
        json_settings = self.loadSettingsJSON()
        json_settings['strict'] = False
        settings = OneLogin_Saml2_Settings(json_settings)
        xml = self.file_contents(join(self.data_path, 'responses', 'response1.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)
        self.assertEqual('support@onelogin.com', response.get_nameid())

        xml_2 = self.file_contents(join(self.data_path, 'responses', 'response_encrypted_nameid.xml.base64'))
        response_2 = OneLogin_Saml2_Response(settings, xml_2)
        self.assertEqual('2de11defd199f8d5bb63f9b7deb265ba5c675c10', response_2.get_nameid())

        xml_3 = self.file_contents(join(self.data_path, 'responses', 'valid_encrypted_assertion.xml.base64'))
        response_3 = OneLogin_Saml2_Response(settings, xml_3)
        self.assertEqual('_68392312d490db6d355555cfbbd8ec95d746516f60', response_3.get_nameid())

        json_settings['strict'] = True
        json_settings['security']['wantNameId'] = True
        settings = OneLogin_Saml2_Settings(json_settings)

        xml_4 = self.file_contents(join(self.data_path, 'responses', 'invalids', 'no_nameid.xml.base64'))
        response_4 = OneLogin_Saml2_Response(settings, xml_4)
        with self.assertRaisesRegex(Exception, 'NameID not found in the assertion of the Response'):
            response_4.get_nameid()

        json_settings['security']['wantNameId'] = False
        settings = OneLogin_Saml2_Settings(json_settings)
        response_5 = OneLogin_Saml2_Response(settings, xml_4)
        self.assertIsNone(response_5.get_nameid())

        json_settings['strict'] = False
        json_settings['security']['wantNameId'] = False
        settings = OneLogin_Saml2_Settings(json_settings)
        response_6 = OneLogin_Saml2_Response(settings, xml_4)
        self.assertIsNone(response_6.get_nameid())

        json_settings['security']['wantNameId'] = True
        settings = OneLogin_Saml2_Settings(json_settings)
        response_7 = OneLogin_Saml2_Response(settings, xml_4)
        self.assertIsNone(response_7.get_nameid())

        del json_settings['security']['wantNameId']
        settings = OneLogin_Saml2_Settings(json_settings)
        response_8 = OneLogin_Saml2_Response(settings, xml_4)
        self.assertIsNone(response_8.get_nameid())

        json_settings['strict'] = True
        settings = OneLogin_Saml2_Settings(json_settings)
        response_9 = OneLogin_Saml2_Response(settings, xml_4)
        with self.assertRaisesRegex(Exception, 'NameID not found in the assertion of the Response'):
            response_9.get_nameid()

        json_settings['strict'] = False
        settings = OneLogin_Saml2_Settings(json_settings)
        xml_5 = self.file_contents(join(self.data_path, 'responses', 'invalids', 'wrong_spnamequalifier.xml.base64'))
        response_10 = OneLogin_Saml2_Response(settings, xml_5)
        self.assertEqual('test@example.com', response_10.get_nameid())

        json_settings['strict'] = True
        settings = OneLogin_Saml2_Settings(json_settings)

        xml_5 = self.file_contents(join(self.data_path, 'responses', 'invalids', 'wrong_spnamequalifier.xml.base64'))
        response_11 = OneLogin_Saml2_Response(settings, xml_5)
        with self.assertRaisesRegex(Exception, 'The SPNameQualifier value mistmatch the SP entityID value.'):
            response_11.get_nameid()

        json_settings['strict'] = True
        json_settings['security']['wantNameId'] = True
        settings = OneLogin_Saml2_Settings(json_settings)

        xml_6 = self.file_contents(join(self.data_path, 'responses', 'invalids', 'empty_nameid.xml.base64'))
        response_12 = OneLogin_Saml2_Response(settings, xml_6)
        with self.assertRaisesRegex(Exception, 'An empty NameID value found'):
            response_12.get_nameid()

        json_settings['security']['wantNameId'] = False
        settings = OneLogin_Saml2_Settings(json_settings)
        response_13 = OneLogin_Saml2_Response(settings, xml_6)
        self.assertIsNone(response_13.get_nameid())

        json_settings['strict'] = False
        json_settings['security']['wantNameId'] = False
        settings = OneLogin_Saml2_Settings(json_settings)
        response_14 = OneLogin_Saml2_Response(settings, xml_6)
        self.assertIsNone(response_14.get_nameid())

        json_settings['security']['wantNameId'] = True
        settings = OneLogin_Saml2_Settings(json_settings)
        response_15 = OneLogin_Saml2_Response(settings, xml_6)
        self.assertIsNone(response_15.get_nameid())

        del json_settings['security']['wantNameId']
        settings = OneLogin_Saml2_Settings(json_settings)
        response_16 = OneLogin_Saml2_Response(settings, xml_6)
        self.assertIsNone(response_16.get_nameid())

        json_settings['strict'] = True
        settings = OneLogin_Saml2_Settings(json_settings)
        response_17 = OneLogin_Saml2_Response(settings, xml_6)
        with self.assertRaisesRegex(Exception, 'An empty NameID value found'):
            response_17.get_nameid()

    def testReturnNameIdFormat(self):
        """
        Tests the get_nameid_format method of the OneLogin_Saml2_Response
        """
        json_settings = self.loadSettingsJSON()
        json_settings['strict'] = False
        settings = OneLogin_Saml2_Settings(json_settings)
        xml = self.file_contents(join(self.data_path, 'responses', 'response1.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)
        self.assertEqual('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress', response.get_nameid_format())

        xml_2 = self.file_contents(join(self.data_path, 'responses', 'response_encrypted_nameid.xml.base64'))
        response_2 = OneLogin_Saml2_Response(settings, xml_2)
        self.assertEqual('urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified', response_2.get_nameid_format())

        xml_3 = self.file_contents(join(self.data_path, 'responses', 'valid_encrypted_assertion.xml.base64'))
        response_3 = OneLogin_Saml2_Response(settings, xml_3)
        self.assertEqual('urn:oasis:names:tc:SAML:2.0:nameid-format:transient', response_3.get_nameid_format())

        json_settings['strict'] = True
        json_settings['security']['wantNameId'] = True
        settings = OneLogin_Saml2_Settings(json_settings)

        xml_4 = self.file_contents(join(self.data_path, 'responses', 'invalids', 'no_nameid.xml.base64'))
        response_4 = OneLogin_Saml2_Response(settings, xml_4)
        with self.assertRaisesRegex(Exception, 'NameID not found in the assertion of the Response'):
            response_4.get_nameid_format()

        json_settings['security']['wantNameId'] = False
        settings = OneLogin_Saml2_Settings(json_settings)
        response_5 = OneLogin_Saml2_Response(settings, xml_4)
        self.assertIsNone(response_5.get_nameid_format())

        json_settings['strict'] = False
        json_settings['security']['wantNameId'] = False
        settings = OneLogin_Saml2_Settings(json_settings)
        response_6 = OneLogin_Saml2_Response(settings, xml_4)
        self.assertIsNone(response_6.get_nameid_format())

        json_settings['security']['wantNameId'] = True
        settings = OneLogin_Saml2_Settings(json_settings)
        response_7 = OneLogin_Saml2_Response(settings, xml_4)
        self.assertIsNone(response_7.get_nameid_format())

        del json_settings['security']['wantNameId']
        settings = OneLogin_Saml2_Settings(json_settings)
        response_8 = OneLogin_Saml2_Response(settings, xml_4)
        self.assertIsNone(response_8.get_nameid_format())

        json_settings['strict'] = True
        settings = OneLogin_Saml2_Settings(json_settings)
        response_9 = OneLogin_Saml2_Response(settings, xml_4)
        with self.assertRaisesRegex(Exception, 'NameID not found in the assertion of the Response'):
            response_9.get_nameid_format()

        json_settings['strict'] = False
        settings = OneLogin_Saml2_Settings(json_settings)
        xml_5 = self.file_contents(join(self.data_path, 'responses', 'invalids', 'wrong_spnamequalifier.xml.base64'))
        response_10 = OneLogin_Saml2_Response(settings, xml_5)
        self.assertEqual('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress', response_10.get_nameid_format())

        json_settings['strict'] = True
        settings = OneLogin_Saml2_Settings(json_settings)

        xml_5 = self.file_contents(join(self.data_path, 'responses', 'invalids', 'wrong_spnamequalifier.xml.base64'))
        response_11 = OneLogin_Saml2_Response(settings, xml_5)
        with self.assertRaisesRegex(Exception, 'The SPNameQualifier value mistmatch the SP entityID value.'):
            response_11.get_nameid_format()

        json_settings['strict'] = True
        json_settings['security']['wantNameId'] = True
        settings = OneLogin_Saml2_Settings(json_settings)

        xml_6 = self.file_contents(join(self.data_path, 'responses', 'invalids', 'empty_nameid.xml.base64'))
        response_12 = OneLogin_Saml2_Response(settings, xml_6)
        with self.assertRaisesRegex(Exception, 'An empty NameID value found'):
            response_12.get_nameid_format()

        json_settings['security']['wantNameId'] = False
        settings = OneLogin_Saml2_Settings(json_settings)
        response_13 = OneLogin_Saml2_Response(settings, xml_6)
        self.assertEqual('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress', response_13.get_nameid_format())

        json_settings['strict'] = False
        json_settings['security']['wantNameId'] = False
        settings = OneLogin_Saml2_Settings(json_settings)
        response_14 = OneLogin_Saml2_Response(settings, xml_6)
        self.assertEqual('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress', response_14.get_nameid_format())

        json_settings['security']['wantNameId'] = True
        settings = OneLogin_Saml2_Settings(json_settings)
        response_15 = OneLogin_Saml2_Response(settings, xml_6)
        self.assertEqual('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress', response_15.get_nameid_format())

        del json_settings['security']['wantNameId']
        settings = OneLogin_Saml2_Settings(json_settings)
        response_16 = OneLogin_Saml2_Response(settings, xml_6)
        self.assertEqual('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress', response_16.get_nameid_format())

        json_settings['strict'] = True
        settings = OneLogin_Saml2_Settings(json_settings)
        response_17 = OneLogin_Saml2_Response(settings, xml_6)
        with self.assertRaisesRegex(Exception, 'An empty NameID value found'):
            response_17.get_nameid_format()

    def testGetNameIdData(self):
        """
        Tests the get_nameid_data method of the OneLogin_Saml2_Response
        """
        json_settings = self.loadSettingsJSON()
        json_settings['strict'] = False
        settings = OneLogin_Saml2_Settings(json_settings)
        xml = self.file_contents(join(self.data_path, 'responses', 'response1.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)
        expected_nameid_data = {
            'Value': 'support@onelogin.com',
            'Format': 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
        }
        nameid_data = response.get_nameid_data()
        self.assertEqual(expected_nameid_data, nameid_data)

        xml_2 = self.file_contents(join(self.data_path, 'responses', 'response_encrypted_nameid.xml.base64'))
        response_2 = OneLogin_Saml2_Response(settings, xml_2)
        expected_nameid_data_2 = {
            'Value': '2de11defd199f8d5bb63f9b7deb265ba5c675c10',
            'Format': 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
            'SPNameQualifier': 'http://stuff.com/endpoints/metadata.php'
        }
        nameid_data_2 = response_2.get_nameid_data()
        self.assertEqual(expected_nameid_data_2, nameid_data_2)

        xml_3 = self.file_contents(join(self.data_path, 'responses', 'valid_encrypted_assertion.xml.base64'))
        response_3 = OneLogin_Saml2_Response(settings, xml_3)
        expected_nameid_data_3 = {
            'Value': '_68392312d490db6d355555cfbbd8ec95d746516f60',
            'Format': 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
            'SPNameQualifier': 'http://stuff.com/endpoints/metadata.php'
        }
        nameid_data_3 = response_3.get_nameid_data()
        self.assertEqual(expected_nameid_data_3, nameid_data_3)

        json_settings['strict'] = True
        json_settings['security']['wantNameId'] = True
        settings = OneLogin_Saml2_Settings(json_settings)

        xml_4 = self.file_contents(join(self.data_path, 'responses', 'invalids', 'no_nameid.xml.base64'))
        response_4 = OneLogin_Saml2_Response(settings, xml_4)
        with self.assertRaisesRegex(Exception, 'NameID not found in the assertion of the Response'):
            response_4.get_nameid_data()

        json_settings['security']['wantNameId'] = False
        settings = OneLogin_Saml2_Settings(json_settings)
        response_5 = OneLogin_Saml2_Response(settings, xml_4)
        nameid_data_5 = response_5.get_nameid_data()
        self.assertEqual({}, nameid_data_5)

        json_settings['strict'] = False
        json_settings['security']['wantNameId'] = False
        settings = OneLogin_Saml2_Settings(json_settings)
        response_6 = OneLogin_Saml2_Response(settings, xml_4)
        nameid_data_6 = response_6.get_nameid_data()
        self.assertEqual({}, nameid_data_6)

        json_settings['security']['wantNameId'] = True
        settings = OneLogin_Saml2_Settings(json_settings)
        response_7 = OneLogin_Saml2_Response(settings, xml_4)
        nameid_data_7 = response_7.get_nameid_data()
        self.assertEqual({}, nameid_data_7)

        del json_settings['security']['wantNameId']
        settings = OneLogin_Saml2_Settings(json_settings)
        response_8 = OneLogin_Saml2_Response(settings, xml_4)
        nameid_data_8 = response_8.get_nameid_data()
        self.assertEqual({}, nameid_data_8)

        json_settings['strict'] = True
        settings = OneLogin_Saml2_Settings(json_settings)
        response_9 = OneLogin_Saml2_Response(settings, xml_4)
        with self.assertRaisesRegex(Exception, 'NameID not found in the assertion of the Response'):
            response_9.get_nameid_data()

        expected_nameid_data_4 = {
            'Format': 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
            'SPNameQualifier': 'wrong-sp-entityid',
            'Value': 'test@example.com'
        }
        json_settings['strict'] = False
        settings = OneLogin_Saml2_Settings(json_settings)
        xml_5 = self.file_contents(join(self.data_path, 'responses', 'invalids', 'wrong_spnamequalifier.xml.base64'))
        response_10 = OneLogin_Saml2_Response(settings, xml_5)
        nameid_data_10 = response_10.get_nameid_data()
        self.assertEqual(expected_nameid_data_4, nameid_data_10)

        json_settings['strict'] = True
        settings = OneLogin_Saml2_Settings(json_settings)

        xml_5 = self.file_contents(join(self.data_path, 'responses', 'invalids', 'wrong_spnamequalifier.xml.base64'))
        response_11 = OneLogin_Saml2_Response(settings, xml_5)
        with self.assertRaisesRegex(Exception, 'The SPNameQualifier value mistmatch the SP entityID value.'):
            response_11.get_nameid_data()

        expected_nameid_data_5 = {
            'Value': None,
            'Format': 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        }

        json_settings['strict'] = True
        json_settings['security']['wantNameId'] = True
        settings = OneLogin_Saml2_Settings(json_settings)

        xml_6 = self.file_contents(join(self.data_path, 'responses', 'invalids', 'empty_nameid.xml.base64'))
        response_12 = OneLogin_Saml2_Response(settings, xml_6)
        with self.assertRaisesRegex(Exception, 'An empty NameID value found'):
            response_12.get_nameid_data()

        json_settings['security']['wantNameId'] = False
        settings = OneLogin_Saml2_Settings(json_settings)
        response_13 = OneLogin_Saml2_Response(settings, xml_6)
        nameid_data_13 = response_13.get_nameid_data()
        nameid_data_13 = self.assertEqual(expected_nameid_data_5, nameid_data_13)

        json_settings['strict'] = False
        json_settings['security']['wantNameId'] = False
        settings = OneLogin_Saml2_Settings(json_settings)
        response_14 = OneLogin_Saml2_Response(settings, xml_6)
        nameid_data_14 = response_14.get_nameid_data()
        self.assertEqual(expected_nameid_data_5, nameid_data_14)

        json_settings['security']['wantNameId'] = True
        settings = OneLogin_Saml2_Settings(json_settings)
        response_15 = OneLogin_Saml2_Response(settings, xml_6)
        nameid_data_15 = response_15.get_nameid_data()
        self.assertEqual(expected_nameid_data_5, nameid_data_15)

        del json_settings['security']['wantNameId']
        settings = OneLogin_Saml2_Settings(json_settings)
        response_16 = OneLogin_Saml2_Response(settings, xml_6)
        nameid_data_16 = response_16.get_nameid_data()
        self.assertEqual(expected_nameid_data_5, nameid_data_16)

        json_settings['strict'] = True
        settings = OneLogin_Saml2_Settings(json_settings)
        response_17 = OneLogin_Saml2_Response(settings, xml_6)
        with self.assertRaisesRegex(Exception, 'An empty NameID value found'):
            response_17.get_nameid_data()

    def testCheckStatus(self):
        """
        Tests the check_status method of the OneLogin_Saml2_Response
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        xml = self.file_contents(join(self.data_path, 'responses', 'response1.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)
        response.check_status()

        xml_enc = self.file_contents(join(self.data_path, 'responses', 'valid_encrypted_assertion.xml.base64'))
        response_enc = OneLogin_Saml2_Response(settings, xml_enc)
        response_enc.check_status()

        xml_2 = self.file_contents(join(self.data_path, 'responses', 'invalids', 'status_code_responder.xml.base64'))
        response_2 = OneLogin_Saml2_Response(settings, xml_2)
        with self.assertRaisesRegex(Exception, 'The status code of the Response was not Success, was Responder'):
            response_2.check_status()

        xml_3 = self.file_contents(join(self.data_path, 'responses', 'invalids', 'status_code_responer_and_msg.xml.base64'))
        response_3 = OneLogin_Saml2_Response(settings, xml_3)
        with self.assertRaisesRegex(Exception, 'The status code of the Response was not Success, was Responder -> something_is_wrong'):
            response_3.check_status()

    def testCheckOneCondition(self):
        """
        Tests the check_one_condition method of SamlResponse
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        xml = self.file_contents(join(self.data_path, 'responses', 'invalids', 'no_conditions.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)
        self.assertFalse(response.check_one_condition())

        self.assertTrue(response.is_valid(self.get_request_data()))
        settings.set_strict(True)
        response = OneLogin_Saml2_Response(settings, xml)
        self.assertFalse(response.is_valid(self.get_request_data()))
        self.assertEqual('The Assertion must include a Conditions element', response.get_error())

        xml_2 = self.file_contents(join(self.data_path, 'responses', 'valid_response.xml.base64'))
        response_2 = OneLogin_Saml2_Response(settings, xml_2)
        self.assertTrue(response_2.check_one_condition())

    def testCheckOneAuthnStatement(self):
        """
        Tests the check_one_authnstatement method of SamlResponse
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        xml = self.file_contents(join(self.data_path, 'responses', 'invalids', 'no_authnstatement.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)
        self.assertFalse(response.check_one_authnstatement())

        self.assertTrue(response.is_valid(self.get_request_data()))
        settings.set_strict(True)
        response = OneLogin_Saml2_Response(settings, xml)
        self.assertFalse(response.is_valid(self.get_request_data()))
        self.assertEqual('The Assertion must include an AuthnStatement element', response.get_error())

        xml_2 = self.file_contents(join(self.data_path, 'responses', 'valid_response.xml.base64'))
        response_2 = OneLogin_Saml2_Response(settings, xml_2)
        self.assertTrue(response_2.check_one_authnstatement())

    def testGetAudiences(self):
        """
        Tests the get_audiences method of the OneLogin_Saml2_Response
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        xml = self.file_contents(join(self.data_path, 'responses', 'no_audience.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)
        self.assertEqual([], response.get_audiences())

        xml_2 = self.file_contents(join(self.data_path, 'responses', 'response1.xml.base64'))
        response_2 = OneLogin_Saml2_Response(settings, xml_2)
        self.assertEqual(['{audience}'], response_2.get_audiences())

        xml_3 = self.file_contents(join(self.data_path, 'responses', 'valid_encrypted_assertion.xml.base64'))
        response_3 = OneLogin_Saml2_Response(settings, xml_3)
        self.assertEqual(['http://stuff.com/endpoints/metadata.php'], response_3.get_audiences())

    def testQueryAssertions(self):
        """
        Tests the __query_assertion and __query methods of the
        OneLogin_Saml2_Response using the get_issuers call
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        xml = self.file_contents(join(self.data_path, 'responses', 'adfs_response.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)
        self.assertEqual(['http://login.example.com/issuer'], response.get_issuers())

        xml_2 = self.file_contents(join(self.data_path, 'responses', 'valid_encrypted_assertion.xml.base64'))
        response_2 = OneLogin_Saml2_Response(settings, xml_2)
        self.assertEqual(['http://idp.example.com/'], response_2.get_issuers())

        xml_3 = self.file_contents(join(self.data_path, 'responses', 'double_signed_encrypted_assertion.xml.base64'))
        response_3 = OneLogin_Saml2_Response(settings, xml_3)
        self.assertEqual(['http://idp.example.com/', 'https://pitbulk.no-ip.org/simplesaml/saml2/idp/metadata.php'], sorted(response_3.get_issuers()))

        xml_4 = self.file_contents(join(self.data_path, 'responses', 'double_signed_response.xml.base64'))
        response_4 = OneLogin_Saml2_Response(settings, xml_4)
        self.assertEqual(['https://pitbulk.no-ip.org/simplesaml/saml2/idp/metadata.php'], response_4.get_issuers())

        xml_5 = self.file_contents(join(self.data_path, 'responses', 'signed_message_encrypted_assertion.xml.base64'))
        response_5 = OneLogin_Saml2_Response(settings, xml_5)
        self.assertEqual(['http://idp.example.com/', 'https://pitbulk.no-ip.org/simplesaml/saml2/idp/metadata.php'], sorted(response_5.get_issuers()))

        xml_6 = self.file_contents(join(self.data_path, 'responses', 'signed_assertion_response.xml.base64'))
        response_6 = OneLogin_Saml2_Response(settings, xml_6)
        self.assertEqual(['https://pitbulk.no-ip.org/simplesaml/saml2/idp/metadata.php'], response_6.get_issuers())

        xml_7 = self.file_contents(join(self.data_path, 'responses', 'signed_encrypted_assertion.xml.base64'))
        response_7 = OneLogin_Saml2_Response(settings, xml_7)
        self.assertEqual(['http://idp.example.com/'], response_7.get_issuers())

    def testGetIssuers(self):
        """
        Tests the get_issuers method of the OneLogin_Saml2_Response
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        xml = self.file_contents(join(self.data_path, 'responses', 'adfs_response.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)
        self.assertEqual(['http://login.example.com/issuer'], response.get_issuers())

        xml_2 = self.file_contents(join(self.data_path, 'responses', 'valid_encrypted_assertion.xml.base64'))
        response_2 = OneLogin_Saml2_Response(settings, xml_2)
        self.assertEqual(['http://idp.example.com/'], response_2.get_issuers())

        xml_3 = self.file_contents(join(self.data_path, 'responses', 'double_signed_encrypted_assertion.xml.base64'))
        response_3 = OneLogin_Saml2_Response(settings, xml_3)
        self.assertEqual(['http://idp.example.com/', 'https://pitbulk.no-ip.org/simplesaml/saml2/idp/metadata.php'], sorted(response_3.get_issuers()))

        xml_4 = self.file_contents(join(self.data_path, 'responses', 'invalids', 'no_issuer_response.xml.base64'))
        response_4 = OneLogin_Saml2_Response(settings, xml_4)
        response_4.get_issuers()
        self.assertEqual(['https://pitbulk.no-ip.org/simplesaml/saml2/idp/metadata.php'], response_4.get_issuers())

        xml_5 = self.file_contents(join(self.data_path, 'responses', 'invalids', 'no_issuer_assertion.xml.base64'))
        response_5 = OneLogin_Saml2_Response(settings, xml_5)
        with self.assertRaisesRegex(Exception, 'Issuer of the Assertion not found or multiple.'):
            response_5.get_issuers()

    def testGetSessionIndex(self):
        """
        Tests the get_session_index method of the OneLogin_Saml2_Response
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        xml = self.file_contents(join(self.data_path, 'responses', 'response1.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)
        self.assertEqual('_531c32d283bdff7e04e487bcdbc4dd8d', response.get_session_index())

        xml_2 = self.file_contents(join(self.data_path, 'responses', 'valid_encrypted_assertion.xml.base64'))
        response_2 = OneLogin_Saml2_Response(settings, xml_2)
        self.assertEqual('_7164a9a9f97828bfdb8d0ebc004a05d2e7d873f70c', response_2.get_session_index())

    def testGetAttributes(self):
        """
        Tests the getAttributes method of the OneLogin_Saml2_Response
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        xml = self.file_contents(join(self.data_path, 'responses', 'response1.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)
        expected_attributes = {
            'uid': ['demo'],
            'another_value': ['value']
        }
        self.assertEqual(expected_attributes, response.get_attributes())

        # An assertion that has no attributes should return an empty
        # array when asked for the attributes
        xml_2 = self.file_contents(join(self.data_path, 'responses', 'response2.xml.base64'))
        response_2 = OneLogin_Saml2_Response(settings, xml_2)
        self.assertEqual({}, response_2.get_attributes())

        # Encrypted Attributes are not supported
        xml_3 = self.file_contents(join(self.data_path, 'responses', 'invalids', 'encrypted_attrs.xml.base64'))
        response_3 = OneLogin_Saml2_Response(settings, xml_3)
        self.assertEqual({}, response_3.get_attributes())

    def testGetNestedNameIDAttributes(self):
        """
        Tests the getAttributes method of the OneLogin_Saml2_Response with nested
        nameID data
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        xml = self.file_contents(join(self.data_path, 'responses', 'response_with_nested_nameid_values.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)
        expected_attributes = {
            'uid': ['demo'],
            'another_value': [{
                'NameID': {
                    'Format': 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
                    'NameQualifier': 'https://idpID',
                    'value': 'value'
                }
            }]
        }
        self.assertEqual(expected_attributes, response.get_attributes())

    def testOnlyRetrieveAssertionWithIDThatMatchesSignatureReference(self):
        """
        Tests the get_nameid method of the OneLogin_Saml2_Response
        The Assertion is unsigned so the method fails
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        xml = self.file_contents(join(self.data_path, 'responses', 'wrapped_response_2.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)
        with self.assertRaisesRegex(Exception, 'Invalid Signature Element {urn:oasis:names:tc:SAML:2.0:metadata}EntityDescriptor SAML Response rejected'):
            response.is_valid(self.get_request_data(), raise_exceptions=True)
        nameid = response.get_nameid()
        self.assertEqual('root@example.com', nameid)

    def testDoesNotAllowSignatureWrappingAttack(self):
        """
        Tests the get_nameid method of the OneLogin_Saml2_Response
        Test that the SignatureWrappingAttack is not allowed
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        xml = self.file_contents(join(self.data_path, 'responses', 'response4.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)
        self.assertEqual('test@onelogin.com', response.get_nameid())
        self.assertFalse(response.is_valid(self.get_request_data()))

    def testNodeTextAttack(self):
        """
        Tests the get_nameid and get_attributes methods of the OneLogin_Saml2_Response
        Test that the node text with comment attack (VU#475445) is not allowed
        """
        xml = self.file_contents(join(self.data_path, 'responses', 'response_node_text_attack.xml.base64'))
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        response = OneLogin_Saml2_Response(settings, xml)
        attributes = response.get_attributes()
        nameid = response.get_nameid()
        self.assertEqual("smith", attributes.get('surname')[0])
        self.assertEqual('support@onelogin.com', nameid)

    def testGetSessionNotOnOrAfter(self):
        """
        Tests the get_session_not_on_or_after method of the OneLogin_Saml2_Response
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        xml = self.file_contents(join(self.data_path, 'responses', 'response1.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)
        self.assertEqual(1290203857, response.get_session_not_on_or_after())

        # An assertion that do not specified Session timeout should return NULL
        xml_2 = self.file_contents(join(self.data_path, 'responses', 'response2.xml.base64'))
        response_2 = OneLogin_Saml2_Response(settings, xml_2)
        self.assertEqual(None, response_2.get_session_not_on_or_after())

        xml_3 = self.file_contents(join(self.data_path, 'responses', 'valid_encrypted_assertion.xml.base64'))
        response_3 = OneLogin_Saml2_Response(settings, xml_3)
        self.assertEqual(2696012228, response_3.get_session_not_on_or_after())

    def testIsInvalidXML(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_Response
        Case Invalid XML
        """
        message = compat.to_string(OneLogin_Saml2_Utils.b64encode('<samlp:Response Version="2.0" ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion>invalid</saml:Assertion></samlp:Response>'))
        request_data = {
            'http_host': 'example.com',
            'script_name': 'index.html',
            'get_data': {}
        }
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())

        response = OneLogin_Saml2_Response(settings, message)
        response.is_valid(request_data)
        self.assertEqual('No Signature found. SAML Response rejected', response.get_error())

        settings.set_strict(True)
        response_2 = OneLogin_Saml2_Response(settings, message)
        self.assertFalse(response_2.is_valid(request_data))
        self.assertEqual('Invalid SAML Response. Not match the saml-schema-protocol-2.0.xsd', response_2.get_error())

    def testValidateNumAssertions(self):
        """
        Tests the validate_num_assertions method of the OneLogin_Saml2_Response
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        xml = self.file_contents(join(self.data_path, 'responses', 'response1.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)
        self.assertTrue(response.validate_num_assertions())

        xml_multi_assertion = self.file_contents(join(self.data_path, 'responses', 'invalids', 'multiple_assertions.xml.base64'))
        response_2 = OneLogin_Saml2_Response(settings, xml_multi_assertion)
        self.assertFalse(response_2.validate_num_assertions())

    def testValidateTimestamps(self):
        """
        Tests the validate_timestamps method of the OneLogin_Saml2_Response
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        xml = self.file_contents(join(self.data_path, 'responses', 'valid_response.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)
        self.assertTrue(response.validate_timestamps())

        xml_2 = self.file_contents(join(self.data_path, 'responses', 'valid_encrypted_assertion.xml.base64'))
        response_2 = OneLogin_Saml2_Response(settings, xml_2)
        self.assertTrue(response_2.validate_timestamps())

        xml_3 = self.file_contents(join(self.data_path, 'responses', 'expired_response.xml.base64'))
        response_3 = OneLogin_Saml2_Response(settings, xml_3)
        self.assertFalse(response_3.validate_timestamps())

        xml_4 = self.file_contents(join(self.data_path, 'responses', 'invalids', 'not_after_failed.xml.base64'))
        response_4 = OneLogin_Saml2_Response(settings, xml_4)
        self.assertFalse(response_4.validate_timestamps())

        xml_5 = self.file_contents(join(self.data_path, 'responses', 'invalids', 'not_before_failed.xml.base64'))
        response_5 = OneLogin_Saml2_Response(settings, xml_5)
        self.assertFalse(response_5.validate_timestamps())

    def testValidateVersion(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_Response
        Case invalid version
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        xml = self.file_contents(join(self.data_path, 'responses', 'invalids', 'no_saml2.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)
        with self.assertRaisesRegex(Exception, 'Unsupported SAML version'):
            response.is_valid(self.get_request_data(), raise_exceptions=True)

    def testValidateID(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_Response
        Case invalid no ID
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        xml = self.file_contents(join(self.data_path, 'responses', 'invalids', 'no_id.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)
        with self.assertRaisesRegex(Exception, 'Missing ID attribute on SAML Response'):
            response.is_valid(self.get_request_data(), raise_exceptions=True)

    def testIsInValidReference(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_Response
        Case invalid reference
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        xml = self.file_contents(join(self.data_path, 'responses', 'response1.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)
        self.assertFalse(response.is_valid(self.get_request_data()))
        self.assertEqual('Signature validation failed. SAML Response rejected', response.get_error())

        with self.assertRaisesRegex(Exception, 'Signature validation failed. SAML Response rejected'):
            response.is_valid(self.get_request_data(), raise_exceptions=True)

    def testIsInValidExpired(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_Response
        Case expired response
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        xml = self.file_contents(join(self.data_path, 'responses', 'expired_response.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)
        response.is_valid(self.get_request_data())
        self.assertEqual('No Signature found. SAML Response rejected', response.get_error())

        settings.set_strict(True)
        response_2 = OneLogin_Saml2_Response(settings, xml)
        with self.assertRaisesRegex(Exception, 'Could not validate timestamp: expired. Check system clock.'):
            response_2.is_valid(self.get_request_data(), raise_exceptions=True)

    def testIsInValidNoStatement(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_Response
        Case no statement
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        xml = self.file_contents(join(self.data_path, 'responses', 'invalids', 'no_signature.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)
        response.is_valid(self.get_request_data())
        self.assertEqual('No Signature found. SAML Response rejected', response.get_error())

        settings.set_strict(True)
        response_2 = OneLogin_Saml2_Response(settings, xml)
        self.assertFalse(response_2.is_valid(self.get_request_data()))
        self.assertEqual('There is no AttributeStatement on the Response', response_2.get_error())

    def testIsValidOptionalStatement(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_Response
        Case AttributeStatement is optional
        """
        # shortcut
        json_settings = self.loadSettingsJSON()
        settings = OneLogin_Saml2_Settings(json_settings)
        settings.set_strict(True)

        # want AttributeStatement True by default
        self.assertTrue(settings.get_security_data()['wantAttributeStatement'])

        xml = self.file_contents(join(self.data_path, 'responses', 'invalids', 'signed_assertion_response.xml.base64'))

        response = OneLogin_Saml2_Response(settings, xml)
        self.assertFalse(response.is_valid(self.get_request_data()))
        self.assertEqual('There is no AttributeStatement on the Response', response.get_error())

        # change wantAttributeStatement to optional
        json_settings['security']['wantAttributeStatement'] = False
        settings = OneLogin_Saml2_Settings(json_settings)

        # check settings
        self.assertFalse(settings.get_security_data()['wantAttributeStatement'])

        response = OneLogin_Saml2_Response(settings, xml)
        response.is_valid(self.get_request_data())
        self.assertNotEqual('There is no AttributeStatement on the Response', response.get_error())
        self.assertEqual('Signature validation failed. SAML Response rejected', response.get_error())

    def testIsInValidNoKey(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_Response
        Case no key
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        xml = self.file_contents(join(self.data_path, 'responses', 'invalids', 'no_key.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)
        with self.assertRaisesRegex(Exception, 'Signature validation failed. SAML Response rejected'):
            response.is_valid(self.get_request_data(), raise_exceptions=True)

    def testIsInValidMultipleAssertions(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_Response
        Case invalid multiple assertions
        """

        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        xml = self.file_contents(join(self.data_path, 'responses', 'invalids', 'multiple_assertions.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)
        with self.assertRaisesRegex(Exception, 'SAML Response must contain 1 assertion'):
            response.is_valid(self.get_request_data(), raise_exceptions=True)

    def testIsInValidEncAttrs(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_Response
        Case invalid Encrypted Attrs
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        xml = self.file_contents(join(self.data_path, 'responses', 'invalids', 'encrypted_attrs.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)
        response.is_valid(self.get_request_data())
        self.assertEqual('No Signature found. SAML Response rejected', response.get_error())

        settings.set_strict(True)
        response_2 = OneLogin_Saml2_Response(settings, xml)
        with self.assertRaisesRegex(Exception, 'There is an EncryptedAttribute in the Response and this SP not support them'):
            response_2.is_valid(self.get_request_data(), raise_exceptions=True)

    def testIsInValidDuplicatedAttrs(self):
        """
        Tests the getAttributes method of the OneLogin_Saml2_Response
        Case duplicated Attrs
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        xml = self.file_contents(join(self.data_path, 'responses', 'invalids', 'duplicated_attributes.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)
        with self.assertRaisesRegex(Exception, 'Found an Attribute element with duplicated Name'):
            response.get_attributes()

    def testIsInValidDestination(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_Response class
        Case Invalid Response, Invalid Destination
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        message = self.file_contents(join(self.data_path, 'responses', 'unsigned_response.xml.base64'))
        response = OneLogin_Saml2_Response(settings, message)
        response.is_valid(self.get_request_data())
        self.assertEqual('No Signature found. SAML Response rejected', response.get_error())

        settings.set_strict(True)
        response_2 = OneLogin_Saml2_Response(settings, message)
        self.assertFalse(response_2.is_valid(self.get_request_data()))
        self.assertIn('The response was received at', response_2.get_error())

        # Empty Destination
        dom = parseString(b64decode(message))
        dom.firstChild.setAttribute('Destination', '')
        message_2 = OneLogin_Saml2_Utils.b64encode(dom.toxml())
        response_3 = OneLogin_Saml2_Response(settings, message_2)
        self.assertFalse(response_3.is_valid(self.get_request_data()))
        self.assertIn('The response has an empty Destination value', response_3.get_error())

        message_3 = self.file_contents(join(self.data_path, 'responses', 'invalids', 'empty_destination.xml.base64'))
        response_4 = OneLogin_Saml2_Response(settings, message_3)
        self.assertFalse(response_4.is_valid(self.get_request_data()))
        self.assertEqual('The response has an empty Destination value', response_4.get_error())

        # No Destination
        dom.firstChild.removeAttribute('Destination')
        message_4 = OneLogin_Saml2_Utils.b64encode(dom.toxml())
        response_5 = OneLogin_Saml2_Response(settings, message_4)
        self.assertFalse(response_5.is_valid(self.get_request_data()))
        self.assertIn('A valid SubjectConfirmation was not found on this Response', response_5.get_error())

    def testIsInValidAudience(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_Response class
        Case Invalid Response, Invalid Audience
        """
        request_data = {
            'http_host': 'stuff.com',
            'script_name': '/endpoints/endpoints/acs.php',
        }
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        message = self.file_contents(join(self.data_path, 'responses', 'invalids', 'invalid_audience.xml.base64'))

        response = OneLogin_Saml2_Response(settings, message)
        response.is_valid(request_data)
        self.assertEqual('No Signature found. SAML Response rejected', response.get_error())

        settings.set_strict(True)
        response_2 = OneLogin_Saml2_Response(settings, message)

        self.assertFalse(response_2.is_valid(request_data))
        self.assertIn('is not a valid audience for this Response', response_2.get_error())

    def testIsInValidAuthenticationContext(self):
        """
        Tests that requestedAuthnContext, when set, is compared against the
        response AuthnContext, which is what you use for two-factor
        authentication. Without this check you can get back a valid response
        that didn't complete the two-factor step.
        """
        request_data = self.get_request_data()
        message = self.file_contents(join(self.data_path, 'responses', 'valid_response.xml.base64'))
        two_factor_context = 'urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken'
        password_context = 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password'
        settings_dict = self.loadSettingsJSON()
        settings_dict['security']['requestedAuthnContext'] = [two_factor_context]
        settings_dict['security']['failOnAuthnContextMismatch'] = True
        settings_dict['strict'] = True
        settings = OneLogin_Saml2_Settings(settings_dict)

        # check that we catch when the contexts don't match
        response = OneLogin_Saml2_Response(settings, message)
        self.assertFalse(response.is_valid(request_data))
        self.assertIn('The AuthnContext "%s" didn\'t include requested context "%s"' % (password_context, two_factor_context), response.get_error())

        # now drop in the expected AuthnContextClassRef and see that it passes
        original_message = compat.to_string(OneLogin_Saml2_Utils.b64decode(message))
        two_factor_message = original_message.replace(password_context, two_factor_context)
        two_factor_message = OneLogin_Saml2_Utils.b64encode(two_factor_message)
        response = OneLogin_Saml2_Response(settings, two_factor_message)
        response.is_valid(request_data)
        # check that we got as far as destination validation, which comes later
        self.assertIn('The response was received at', response.get_error())

        # with the default setting, check that we succeed with our original context
        settings_dict['security']['requestedAuthnContext'] = True
        settings = OneLogin_Saml2_Settings(settings_dict)
        response = OneLogin_Saml2_Response(settings, message)
        response.is_valid(request_data)
        self.assertIn('The response was received at', response.get_error())

    def testIsInValidIssuer(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_Response class
        Case Invalid Response, Invalid Issuer
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        request_data = {
            'http_host': 'example.com',
            'script_name': 'index.html'
        }
        current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)
        xml = self.file_contents(join(self.data_path, 'responses', 'invalids', 'invalid_issuer_assertion.xml.base64'))
        plain_message = compat.to_string(OneLogin_Saml2_Utils.b64decode(xml))
        plain_message = plain_message.replace('http://stuff.com/endpoints/endpoints/acs.php', current_url)
        message = OneLogin_Saml2_Utils.b64encode(plain_message)

        xml_2 = self.file_contents(join(self.data_path, 'responses', 'invalids', 'invalid_issuer_message.xml.base64'))
        plain_message_2 = compat.to_string(OneLogin_Saml2_Utils.b64decode(xml_2))
        plain_message_2 = plain_message_2.replace('http://stuff.com/endpoints/endpoints/acs.php', current_url)
        message_2 = OneLogin_Saml2_Utils.b64encode(plain_message_2)

        response = OneLogin_Saml2_Response(settings, message)
        response.is_valid(request_data)
        self.assertEqual('No Signature found. SAML Response rejected', response.get_error())

        response_2 = OneLogin_Saml2_Response(settings, message_2)
        response_2.is_valid(request_data)
        self.assertEqual('No Signature found. SAML Response rejected', response_2.get_error())

        settings.set_strict(True)
        response_3 = OneLogin_Saml2_Response(settings, message)
        with self.assertRaisesRegex(Exception, 'Invalid issuer in the Assertion/Response'):
            response_3.is_valid(request_data, raise_exceptions=True)

        response_4 = OneLogin_Saml2_Response(settings, message_2)
        with self.assertRaisesRegex(Exception, 'Invalid issuer in the Assertion/Response'):
            response_4.is_valid(request_data, raise_exceptions=True)

    def testIsInValidSessionIndex(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_Response class
        Case Invalid Response, Invalid SessionIndex
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        request_data = {
            'http_host': 'example.com',
            'script_name': 'index.html'
        }
        current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)
        xml = self.file_contents(join(self.data_path, 'responses', 'invalids', 'invalid_sessionindex.xml.base64'))
        plain_message = compat.to_string(OneLogin_Saml2_Utils.b64decode(xml))
        plain_message = plain_message.replace('http://stuff.com/endpoints/endpoints/acs.php', current_url)
        message = OneLogin_Saml2_Utils.b64encode(plain_message)

        response = OneLogin_Saml2_Response(settings, message)
        response.is_valid(request_data)
        self.assertEqual('No Signature found. SAML Response rejected', response.get_error())

        settings.set_strict(True)
        response_2 = OneLogin_Saml2_Response(settings, message)
        with self.assertRaisesRegex(Exception, 'The attributes have expired, based on the SessionNotOnOrAfter of the AttributeStatement of this Response'):
            response_2.is_valid(request_data, raise_exceptions=True)

    def testDatetimeWithMiliseconds(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_Response class
        Somtimes IdPs uses datetimes with miliseconds, this
        test is to verify that the toolkit supports them
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        request_data = {
            'http_host': 'example.com',
            'script_name': 'index.html'
        }
        current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)

        xml = self.file_contents(join(self.data_path, 'responses', 'unsigned_response_with_miliseconds.xm.base64'))
        plain_message = compat.to_string(OneLogin_Saml2_Utils.b64decode(xml))
        plain_message = plain_message.replace('http://stuff.com/endpoints/endpoints/acs.php', current_url)
        message = OneLogin_Saml2_Utils.b64encode(plain_message)
        response = OneLogin_Saml2_Response(settings, message)
        response.is_valid(request_data)
        self.assertEqual('No Signature found. SAML Response rejected', response.get_error())

    def testIsInValidSubjectConfirmation(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_Response class
        Case Invalid Response, Invalid SubjectConfirmation
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        request_data = {
            'http_host': 'example.com',
            'script_name': 'index.html'
        }
        current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)
        xml = self.file_contents(join(self.data_path, 'responses', 'invalids', 'no_subjectconfirmation_method.xml.base64'))
        plain_message = compat.to_string(OneLogin_Saml2_Utils.b64decode(xml))
        plain_message = plain_message.replace('http://stuff.com/endpoints/endpoints/acs.php', current_url)
        message = OneLogin_Saml2_Utils.b64encode(plain_message)

        xml_2 = self.file_contents(join(self.data_path, 'responses', 'invalids', 'no_subjectconfirmation_data.xml.base64'))
        plain_message_2 = compat.to_string(OneLogin_Saml2_Utils.b64decode(xml_2))
        plain_message_2 = plain_message_2.replace('http://stuff.com/endpoints/endpoints/acs.php', current_url)
        message_2 = OneLogin_Saml2_Utils.b64encode(plain_message_2)

        xml_3 = self.file_contents(join(self.data_path, 'responses', 'invalids', 'invalid_subjectconfirmation_inresponse.xml.base64'))
        plain_message_3 = compat.to_string(OneLogin_Saml2_Utils.b64decode(xml_3))
        plain_message_3 = plain_message_3.replace('http://stuff.com/endpoints/endpoints/acs.php', current_url)
        message_3 = OneLogin_Saml2_Utils.b64encode(plain_message_3)

        xml_4 = self.file_contents(join(self.data_path, 'responses', 'invalids', 'invalid_subjectconfirmation_recipient.xml.base64'))
        plain_message_4 = compat.to_string(OneLogin_Saml2_Utils.b64decode(xml_4))
        plain_message_4 = plain_message_4.replace('http://stuff.com/endpoints/endpoints/acs.php', current_url)
        message_4 = OneLogin_Saml2_Utils.b64encode(plain_message_4)

        xml_5 = self.file_contents(join(self.data_path, 'responses', 'invalids', 'invalid_subjectconfirmation_noa.xml.base64'))
        plain_message_5 = compat.to_string(OneLogin_Saml2_Utils.b64decode(xml_5))
        plain_message_5 = plain_message_5.replace('http://stuff.com/endpoints/endpoints/acs.php', current_url)
        message_5 = OneLogin_Saml2_Utils.b64encode(plain_message_5)

        xml_6 = self.file_contents(join(self.data_path, 'responses', 'invalids', 'invalid_subjectconfirmation_nb.xml.base64'))
        plain_message_6 = compat.to_string(OneLogin_Saml2_Utils.b64decode(xml_6))
        plain_message_6 = plain_message_6.replace('http://stuff.com/endpoints/endpoints/acs.php', current_url)
        message_6 = OneLogin_Saml2_Utils.b64encode(plain_message_6)

        response = OneLogin_Saml2_Response(settings, message)
        response.is_valid(request_data)
        self.assertEqual('No Signature found. SAML Response rejected', response.get_error())

        response_2 = OneLogin_Saml2_Response(settings, message_2)
        response_2.is_valid(request_data)
        self.assertEqual('No Signature found. SAML Response rejected', response_2.get_error())

        response_3 = OneLogin_Saml2_Response(settings, message_3)
        response_3.is_valid(request_data)
        self.assertEqual('No Signature found. SAML Response rejected', response_3.get_error())

        response_4 = OneLogin_Saml2_Response(settings, message_4)
        response_4.is_valid(request_data)
        self.assertEqual('No Signature found. SAML Response rejected', response_4.get_error())

        response_5 = OneLogin_Saml2_Response(settings, message_5)
        response_5.is_valid(request_data)
        self.assertEqual('No Signature found. SAML Response rejected', response_5.get_error())

        response_6 = OneLogin_Saml2_Response(settings, message_6)
        response_6.is_valid(request_data)
        self.assertEqual('No Signature found. SAML Response rejected', response_6.get_error())

        settings.set_strict(True)
        response = OneLogin_Saml2_Response(settings, message)
        with self.assertRaisesRegex(Exception, 'A valid SubjectConfirmation was not found on this Response'):
            response.is_valid(request_data, raise_exceptions=True)

        response_2 = OneLogin_Saml2_Response(settings, message_2)
        with self.assertRaisesRegex(Exception, 'A valid SubjectConfirmation was not found on this Response'):
            response_2.is_valid(request_data, raise_exceptions=True)

        response_3 = OneLogin_Saml2_Response(settings, message_3)
        with self.assertRaisesRegex(Exception, 'A valid SubjectConfirmation was not found on this Response'):
            response_3.is_valid(request_data, raise_exceptions=True)

        response_4 = OneLogin_Saml2_Response(settings, message_4)
        with self.assertRaisesRegex(Exception, 'A valid SubjectConfirmation was not found on this Response'):
            response_4.is_valid(request_data, raise_exceptions=True)

        response_5 = OneLogin_Saml2_Response(settings, message_5)
        with self.assertRaisesRegex(Exception, 'A valid SubjectConfirmation was not found on this Response'):
            response_5.is_valid(request_data, raise_exceptions=True)

        response_6 = OneLogin_Saml2_Response(settings, message_6)
        with self.assertRaisesRegex(Exception, 'A valid SubjectConfirmation was not found on this Response'):
            response_6.is_valid(request_data, raise_exceptions=True)

    def testIsInValidRequestId(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_Response class
        Case Invalid Response, Invalid requestID
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        request_data = {
            'http_host': 'example.com',
            'script_name': 'index.html'
        }
        current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)
        xml = self.file_contents(join(self.data_path, 'responses', 'unsigned_response.xml.base64'))
        plain_message = compat.to_string(OneLogin_Saml2_Utils.b64decode(xml))
        plain_message = plain_message.replace('http://stuff.com/endpoints/endpoints/acs.php', current_url)
        message = OneLogin_Saml2_Utils.b64encode(plain_message)

        response = OneLogin_Saml2_Response(settings, message)
        request_id = 'invalid'
        response.is_valid(request_data, request_id)
        self.assertEqual('No Signature found. SAML Response rejected', response.get_error())

        settings.set_strict(True)
        response = OneLogin_Saml2_Response(settings, message)
        with self.assertRaisesRegex(Exception, 'The InResponseTo of the Response'):
            response.is_valid(request_data, request_id, raise_exceptions=True)

        valid_request_id = '_57bcbf70-7b1f-012e-c821-782bcb13bb38'
        response.is_valid(request_data, valid_request_id)
        self.assertEqual('No Signature found. SAML Response rejected', response.get_error())

    def testIsInValidSignIssues(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_Response class
        Case Invalid Response, Invalid signing issues
        """
        settings_info = self.loadSettingsJSON()
        request_data = {
            'http_host': 'example.com',
            'script_name': 'index.html'
        }
        current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)
        xml = self.file_contents(join(self.data_path, 'responses', 'unsigned_response.xml.base64'))
        plain_message = compat.to_string(OneLogin_Saml2_Utils.b64decode(xml))
        plain_message = plain_message.replace('http://stuff.com/endpoints/endpoints/acs.php', current_url)
        message = OneLogin_Saml2_Utils.b64encode(plain_message)

        settings_info['security']['wantAssertionsSigned'] = False
        settings = OneLogin_Saml2_Settings(settings_info)
        response = OneLogin_Saml2_Response(settings, message)
        response.is_valid(request_data)
        self.assertEqual('No Signature found. SAML Response rejected', response.get_error())

        settings_info['security']['wantAssertionsSigned'] = True
        settings_2 = OneLogin_Saml2_Settings(settings_info)
        response_2 = OneLogin_Saml2_Response(settings_2, message)
        response_2.is_valid(request_data)
        self.assertEqual('No Signature found. SAML Response rejected', response_2.get_error())

        settings_info['strict'] = True
        settings_info['security']['wantAssertionsSigned'] = False
        settings_3 = OneLogin_Saml2_Settings(settings_info)
        response_3 = OneLogin_Saml2_Response(settings_3, message)
        response_3.is_valid(request_data)
        self.assertEqual('No Signature found. SAML Response rejected', response_3.get_error())

        settings_info['security']['wantAssertionsSigned'] = True
        settings_4 = OneLogin_Saml2_Settings(settings_info)
        response_4 = OneLogin_Saml2_Response(settings_4, message)
        with self.assertRaisesRegex(Exception, 'The Assertion of the Response is not signed and the SP require it'):
            response_4.is_valid(request_data, raise_exceptions=True)

        settings_info['security']['wantAssertionsSigned'] = False
        settings_info['strict'] = False

        settings_info['security']['wantMessagesSigned'] = False
        settings_5 = OneLogin_Saml2_Settings(settings_info)
        response_5 = OneLogin_Saml2_Response(settings_5, message)
        response_5.is_valid(request_data)
        self.assertEqual('No Signature found. SAML Response rejected', response_5.get_error())

        settings_info['security']['wantMessagesSigned'] = True
        settings_6 = OneLogin_Saml2_Settings(settings_info)
        response_6 = OneLogin_Saml2_Response(settings_6, message)
        response_6.is_valid(request_data)
        self.assertEqual('No Signature found. SAML Response rejected', response_6.get_error())

        settings_info['strict'] = True
        settings_info['security']['wantMessagesSigned'] = False
        settings_7 = OneLogin_Saml2_Settings(settings_info)
        response_7 = OneLogin_Saml2_Response(settings_7, message)
        response_7.is_valid(request_data)
        self.assertEqual('No Signature found. SAML Response rejected', response_7.get_error())

        settings_info['security']['wantMessagesSigned'] = True
        settings_8 = OneLogin_Saml2_Settings(settings_info)
        response_8 = OneLogin_Saml2_Response(settings_8, message)
        with self.assertRaisesRegex(Exception, 'The Message of the Response is not signed and the SP require it'):
            response_8.is_valid(request_data, raise_exceptions=True)

    def testIsInValidEncIssues(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_Response class
        Case Invalid Response, Invalid encryptation issues
        """
        settings_info = self.loadSettingsJSON()
        request_data = {
            'http_host': 'example.com',
            'script_name': 'index.html'
        }
        current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)
        xml = self.file_contents(join(self.data_path, 'responses', 'unsigned_response.xml.base64'))
        plain_message = compat.to_string(OneLogin_Saml2_Utils.b64decode(xml))
        plain_message = plain_message.replace('http://stuff.com/endpoints/endpoints/acs.php', current_url)
        message = OneLogin_Saml2_Utils.b64encode(plain_message)

        settings_info['security']['wantAssertionsEncrypted'] = True
        settings = OneLogin_Saml2_Settings(settings_info)
        response = OneLogin_Saml2_Response(settings, message)
        response.is_valid(request_data)
        self.assertEqual('No Signature found. SAML Response rejected', response.get_error())

        settings_info['strict'] = True
        settings_info['security']['wantAssertionsEncrypted'] = False
        settings = OneLogin_Saml2_Settings(settings_info)
        response_2 = OneLogin_Saml2_Response(settings, message)
        response_2.is_valid(request_data)
        self.assertEqual('No Signature found. SAML Response rejected', response_2.get_error())

        settings_info['security']['wantAssertionsEncrypted'] = True
        settings = OneLogin_Saml2_Settings(settings_info)
        response_3 = OneLogin_Saml2_Response(settings, message)

        self.assertFalse(response_3.is_valid(request_data))
        self.assertEqual('The assertion of the Response is not encrypted and the SP require it', response_3.get_error())

        settings_info['security']['wantAssertionsEncrypted'] = False
        settings_info['security']['wantNameIdEncrypted'] = True
        settings_info['strict'] = False
        settings = OneLogin_Saml2_Settings(settings_info)
        response_4 = OneLogin_Saml2_Response(settings, message)
        response_4.is_valid(request_data)
        self.assertEqual('No Signature found. SAML Response rejected', response_4.get_error())

        settings_info['strict'] = True
        settings = OneLogin_Saml2_Settings(settings_info)
        response_5 = OneLogin_Saml2_Response(settings, message)

        self.assertFalse(response_5.is_valid(request_data))
        self.assertEqual('The NameID of the Response is not encrypted and the SP require it', response_5.get_error())

        settings_info_2 = self.loadSettingsJSON('settings3.json')
        settings_info_2['strict'] = True
        settings_info_2['security']['wantNameIdEncrypted'] = True
        settings_2 = OneLogin_Saml2_Settings(settings_info_2)

        request_data = {
            'http_host': 'pytoolkit.com',
            'server_port': 8000,
            'script_name': '',
            'request_uri': '?acs',
        }

        message_2 = self.file_contents(join(self.data_path, 'responses', 'valid_encrypted_assertion_encrypted_nameid.xml.base64'))
        response_6 = OneLogin_Saml2_Response(settings_2, message_2)
        self.assertFalse(response_6.is_valid(request_data))
        self.assertEqual('The attributes have expired, based on the SessionNotOnOrAfter of the AttributeStatement of this Response', response_6.get_error())

    def testIsInValidCert(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_Response
        Case invalid cert
        """
        settings_info = self.loadSettingsJSON()
        settings_info['idp']['x509cert'] = 'NotValidCert'
        settings = OneLogin_Saml2_Settings(settings_info)
        xml = self.file_contents(join(self.data_path, 'responses', 'valid_response.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)

        with self.assertRaisesRegex(Exception, 'Signature validation failed. SAML Response rejected'):
            response.is_valid(self.get_request_data(), raise_exceptions=True)

    def testIsInValidCert2(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_Response
        Case invalid cert2
        """
        settings_info = self.loadSettingsJSON()
        settings_info['idp']['x509cert'] = 'MIIENjCCAx6gAwIBAgIBATANBgkqhkiG9w0BAQUFADBvMQswCQYDVQQGEwJTRTEU MBIGA1UEChMLQWRkVHJ1c3QgQUIxJjAkBgNVBAsTHUFkZFRydXN0IEV4dGVybmFs IFRUUCBOZXR3b3JrMSIwIAYDVQQDExlBZGRUcnVzdCBFeHRlcm5hbCBDQSBSb290 MB4XDTAwMDUzMDEwNDgzOFoXDTIwMDUzMDEwNDgzOFowbzELMAkGA1UEBhMCU0Ux FDASBgNVBAoTC0FkZFRydXN0IEFCMSYwJAYDVQQLEx1BZGRUcnVzdCBFeHRlcm5h bCBUVFAgTmV0d29yazEiMCAGA1UEAxMZQWRkVHJ1c3QgRXh0ZXJuYWwgQ0EgUm9v dDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALf3GjPm8gAELTngTlvt H7xsD821+iO2zt6bETOXpClMfZOfvUq8k+0DGuOPz+VtUFrWlymUWoCwSXrbLpX9 uMq/NzgtHj6RQa1wVsfwTz/oMp50ysiQVOnGXw94nZpAPA6sYapeFI+eh6FqUNzX mk6vBbOmcZSccbNQYArHE504B4YCqOmoaSYYkKtMsE8jqzpPhNjfzp/haW+710LX a0Tkx63ubUFfclpxCDezeWWkWaCUN/cALw3CknLa0Dhy2xSoRcRdKn23tNbE7qzN E0S3ySvdQwAl+mG5aWpYIxG3pzOPVnVZ9c0p10a3CitlttNCbxWyuHv77+ldU9U0 WicCAwEAAaOB3DCB2TAdBgNVHQ4EFgQUrb2YejS0Jvf6xCZU7wO94CTLVBowCwYD VR0PBAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wgZkGA1UdIwSBkTCBjoAUrb2YejS0 Jvf6xCZU7wO94CTLVBqhc6RxMG8xCzAJBgNVBAYTAlNFMRQwEgYDVQQKEwtBZGRU cnVzdCBBQjEmMCQGA1UECxMdQWRkVHJ1c3QgRXh0ZXJuYWwgVFRQIE5ldHdvcmsx IjAgBgNVBAMTGUFkZFRydXN0IEV4dGVybmFsIENBIFJvb3SCAQEwDQYJKoZIhvcN AQEFBQADggEBALCb4IUlwtYj4g+WBpKdQZic2YR5gdkeWxQHIzZlj7DYd7usQWxH YINRsPkyPef89iYTx4AWpb9a/IfPeHmJIZriTAcKhjW88t5RxNKWt9x+Tu5w/Rw5 6wwCURQtjr0W4MHfRnXnJK3s9EK0hZNwEGe6nQY1ShjTK3rMUUKhemPR5ruhxSvC Nr4TDea9Y355e6cJDUCrat2PisP29owaQgVR1EX1n6diIWgVIEM8med8vSTYqZEX c4g/VhsxOBi0cQ+azcgOno4uG+GMmIPLHzHxREzGBHNJdmAPx/i9F4BrLunMTA5a mnkPIAou1Z5jJh5VkpTYghdae9C8x49OhgQ='
        settings = OneLogin_Saml2_Settings(settings_info)
        xml = self.file_contents(join(self.data_path, 'responses', 'valid_response.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)
        self.assertFalse(response.is_valid(self.get_request_data()))

    def testIsValid(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_Response
        Case valid unsigned response
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())

        xml = self.file_contents(join(self.data_path, 'responses', 'valid_unsigned_response.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)
        response.is_valid(self.get_request_data())
        self.assertEqual('No Signature found. SAML Response rejected', response.get_error())

    def testIsValid2(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_Response
        Case valid response2
        """
        settings_info = self.loadSettingsJSON()
        settings = OneLogin_Saml2_Settings(settings_info)

        # expired cert
        xml = self.file_contents(join(self.data_path, 'responses', 'valid_response.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)

        self.assertTrue(response.is_valid(self.get_request_data()))

        settings_info_2 = self.loadSettingsJSON('settings2.json')
        settings_2 = OneLogin_Saml2_Settings(settings_info_2)
        xml_2 = self.file_contents(join(self.data_path, 'responses', 'valid_response2.xml.base64'))
        response_2 = OneLogin_Saml2_Response(settings_2, xml_2)
        self.assertTrue(response_2.is_valid(self.get_request_data()))

        settings_info_3 = self.loadSettingsJSON('settings2.json')
        idp_cert = OneLogin_Saml2_Utils.format_cert(settings_info_3['idp']['x509cert'])
        settings_info_3['idp']['certFingerprint'] = OneLogin_Saml2_Utils.calculate_x509_fingerprint(idp_cert)
        settings_info_3['idp']['x509cert'] = ''
        settings_3 = OneLogin_Saml2_Settings(settings_info_3)
        response_3 = OneLogin_Saml2_Response(settings_3, xml_2)
        self.assertTrue(response_3.is_valid(self.get_request_data()))

        settings_info_3['idp']['certFingerprintAlgorithm'] = 'sha1'
        settings_4 = OneLogin_Saml2_Settings(settings_info_3)
        response_4 = OneLogin_Saml2_Response(settings_4, xml_2)
        self.assertTrue(response_4.is_valid(self.get_request_data()))

        settings_info_3['idp']['certFingerprintAlgorithm'] = 'sha256'
        settings_5 = OneLogin_Saml2_Settings(settings_info_3)
        response_5 = OneLogin_Saml2_Response(settings_5, xml_2)
        self.assertFalse(response_5.is_valid(self.get_request_data()))

        settings_info_3['idp']['certFingerprint'] = OneLogin_Saml2_Utils.calculate_x509_fingerprint(idp_cert, 'sha256')
        settings_6 = OneLogin_Saml2_Settings(settings_info_3)
        response_6 = OneLogin_Saml2_Response(settings_6, xml_2)
        self.assertTrue(response_6.is_valid(self.get_request_data()))

    def testIsValidEnc(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_Response
        Case valid encrypted assertion

        Signed data can't be modified, so Destination will always fail in
        strict mode
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())

        # expired cert
        xml = self.file_contents(join(self.data_path, 'responses', 'double_signed_encrypted_assertion.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)
        self.assertTrue(response.is_valid(self.get_request_data()))

        xml_2 = self.file_contents(join(self.data_path, 'responses', 'signed_encrypted_assertion.xml.base64'))
        response_2 = OneLogin_Saml2_Response(settings, xml_2)
        self.assertTrue(response_2.is_valid(self.get_request_data()))

        xml_3 = self.file_contents(join(self.data_path, 'responses', 'signed_message_encrypted_assertion.xml.base64'))
        response_3 = OneLogin_Saml2_Response(settings, xml_3)
        self.assertTrue(response_3.is_valid(self.get_request_data()))

        settings_2 = OneLogin_Saml2_Settings(self.loadSettingsJSON('settings2.json'))
        xml_4 = self.file_contents(join(self.data_path, 'responses', 'double_signed_encrypted_assertion2.xml.base64'))
        response_4 = OneLogin_Saml2_Response(settings_2, xml_4)
        self.assertTrue(response_4.is_valid(self.get_request_data()))

        xml_5 = self.file_contents(join(self.data_path, 'responses', 'signed_encrypted_assertion2.xml.base64'))
        response_5 = OneLogin_Saml2_Response(settings_2, xml_5)
        self.assertTrue(response_5.is_valid(self.get_request_data()))

        xml_6 = self.file_contents(join(self.data_path, 'responses', 'signed_message_encrypted_assertion2.xml.base64'))
        response_6 = OneLogin_Saml2_Response(settings_2, xml_6)
        self.assertTrue(response_6.is_valid(self.get_request_data()))

        settings.set_strict(True)
        xml_7 = self.file_contents(join(self.data_path, 'responses', 'valid_encrypted_assertion.xml.base64'))
        # In order to avoid the destination problem
        plain_message = compat.to_string(OneLogin_Saml2_Utils.b64decode(xml_7))
        request_data = {
            'http_host': 'example.com',
            'script_name': 'index.html'
        }
        current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)
        plain_message = plain_message.replace('http://stuff.com/endpoints/endpoints/acs.php', current_url)
        message = compat.to_string(OneLogin_Saml2_Utils.b64encode(plain_message))
        response_7 = OneLogin_Saml2_Response(settings, message)
        response_7.is_valid(request_data)
        self.assertEqual('No Signature found. SAML Response rejected', response_7.get_error())

    def testIsValidSign(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_Response
        Case valid sign response / sign assertion / both signed

        Strict mode will always fail due destination problem, if we manipulate
        it the sign will fail.
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())

        # expired cert
        xml = self.file_contents(join(self.data_path, 'responses', 'signed_message_response.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)
        self.assertTrue(response.is_valid(self.get_request_data()))

        xml_2 = self.file_contents(join(self.data_path, 'responses', 'signed_assertion_response.xml.base64'))
        response_2 = OneLogin_Saml2_Response(settings, xml_2)
        self.assertTrue(response_2.is_valid(self.get_request_data()))

        xml_3 = self.file_contents(join(self.data_path, 'responses', 'double_signed_response.xml.base64'))
        response_3 = OneLogin_Saml2_Response(settings, xml_3)
        self.assertTrue(response_3.is_valid(self.get_request_data()))

        settings_2 = OneLogin_Saml2_Settings(self.loadSettingsJSON('settings2.json'))
        xml_4 = self.file_contents(join(self.data_path, 'responses', 'signed_message_response2.xml.base64'))
        response_4 = OneLogin_Saml2_Response(settings_2, xml_4)
        self.assertTrue(response_4.is_valid(self.get_request_data()))

        xml_5 = self.file_contents(join(self.data_path, 'responses', 'signed_assertion_response2.xml.base64'))
        response_5 = OneLogin_Saml2_Response(settings_2, xml_5)
        self.assertTrue(response_5.is_valid(self.get_request_data()))

        xml_6 = self.file_contents(join(self.data_path, 'responses', 'double_signed_response2.xml.base64'))
        response_6 = OneLogin_Saml2_Response(settings_2, xml_6)
        self.assertTrue(response_6.is_valid(self.get_request_data()))

        dom = parseString(b64decode(xml_4))
        dom.firstChild.firstChild.firstChild.nodeValue = 'https://example.com/other-idp'
        xml_7 = OneLogin_Saml2_Utils.b64encode(dom.toxml())
        response_7 = OneLogin_Saml2_Response(settings, xml_7)
        # Modified message
        self.assertFalse(response_7.is_valid(self.get_request_data()))

        dom_2 = parseString(OneLogin_Saml2_Utils.b64decode(xml_5))
        dom_2.firstChild.firstChild.firstChild.nodeValue = 'https://example.com/other-idp'
        xml_8 = OneLogin_Saml2_Utils.b64encode(dom_2.toxml())
        response_8 = OneLogin_Saml2_Response(settings, xml_8)
        # Modified message
        self.assertFalse(response_8.is_valid(self.get_request_data()))

        dom_3 = parseString(OneLogin_Saml2_Utils.b64decode(xml_6))
        dom_3.firstChild.firstChild.firstChild.nodeValue = 'https://example.com/other-idp'
        xml_9 = OneLogin_Saml2_Utils.b64encode(dom_3.toxml())
        response_9 = OneLogin_Saml2_Response(settings, xml_9)
        # Modified message
        self.assertFalse(response_9.is_valid(self.get_request_data()))

    def testIsValidSignFingerprint(self):
        """
        Tests the is_valid method of the OneLogin_Saml2_Response
        Case valid sign response / sign assertion / both signed with fingerprint

        Strict mode will always fail due destination problem, if we manipulate
        it the sign will fail.
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON("settings6.json"))

        # expired cert
        xml = self.file_contents(join(self.data_path, 'responses', 'signed_message_response.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)
        self.assertTrue(response.is_valid(self.get_request_data()))

        xml_2 = self.file_contents(join(self.data_path, 'responses', 'signed_assertion_response.xml.base64'))
        response_2 = OneLogin_Saml2_Response(settings, xml_2)
        self.assertTrue(response_2.is_valid(self.get_request_data()))

        xml_3 = self.file_contents(join(self.data_path, 'responses', 'double_signed_response.xml.base64'))
        response_3 = OneLogin_Saml2_Response(settings, xml_3)
        self.assertTrue(response_3.is_valid(self.get_request_data()))

        settings_2 = OneLogin_Saml2_Settings(self.loadSettingsJSON('settings2.json'))
        xml_4 = self.file_contents(join(self.data_path, 'responses', 'signed_message_response2.xml.base64'))
        response_4 = OneLogin_Saml2_Response(settings_2, xml_4)
        self.assertTrue(response_4.is_valid(self.get_request_data()))

        xml_5 = self.file_contents(join(self.data_path, 'responses', 'signed_assertion_response2.xml.base64'))
        response_5 = OneLogin_Saml2_Response(settings_2, xml_5)
        self.assertTrue(response_5.is_valid(self.get_request_data()))

        xml_6 = self.file_contents(join(self.data_path, 'responses', 'double_signed_response2.xml.base64'))
        response_6 = OneLogin_Saml2_Response(settings_2, xml_6)
        self.assertTrue(response_6.is_valid(self.get_request_data()))

        dom = parseString(b64decode(xml_4))
        dom.firstChild.firstChild.firstChild.nodeValue = 'https://example.com/other-idp'
        xml_7 = OneLogin_Saml2_Utils.b64encode(dom.toxml())
        response_7 = OneLogin_Saml2_Response(settings, xml_7)
        # Modified message
        self.assertFalse(response_7.is_valid(self.get_request_data()))

        dom_2 = parseString(OneLogin_Saml2_Utils.b64decode(xml_5))
        dom_2.firstChild.firstChild.firstChild.nodeValue = 'https://example.com/other-idp'
        xml_8 = OneLogin_Saml2_Utils.b64encode(dom_2.toxml())
        response_8 = OneLogin_Saml2_Response(settings, xml_8)
        # Modified message
        self.assertFalse(response_8.is_valid(self.get_request_data()))

        dom_3 = parseString(OneLogin_Saml2_Utils.b64decode(xml_6))
        dom_3.firstChild.firstChild.firstChild.nodeValue = 'https://example.com/other-idp'
        xml_9 = OneLogin_Saml2_Utils.b64encode(dom_3.toxml())
        response_9 = OneLogin_Saml2_Response(settings, xml_9)
        # Modified message
        self.assertFalse(response_9.is_valid(self.get_request_data()))

    def testIsValidSignWithEmptyReferenceURI(self):
        settings_info = self.loadSettingsJSON()
        del settings_info['idp']['x509cert']
        settings_info['idp']['certFingerprint'] = "194d97e4d8c9c8cfa4b721e5ee497fd9660e5213"
        settings = OneLogin_Saml2_Settings(settings_info)
        xml = self.file_contents(join(self.data_path, 'responses', 'response_without_reference_uri.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)
        self.assertTrue(response.is_valid(self.get_request_data()))

    def testIsValidWithoutInResponseTo(self):
        """
        If assertion contains InResponseTo but not the Response tag, we should
        not compare the assertion InResponseTo value to None.
        """

        # prepare strict settings
        settings_info = self.loadSettingsJSON()
        settings_info['strict'] = True
        settings_info['idp']['entityId'] = 'https://pitbulk.no-ip.org/simplesaml/saml2/idp/metadata.php'
        settings_info['sp']['entityId'] = 'https://pitbulk.no-ip.org/newonelogin/demo1/metadata.php'

        settings = OneLogin_Saml2_Settings(settings_info)

        xml = self.file_contents(join(self.data_path, 'responses', 'valid_response_without_inresponseto.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)

        not_on_or_after = datetime.strptime('2014-02-19T09:37:01Z', '%Y-%m-%dT%H:%M:%SZ')
        not_on_or_after -= timedelta(seconds=150)

        with freeze_time(not_on_or_after):
            self.assertTrue(response.is_valid({
                'https': 'on',
                'http_host': 'pitbulk.no-ip.org',
                'script_name': 'newonelogin/demo1/index.php?acs'
            }))

    def testIsValidRaisesExceptionWhenRaisesArgumentIsTrue(self):
        """
        Tests that the internal exception gets raised if the raise parameter
        is True.
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        settings.set_strict(True)
        xml = self.file_contents(join(self.data_path, 'responses', 'invalids', 'no_conditions.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)

        self.assertFalse(response.is_valid(self.get_request_data()))

        with self.assertRaises(Exception):
            response.is_valid(self.get_request_data(), raise_exceptions=True)

    def testStatusCheckBeforeAssertionCheck(self):
        """
        Tests the status of a response is checked before the assertion count. As failed statuses will have no assertions
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        xml = self.file_contents(join(self.data_path, 'responses', 'invalids', 'status_code_responder.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)
        with self.assertRaisesRegex(Exception, 'The status code of the Response was not Success, was Responder'):
            response.is_valid(self.get_request_data(), raise_exceptions=True)

    def testGetId(self):
        """
        Tests that we can retrieve the ID of the Response
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        xml = self.file_contents(join(self.data_path, 'responses', 'signed_message_response.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)
        self.assertEqual(response.get_id(), 'pfxc3d2b542-0f7e-8767-8e87-5b0dc6913375')

    def testGetAssertionId(self):
        """
        Tests that we can retrieve the ID of the Assertion
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        xml = self.file_contents(join(self.data_path, 'responses', 'signed_message_response.xml.base64'))
        response = OneLogin_Saml2_Response(settings, xml)
        self.assertEqual(response.get_assertion_id(), '_cccd6024116641fe48e0ae2c51220d02755f96c98d')

    def testGetAssertionNotOnOrAfter(self):
        """
        Tests that we can retrieve the NotOnOrAfter value of
        the valid SubjectConfirmationData
        """
        settings_data = self.loadSettingsJSON()
        request_data = self.get_request_data()
        settings = OneLogin_Saml2_Settings(settings_data)
        message = self.file_contents(join(self.data_path, 'responses', 'valid_response.xml.base64'))
        response = OneLogin_Saml2_Response(settings, message)
        self.assertIsNone(response.get_assertion_not_on_or_after())

        response.is_valid(request_data)
        self.assertIsNone(response.get_error())
        self.assertIsNone(response.get_assertion_not_on_or_after())

        settings_data['strict'] = True
        settings = OneLogin_Saml2_Settings(settings_data)
        response = OneLogin_Saml2_Response(settings, message)

        response.is_valid(request_data)
        self.assertNotEqual(response.get_error(), None)
        self.assertIsNone(response.get_assertion_not_on_or_after())

        request_data['https'] = 'on'
        request_data['http_host'] = 'pitbulk.no-ip.org'
        request_data['script_name'] = '/newonelogin/demo1/index.php?acs'
        response.is_valid(request_data)
        self.assertIsNone(response.get_error())
        self.assertEqual(response.get_assertion_not_on_or_after(), 2671081021)
