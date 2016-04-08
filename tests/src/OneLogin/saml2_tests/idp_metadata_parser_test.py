# -*- coding: utf-8 -*-

# Copyright (c) 2014, OneLogin, Inc.
# All rights reserved.


import json
from os.path import dirname, join, exists
from lxml.etree import XMLSyntaxError
import unittest

from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser


class OneLogin_Saml2_IdPMetadataParser_Test(unittest.TestCase):
    data_path = join(dirname(dirname(dirname(dirname(__file__)))), 'data')
    settings_path = join(dirname(dirname(dirname(dirname(__file__)))), 'settings')

    def loadSettingsJSON(self, filename='settings1.json'):
        filename = join(self.settings_path, filename)
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

    def testGetMetadata(self):
        """
        Tests the get_metadata method of the OneLogin_Saml2_IdPMetadataParser
        """
        with self.assertRaises(Exception):
            data = OneLogin_Saml2_IdPMetadataParser.get_metadata('http://google.es')

        data = OneLogin_Saml2_IdPMetadataParser.get_metadata('https://www.testshib.org/metadata/testshib-providers.xml')
        self.assertTrue(data is not None and data is not {})

    def testParseRemote(self):
        """
        Tests the parse_remote method of the OneLogin_Saml2_IdPMetadataParser
        """
        with self.assertRaises(Exception):
            data = OneLogin_Saml2_IdPMetadataParser.parse_remote('http://google.es')

        data = OneLogin_Saml2_IdPMetadataParser.parse_remote('https://www.testshib.org/metadata/testshib-providers.xml')
        self.assertTrue(data is not None and data is not {})
        expected_data = {'sp': {'NameIDFormat': 'urn:mace:shibboleth:1.0:nameIdentifier'}, 'idp': {'singleLogoutService': {'url': 'https://idp.testshib.org/idp/profile/SAML2/Redirect/SSO'}, 'entityId': 'https://idp.testshib.org/idp/shibboleth'}}
        self.assertEqual(expected_data, data)

    def testParse(self):
        """
        Tests the parse method of the OneLogin_Saml2_IdPMetadataParser
        """
        with self.assertRaises(XMLSyntaxError):
            data = OneLogin_Saml2_IdPMetadataParser.parse('')

        xml_sp_metadata = self.file_contents(join(self.data_path, 'metadata', 'metadata_settings1.xml'))
        data = OneLogin_Saml2_IdPMetadataParser.parse(xml_sp_metadata)
        self.assertEqual({}, data)

        xml_idp_metadata = self.file_contents(join(self.data_path, 'metadata', 'idp_metadata.xml'))
        data = OneLogin_Saml2_IdPMetadataParser.parse(xml_idp_metadata)
        expected_data = {'sp': {'NameIDFormat': 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'}, 'idp': {'singleLogoutService': {'url': 'https://app.onelogin.com/trust/saml2/http-post/sso/383123'}, 'entityId': 'https://app.onelogin.com/saml/metadata/383123', 'x509cert': 'MIIEHjCCAwagAwIBAgIBATANBgkqhkiG9w0BAQUFADBnMQswCQYDVQQGEwJVUzET\nMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UEBwwMU2FudGEgTW9uaWNhMREwDwYD\nVQQKDAhPbmVMb2dpbjEZMBcGA1UEAwwQYXBwLm9uZWxvZ2luLmNvbTAeFw0xMzA2\nMDUxNzE2MjBaFw0xODA2MDUxNzE2MjBaMGcxCzAJBgNVBAYTAlVTMRMwEQYDVQQI\nDApDYWxpZm9ybmlhMRUwEwYDVQQHDAxTYW50YSBNb25pY2ExETAPBgNVBAoMCE9u\nZUxvZ2luMRkwFwYDVQQDDBBhcHAub25lbG9naW4uY29tMIIBIjANBgkqhkiG9w0B\nAQEFAAOCAQ8AMIIBCgKCAQEAse8rnep4qL2GmhH10pMQyJ2Jae+AQHyfgVjaQZ7Z\n0QQog5jX91vcJRSMi0XWJnUtOr6lF0dq1+yckjZ92wyLrH+7fvngNO1aV4Mjk9sT\ngf+iqMrae6y6fRxDt9PXrEFVjvd3vv7QTJf2FuIPy4vVP06Dt8EMkQIr8rmLmU0m\nTr1k2DkrdtdlCuNFTXuAu3QqfvNCRrRwfNObn9MP6JeOUdcGLJsBjGF8exfcN1SF\nzRF0JFr3dmOlx761zK5liD0T1sYWnDquatj/JD9fZMbKecBKni1NglH/LVd+b6aJ\nUAr5LulERULUjLqYJRKW31u91/4Qazdo9tbvwqyFxaoUrwIDAQABo4HUMIHRMAwG\nA1UdEwEB/wQCMAAwHQYDVR0OBBYEFPWcXvQSlTXnzZD2xziuoUvrrDedMIGRBgNV\nHSMEgYkwgYaAFPWcXvQSlTXnzZD2xziuoUvrrDedoWukaTBnMQswCQYDVQQGEwJV\nUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UEBwwMU2FudGEgTW9uaWNhMREw\nDwYDVQQKDAhPbmVMb2dpbjEZMBcGA1UEAwwQYXBwLm9uZWxvZ2luLmNvbYIBATAO\nBgNVHQ8BAf8EBAMCBPAwDQYJKoZIhvcNAQEFBQADggEBAB/8xe3rzqXQVxzHyAHu\nAuPa73ClDoL1cko0Fp8CGcqEIyj6Te9gx5z6wyfv+Lo8RFvBLlnB1lXqbC+fTGcV\ngG/4oKLJ5UwRFxInqpZPnOAudVNnd0PYOODn9FWs6u+OTIQIaIcPUv3MhB9lwHIJ\nsTk/bs9xcru5TPyLIxLLd6ib/pRceKH2mTkzUd0DYk9CQNXXeoGx/du5B9nh3ClP\nTbVakRzl3oswgI5MQIphYxkW70SopEh4kOFSRE1ND31NNIq1YrXlgtkguQBFsZWu\nQOPR6cEwFZzP0tHTYbI839WgxX6hfhIUTUz6mLqq4+3P4BG3+1OXeVDg63y8Uh78\n1sE='}}
        self.assertEqual(expected_data, data)

    def testMergeSettings(self):
        """
        Tests the merge_settings method of the OneLogin_Saml2_IdPMetadataParser
        """
        with self.assertRaises(AttributeError):
            settings_result = OneLogin_Saml2_IdPMetadataParser.merge_settings(None, {})

        with self.assertRaises(TypeError):
            settings_result = OneLogin_Saml2_IdPMetadataParser.merge_settings({}, None)

        xml_idp_metadata = self.file_contents(join(self.data_path, 'metadata', 'idp_metadata.xml'))
        data = OneLogin_Saml2_IdPMetadataParser.parse(xml_idp_metadata)
        settings = self.loadSettingsJSON()
        settings_result = OneLogin_Saml2_IdPMetadataParser.merge_settings(settings, data)
        expected_data = {u'sp': {'NameIDFormat': 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'}, u'idp': {'singleLogoutService': {'url': 'https://app.onelogin.com/trust/saml2/http-post/sso/383123'}, 'entityId': 'https://app.onelogin.com/saml/metadata/383123', 'x509cert': 'MIIEHjCCAwagAwIBAgIBATANBgkqhkiG9w0BAQUFADBnMQswCQYDVQQGEwJVUzET\nMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UEBwwMU2FudGEgTW9uaWNhMREwDwYD\nVQQKDAhPbmVMb2dpbjEZMBcGA1UEAwwQYXBwLm9uZWxvZ2luLmNvbTAeFw0xMzA2\nMDUxNzE2MjBaFw0xODA2MDUxNzE2MjBaMGcxCzAJBgNVBAYTAlVTMRMwEQYDVQQI\nDApDYWxpZm9ybmlhMRUwEwYDVQQHDAxTYW50YSBNb25pY2ExETAPBgNVBAoMCE9u\nZUxvZ2luMRkwFwYDVQQDDBBhcHAub25lbG9naW4uY29tMIIBIjANBgkqhkiG9w0B\nAQEFAAOCAQ8AMIIBCgKCAQEAse8rnep4qL2GmhH10pMQyJ2Jae+AQHyfgVjaQZ7Z\n0QQog5jX91vcJRSMi0XWJnUtOr6lF0dq1+yckjZ92wyLrH+7fvngNO1aV4Mjk9sT\ngf+iqMrae6y6fRxDt9PXrEFVjvd3vv7QTJf2FuIPy4vVP06Dt8EMkQIr8rmLmU0m\nTr1k2DkrdtdlCuNFTXuAu3QqfvNCRrRwfNObn9MP6JeOUdcGLJsBjGF8exfcN1SF\nzRF0JFr3dmOlx761zK5liD0T1sYWnDquatj/JD9fZMbKecBKni1NglH/LVd+b6aJ\nUAr5LulERULUjLqYJRKW31u91/4Qazdo9tbvwqyFxaoUrwIDAQABo4HUMIHRMAwG\nA1UdEwEB/wQCMAAwHQYDVR0OBBYEFPWcXvQSlTXnzZD2xziuoUvrrDedMIGRBgNV\nHSMEgYkwgYaAFPWcXvQSlTXnzZD2xziuoUvrrDedoWukaTBnMQswCQYDVQQGEwJV\nUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UEBwwMU2FudGEgTW9uaWNhMREw\nDwYDVQQKDAhPbmVMb2dpbjEZMBcGA1UEAwwQYXBwLm9uZWxvZ2luLmNvbYIBATAO\nBgNVHQ8BAf8EBAMCBPAwDQYJKoZIhvcNAQEFBQADggEBAB/8xe3rzqXQVxzHyAHu\nAuPa73ClDoL1cko0Fp8CGcqEIyj6Te9gx5z6wyfv+Lo8RFvBLlnB1lXqbC+fTGcV\ngG/4oKLJ5UwRFxInqpZPnOAudVNnd0PYOODn9FWs6u+OTIQIaIcPUv3MhB9lwHIJ\nsTk/bs9xcru5TPyLIxLLd6ib/pRceKH2mTkzUd0DYk9CQNXXeoGx/du5B9nh3ClP\nTbVakRzl3oswgI5MQIphYxkW70SopEh4kOFSRE1ND31NNIq1YrXlgtkguQBFsZWu\nQOPR6cEwFZzP0tHTYbI839WgxX6hfhIUTUz6mLqq4+3P4BG3+1OXeVDg63y8Uh78\n1sE='}, u'strict': False, u'contactPerson': {u'technical': {u'givenName': u'technical_name', u'emailAddress': u'technical@example.com'}, u'support': {u'givenName': u'support_name', u'emailAddress': u'support@example.com'}}, u'debug': False, u'organization': {u'en-US': {u'url': u'http://sp.example.com', u'displayname': u'SP test', u'name': u'sp_test'}}, u'security': {u'signMetadata': False, u'wantAssertionsSigned': False, u'authnRequestsSigned': False}, u'custom_base_path': u'../../../tests/data/customPath/'}
        self.assertEqual(expected_data, settings_result)

        expected_data2 = {'sp': {u'singleLogoutService': {u'url': u'http://stuff.com/endpoints/endpoints/sls.php'}, u'assertionConsumerService': {u'url': u'http://stuff.com/endpoints/endpoints/acs.php'}, u'entityId': u'http://stuff.com/endpoints/metadata.php', u'NameIDFormat': u'urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified'}, 'idp': {u'singleLogoutService': {u'url': u'http://idp.example.com/SingleLogoutService.php'}, u'entityId': u'http://idp.example.com/', u'x509cert': u'MIICgTCCAeoCCQCbOlrWDdX7FTANBgkqhkiG9w0BAQUFADCBhDELMAkGA1UEBhMCTk8xGDAWBgNVBAgTD0FuZHJlYXMgU29sYmVyZzEMMAoGA1UEBxMDRm9vMRAwDgYDVQQKEwdVTklORVRUMRgwFgYDVQQDEw9mZWlkZS5lcmxhbmcubm8xITAfBgkqhkiG9w0BCQEWEmFuZHJlYXNAdW5pbmV0dC5ubzAeFw0wNzA2MTUxMjAxMzVaFw0wNzA4MTQxMjAxMzVaMIGEMQswCQYDVQQGEwJOTzEYMBYGA1UECBMPQW5kcmVhcyBTb2xiZXJnMQwwCgYDVQQHEwNGb28xEDAOBgNVBAoTB1VOSU5FVFQxGDAWBgNVBAMTD2ZlaWRlLmVybGFuZy5ubzEhMB8GCSqGSIb3DQEJARYSYW5kcmVhc0B1bmluZXR0Lm5vMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDivbhR7P516x/S3BqKxupQe0LONoliupiBOesCO3SHbDrl3+q9IbfnfmE04rNuMcPsIxB161TdDpIesLCn7c8aPHISKOtPlAeTZSnb8QAu7aRjZq3+PbrP5uW3TcfCGPtKTytHOge/OlJbo078dVhXQ14d1EDwXJW1rRXuUt4C8QIDAQABMA0GCSqGSIb3DQEBBQUAA4GBACDVfp86HObqY+e8BUoWQ9+VMQx1ASDohBjwOsg2WykUqRXF+dLfcUH9dWR63CtZIKFDbStNomPnQz7nbK+onygwBspVEbnHuUihZq3ZUdmumQqCw4Uvs/1Uvq3orOo/WJVhTyvLgFVK2QarQ4/67OZfHd7R+POBXhophSMv1ZOo', u'singleSignOnService': {u'url': u'http://idp.example.com/SSOService.php'}}, u'strict': False, u'contactPerson': {u'technical': {u'givenName': u'technical_name', u'emailAddress': u'technical@example.com'}, u'support': {u'givenName': u'support_name', u'emailAddress': u'support@example.com'}}, u'debug': False, u'organization': {u'en-US': {u'url': u'http://sp.example.com', u'displayname': u'SP test', u'name': u'sp_test'}}, u'security': {u'signMetadata': False, u'wantAssertionsSigned': False, u'authnRequestsSigned': False}, u'custom_base_path': u'../../../tests/data/customPath/'}
        settings_result2 = OneLogin_Saml2_IdPMetadataParser.merge_settings(data, settings)
        self.assertEqual(expected_data2, settings_result2)
