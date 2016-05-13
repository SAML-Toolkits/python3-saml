# -*- coding: utf-8 -*-

# Copyright (c) 2014, OneLogin, Inc.
# All rights reserved.


from copy import deepcopy
import json
from os.path import dirname, join, exists
from lxml.etree import XMLSyntaxError
import unittest
import urllib

from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
from onelogin.saml2.constants import OneLogin_Saml2_Constants


class OneLogin_Saml2_IdPMetadataParser_Test(unittest.TestCase):
    # Instruct unittest to not hide diffs upon test failure, even for complex
    # dictionaries. This prevents the message "Diff is 907 characters long.
    # Set self.maxDiff to None to see it." from showing up.
    maxDiff = None

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

        try:
            data = OneLogin_Saml2_IdPMetadataParser.get_metadata('https://www.testshib.org/metadata/testshib-providers.xml')
            self.assertTrue(data is not None and data is not {})
        except urllib.error.URLError:
            pass

    def testParseRemote(self):
        """
        Tests the parse_remote method of the OneLogin_Saml2_IdPMetadataParser
        """
        with self.assertRaises(Exception):
            data = OneLogin_Saml2_IdPMetadataParser.parse_remote('http://google.es')

        try:
            data = OneLogin_Saml2_IdPMetadataParser.parse_remote('https://www.testshib.org/metadata/testshib-providers.xml')
        except urllib.error.URLError:
            xml = self.file_contents(join(self.data_path, 'metadata', 'testshib-providers.xml'))
            data = OneLogin_Saml2_IdPMetadataParser.parse(xml)

        self.assertTrue(data is not None and data is not {})
        expected_settings_json = """
        {
          "sp": {
            "NameIDFormat": "urn:mace:shibboleth:1.0:nameIdentifier"
          },
          "idp": {
            "entityId": "https://idp.testshib.org/idp/shibboleth",
            "singleSignOnService": {
              "url": "https://idp.testshib.org/idp/profile/SAML2/Redirect/SSO",
              "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            }
          }
        }
        """
        expected_settings = json.loads(expected_settings_json)
        self.assertEqual(expected_settings, data)

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

        # W/o further specification, expect to get the redirect binding SSO
        # URL extracted.
        expected_settings_json = """
        {
          "idp": {
            "singleSignOnService": {
              "url": "https://app.onelogin.com/trust/saml2/http-post/sso/383123",
              "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            },
            "x509cert": "MIIEHjCCAwagAwIBAgIBATANBgkqhkiG9w0BAQUFADBnMQswCQYDVQQGEwJVUzET\\nMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UEBwwMU2FudGEgTW9uaWNhMREwDwYD\\nVQQKDAhPbmVMb2dpbjEZMBcGA1UEAwwQYXBwLm9uZWxvZ2luLmNvbTAeFw0xMzA2\\nMDUxNzE2MjBaFw0xODA2MDUxNzE2MjBaMGcxCzAJBgNVBAYTAlVTMRMwEQYDVQQI\\nDApDYWxpZm9ybmlhMRUwEwYDVQQHDAxTYW50YSBNb25pY2ExETAPBgNVBAoMCE9u\\nZUxvZ2luMRkwFwYDVQQDDBBhcHAub25lbG9naW4uY29tMIIBIjANBgkqhkiG9w0B\\nAQEFAAOCAQ8AMIIBCgKCAQEAse8rnep4qL2GmhH10pMQyJ2Jae+AQHyfgVjaQZ7Z\\n0QQog5jX91vcJRSMi0XWJnUtOr6lF0dq1+yckjZ92wyLrH+7fvngNO1aV4Mjk9sT\\ngf+iqMrae6y6fRxDt9PXrEFVjvd3vv7QTJf2FuIPy4vVP06Dt8EMkQIr8rmLmU0m\\nTr1k2DkrdtdlCuNFTXuAu3QqfvNCRrRwfNObn9MP6JeOUdcGLJsBjGF8exfcN1SF\\nzRF0JFr3dmOlx761zK5liD0T1sYWnDquatj/JD9fZMbKecBKni1NglH/LVd+b6aJ\\nUAr5LulERULUjLqYJRKW31u91/4Qazdo9tbvwqyFxaoUrwIDAQABo4HUMIHRMAwG\\nA1UdEwEB/wQCMAAwHQYDVR0OBBYEFPWcXvQSlTXnzZD2xziuoUvrrDedMIGRBgNV\\nHSMEgYkwgYaAFPWcXvQSlTXnzZD2xziuoUvrrDedoWukaTBnMQswCQYDVQQGEwJV\\nUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UEBwwMU2FudGEgTW9uaWNhMREw\\nDwYDVQQKDAhPbmVMb2dpbjEZMBcGA1UEAwwQYXBwLm9uZWxvZ2luLmNvbYIBATAO\\nBgNVHQ8BAf8EBAMCBPAwDQYJKoZIhvcNAQEFBQADggEBAB/8xe3rzqXQVxzHyAHu\\nAuPa73ClDoL1cko0Fp8CGcqEIyj6Te9gx5z6wyfv+Lo8RFvBLlnB1lXqbC+fTGcV\\ngG/4oKLJ5UwRFxInqpZPnOAudVNnd0PYOODn9FWs6u+OTIQIaIcPUv3MhB9lwHIJ\\nsTk/bs9xcru5TPyLIxLLd6ib/pRceKH2mTkzUd0DYk9CQNXXeoGx/du5B9nh3ClP\\nTbVakRzl3oswgI5MQIphYxkW70SopEh4kOFSRE1ND31NNIq1YrXlgtkguQBFsZWu\\nQOPR6cEwFZzP0tHTYbI839WgxX6hfhIUTUz6mLqq4+3P4BG3+1OXeVDg63y8Uh78\\n1sE=",
            "entityId": "https://app.onelogin.com/saml/metadata/383123"
          },
          "sp": {
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
          }
        }
        """
        expected_settings = json.loads(expected_settings_json)
        self.assertEqual(expected_settings, data)

    def test_parse_testshib_required_binding_sso_redirect(self):
        """
        Test with testshib metadata.

        Especially test extracting SSO with REDIRECT binding.

        Note that the testshib metadata does not contain an SLO specification
        in the first <IDPSSODescriptor> tag.
        """
        expected_settings_json = """
        {
          "sp": {
            "NameIDFormat": "urn:mace:shibboleth:1.0:nameIdentifier"
          },
          "idp": {
            "entityId": "https://idp.testshib.org/idp/shibboleth",
            "singleSignOnService": {
              "url": "https://idp.testshib.org/idp/profile/SAML2/Redirect/SSO",
              "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            }
          }
        }
        """
        try:
            xmldoc = OneLogin_Saml2_IdPMetadataParser.get_metadata(
                'https://www.testshib.org/metadata/testshib-providers.xml')
        except urllib.error.URLError:
            xmldoc = self.file_contents(join(self.data_path, 'metadata', 'testshib-providers.xml'))

        # Parse, require SSO REDIRECT binding, implicitly.
        settings1 = OneLogin_Saml2_IdPMetadataParser.parse(xmldoc)
        # Parse, require SSO REDIRECT binding, explicitly.
        settings2 = OneLogin_Saml2_IdPMetadataParser.parse(
            xmldoc,
            required_sso_binding=OneLogin_Saml2_Constants.BINDING_HTTP_REDIRECT
        )
        expected_settings = json.loads(expected_settings_json)
        self.assertEqual(expected_settings, settings1)
        self.assertEqual(expected_settings, settings2)

    def test_parse_testshib_required_binding_sso_post(self):
        """
        Test with testshib metadata.

        Especially test extracting SSO with POST binding.
        """
        expected_settings_json = """
        {
          "sp": {
            "NameIDFormat": "urn:mace:shibboleth:1.0:nameIdentifier"
          },
          "idp": {
            "entityId": "https://idp.testshib.org/idp/shibboleth",
            "singleSignOnService": {
              "url": "https://idp.testshib.org/idp/profile/SAML2/POST/SSO",
              "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            }
          }
        }
        """
        try:
            xmldoc = OneLogin_Saml2_IdPMetadataParser.get_metadata(
                'https://www.testshib.org/metadata/testshib-providers.xml')
        except urllib.error.URLError:
            xmldoc = self.file_contents(join(self.data_path, 'metadata', 'testshib-providers.xml'))

        # Parse, require POST binding.
        settings = OneLogin_Saml2_IdPMetadataParser.parse(
            xmldoc,
            required_sso_binding=OneLogin_Saml2_Constants.BINDING_HTTP_POST
        )
        expected_settings = json.loads(expected_settings_json)
        self.assertEqual(expected_settings, settings)

    def test_parse_required_binding_all(self):
        """
        Test all combinations of the `require_slo_binding` and
        `require_sso_binding` parameters.

        Note: IdP metadata contains a single logout (SLO)
        service and does not specify any endpoint for the POST binding.
        """
        expected_settings_json = """
        {
          "sp": {
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
          },
          "idp": {
            "entityId": "urn:example:idp",
            "x509cert": "MIIDPDCCAiQCCQDydJgOlszqbzANBgkqhkiG9w0BAQUFADBgMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEQMA4GA1UEChMHSmFua3lDbzESMBAGA1UEAxMJbG9jYWxob3N0MB4XDTE0MDMxMjE5NDYzM1oXDTI3MTExOTE5NDYzM1owYDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xEDAOBgNVBAoTB0phbmt5Q28xEjAQBgNVBAMTCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMGvJpRTTasRUSPqcbqCG+ZnTAurnu0vVpIG9lzExnh11o/BGmzu7lB+yLHcEdwrKBBmpepDBPCYxpVajvuEhZdKFx/Fdy6j5mH3rrW0Bh/zd36CoUNjbbhHyTjeM7FN2yF3u9lcyubuvOzr3B3gX66IwJlU46+wzcQVhSOlMk2tXR+fIKQExFrOuK9tbX3JIBUqItpI+HnAow509CnM134svw8PTFLkR6/CcMqnDfDK1m993PyoC1Y+N4X9XkhSmEQoAlAHPI5LHrvuujM13nvtoVYvKYoj7ScgumkpWNEvX652LfXOnKYlkB8ZybuxmFfIkzedQrbJsyOhfL03cMECAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAeHwzqwnzGEkxjzSD47imXaTqtYyETZow7XwBc0ZaFS50qRFJUgKTAmKS1xQBP/qHpStsROT35DUxJAE6NY1Kbq3ZbCuhGoSlY0L7VzVT5tpu4EY8+Dq/u2EjRmmhoL7UkskvIZ2n1DdERtd+YUMTeqYl9co43csZwDno/IKomeN5qaPc39IZjikJ+nUC6kPFKeu/3j9rgHNlRtocI6S1FdtFz9OZMQlpr0JbUt2T3xS/YoQJn6coDmJL5GTiiKM6cOe+Ur1VwzS1JEDbSS2TWWhzq8ojLdrotYLGd9JOsoQhElmz+tMfCFQUFLExinPAyy7YHlSiVX13QH2XTu/iQQ==",
            "singleSignOnService": {
              "url": "http://idp.example.com",
              "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            },
            "singleLogoutService": {
              "url": "http://idp.example.com/logout",
              "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            }
          }
        }
        """
        xmldoc = self.file_contents(join(self.data_path, 'metadata', 'idp_metadata2.xml'))

        expected_settings = json.loads(expected_settings_json)

        # Parse, require SLO and SSO REDIRECT binding, implicitly.
        settings1 = OneLogin_Saml2_IdPMetadataParser.parse(xmldoc)

        # Parse, require SLO and SSO REDIRECT binding, explicitly.
        settings2 = OneLogin_Saml2_IdPMetadataParser.parse(
            xmldoc,
            required_sso_binding=OneLogin_Saml2_Constants.BINDING_HTTP_REDIRECT,
            required_slo_binding=OneLogin_Saml2_Constants.BINDING_HTTP_REDIRECT
        )
        expected_settings1_2 = deepcopy(expected_settings)
        self.assertEqual(expected_settings1_2, settings1)
        self.assertEqual(expected_settings1_2, settings2)

        settings3 = OneLogin_Saml2_IdPMetadataParser.parse(
            xmldoc,
            required_sso_binding=OneLogin_Saml2_Constants.BINDING_HTTP_POST,
            required_slo_binding=OneLogin_Saml2_Constants.BINDING_HTTP_POST
        )

        expected_settings3 = deepcopy(expected_settings)
        del expected_settings3['idp']['singleLogoutService']
        del expected_settings3['idp']['singleSignOnService']
        self.assertEqual(expected_settings3, settings3)

        settings4 = OneLogin_Saml2_IdPMetadataParser.parse(
            xmldoc,
            required_sso_binding=OneLogin_Saml2_Constants.BINDING_HTTP_POST,
            required_slo_binding=OneLogin_Saml2_Constants.BINDING_HTTP_REDIRECT
        )
        settings5 = OneLogin_Saml2_IdPMetadataParser.parse(
            xmldoc,
            required_sso_binding=OneLogin_Saml2_Constants.BINDING_HTTP_POST
        )
        expected_settings4_5 = deepcopy(expected_settings)
        del expected_settings4_5['idp']['singleSignOnService']
        self.assertEqual(expected_settings4_5, settings4)
        self.assertEqual(expected_settings4_5, settings5)

        settings6 = OneLogin_Saml2_IdPMetadataParser.parse(
            xmldoc,
            required_sso_binding=OneLogin_Saml2_Constants.BINDING_HTTP_REDIRECT,
            required_slo_binding=OneLogin_Saml2_Constants.BINDING_HTTP_POST
        )
        settings7 = OneLogin_Saml2_IdPMetadataParser.parse(
            xmldoc,
            required_slo_binding=OneLogin_Saml2_Constants.BINDING_HTTP_POST
        )
        expected_settings6_7 = deepcopy(expected_settings)
        del expected_settings6_7['idp']['singleLogoutService']
        self.assertEqual(expected_settings6_7, settings6)
        self.assertEqual(expected_settings6_7, settings7)

    def testMergeSettings(self):
        """
        Tests the merge_settings method of the OneLogin_Saml2_IdPMetadataParser
        """
        with self.assertRaises(TypeError):
            settings_result = OneLogin_Saml2_IdPMetadataParser.merge_settings(None, {})

        with self.assertRaises(TypeError):
            settings_result = OneLogin_Saml2_IdPMetadataParser.merge_settings({}, None)

        xml_idp_metadata = self.file_contents(join(self.data_path, 'metadata', 'idp_metadata.xml'))

        # Parse XML metadata.
        data = OneLogin_Saml2_IdPMetadataParser.parse(xml_idp_metadata)

        # Read base settings.
        settings = self.loadSettingsJSON()

        # Merge settings from XML metadata into base settings,
        # let XML metadata have priority if there are conflicting
        # attributes.
        settings_result = OneLogin_Saml2_IdPMetadataParser.merge_settings(settings, data)

        # Generate readable JSON representation:
        # print("%s" % json.dumps(settings_result, indent=2).replace(r'\n', r'\\n'))

        expected_settings_json = """
        {
          "custom_base_path": "../../../tests/data/customPath/",
          "contactPerson": {
            "support": {
              "emailAddress": "support@example.com",
              "givenName": "support_name"
            },
            "technical": {
              "emailAddress": "technical@example.com",
              "givenName": "technical_name"
            }
          },
          "idp": {
            "singleSignOnService": {
              "url": "https://app.onelogin.com/trust/saml2/http-post/sso/383123",
              "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            },
            "entityId": "https://app.onelogin.com/saml/metadata/383123",
            "singleLogoutService": {
              "url": "http://idp.example.com/SingleLogoutService.php"
            },
            "x509cert": "MIIEHjCCAwagAwIBAgIBATANBgkqhkiG9w0BAQUFADBnMQswCQYDVQQGEwJVUzET\\nMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UEBwwMU2FudGEgTW9uaWNhMREwDwYD\\nVQQKDAhPbmVMb2dpbjEZMBcGA1UEAwwQYXBwLm9uZWxvZ2luLmNvbTAeFw0xMzA2\\nMDUxNzE2MjBaFw0xODA2MDUxNzE2MjBaMGcxCzAJBgNVBAYTAlVTMRMwEQYDVQQI\\nDApDYWxpZm9ybmlhMRUwEwYDVQQHDAxTYW50YSBNb25pY2ExETAPBgNVBAoMCE9u\\nZUxvZ2luMRkwFwYDVQQDDBBhcHAub25lbG9naW4uY29tMIIBIjANBgkqhkiG9w0B\\nAQEFAAOCAQ8AMIIBCgKCAQEAse8rnep4qL2GmhH10pMQyJ2Jae+AQHyfgVjaQZ7Z\\n0QQog5jX91vcJRSMi0XWJnUtOr6lF0dq1+yckjZ92wyLrH+7fvngNO1aV4Mjk9sT\\ngf+iqMrae6y6fRxDt9PXrEFVjvd3vv7QTJf2FuIPy4vVP06Dt8EMkQIr8rmLmU0m\\nTr1k2DkrdtdlCuNFTXuAu3QqfvNCRrRwfNObn9MP6JeOUdcGLJsBjGF8exfcN1SF\\nzRF0JFr3dmOlx761zK5liD0T1sYWnDquatj/JD9fZMbKecBKni1NglH/LVd+b6aJ\\nUAr5LulERULUjLqYJRKW31u91/4Qazdo9tbvwqyFxaoUrwIDAQABo4HUMIHRMAwG\\nA1UdEwEB/wQCMAAwHQYDVR0OBBYEFPWcXvQSlTXnzZD2xziuoUvrrDedMIGRBgNV\\nHSMEgYkwgYaAFPWcXvQSlTXnzZD2xziuoUvrrDedoWukaTBnMQswCQYDVQQGEwJV\\nUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UEBwwMU2FudGEgTW9uaWNhMREw\\nDwYDVQQKDAhPbmVMb2dpbjEZMBcGA1UEAwwQYXBwLm9uZWxvZ2luLmNvbYIBATAO\\nBgNVHQ8BAf8EBAMCBPAwDQYJKoZIhvcNAQEFBQADggEBAB/8xe3rzqXQVxzHyAHu\\nAuPa73ClDoL1cko0Fp8CGcqEIyj6Te9gx5z6wyfv+Lo8RFvBLlnB1lXqbC+fTGcV\\ngG/4oKLJ5UwRFxInqpZPnOAudVNnd0PYOODn9FWs6u+OTIQIaIcPUv3MhB9lwHIJ\\nsTk/bs9xcru5TPyLIxLLd6ib/pRceKH2mTkzUd0DYk9CQNXXeoGx/du5B9nh3ClP\\nTbVakRzl3oswgI5MQIphYxkW70SopEh4kOFSRE1ND31NNIq1YrXlgtkguQBFsZWu\\nQOPR6cEwFZzP0tHTYbI839WgxX6hfhIUTUz6mLqq4+3P4BG3+1OXeVDg63y8Uh78\\n1sE="
          },
          "sp": {
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "entityId": "http://stuff.com/endpoints/metadata.php",
            "assertionConsumerService": {
              "url": "http://stuff.com/endpoints/endpoints/acs.php"
            },
            "singleLogoutService": {
              "url": "http://stuff.com/endpoints/endpoints/sls.php"
            }
          },
          "security": {
            "wantAssertionsSigned": false,
            "authnRequestsSigned": false,
            "signMetadata": false
          },
          "debug": false,
          "organization": {
            "en-US": {
              "displayname": "SP test",
              "url": "http://sp.example.com",
              "name": "sp_test"
            }
          },
          "strict": false
        }
        """
        expected_settings = json.loads(expected_settings_json)
        self.assertEqual(expected_settings, settings_result)

        # Commute merge operation. As the order determines which settings
        # dictionary has priority, here we expect a different result.
        settings_result2 = OneLogin_Saml2_IdPMetadataParser.merge_settings(data, settings)
        expected_settings2_json = """
        {
          "debug": false,
          "idp": {
            "singleLogoutService": {
              "url": "http://idp.example.com/SingleLogoutService.php"
            },
            "singleSignOnService": {
              "url": "http://idp.example.com/SSOService.php",
              "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            },
            "entityId": "http://idp.example.com/",
            "x509cert": "MIICgTCCAeoCCQCbOlrWDdX7FTANBgkqhkiG9w0BAQUFADCBhDELMAkGA1UEBhMCTk8xGDAWBgNVBAgTD0FuZHJlYXMgU29sYmVyZzEMMAoGA1UEBxMDRm9vMRAwDgYDVQQKEwdVTklORVRUMRgwFgYDVQQDEw9mZWlkZS5lcmxhbmcubm8xITAfBgkqhkiG9w0BCQEWEmFuZHJlYXNAdW5pbmV0dC5ubzAeFw0wNzA2MTUxMjAxMzVaFw0wNzA4MTQxMjAxMzVaMIGEMQswCQYDVQQGEwJOTzEYMBYGA1UECBMPQW5kcmVhcyBTb2xiZXJnMQwwCgYDVQQHEwNGb28xEDAOBgNVBAoTB1VOSU5FVFQxGDAWBgNVBAMTD2ZlaWRlLmVybGFuZy5ubzEhMB8GCSqGSIb3DQEJARYSYW5kcmVhc0B1bmluZXR0Lm5vMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDivbhR7P516x/S3BqKxupQe0LONoliupiBOesCO3SHbDrl3+q9IbfnfmE04rNuMcPsIxB161TdDpIesLCn7c8aPHISKOtPlAeTZSnb8QAu7aRjZq3+PbrP5uW3TcfCGPtKTytHOge/OlJbo078dVhXQ14d1EDwXJW1rRXuUt4C8QIDAQABMA0GCSqGSIb3DQEBBQUAA4GBACDVfp86HObqY+e8BUoWQ9+VMQx1ASDohBjwOsg2WykUqRXF+dLfcUH9dWR63CtZIKFDbStNomPnQz7nbK+onygwBspVEbnHuUihZq3ZUdmumQqCw4Uvs/1Uvq3orOo/WJVhTyvLgFVK2QarQ4/67OZfHd7R+POBXhophSMv1ZOo"
          },
          "security": {
            "authnRequestsSigned": false,
            "wantAssertionsSigned": false,
            "signMetadata": false
          },
          "contactPerson": {
            "technical": {
              "emailAddress": "technical@example.com",
              "givenName": "technical_name"
            },
            "support": {
              "emailAddress": "support@example.com",
              "givenName": "support_name"
            }
          },
          "strict": false,
          "sp": {
            "singleLogoutService": {
              "url": "http://stuff.com/endpoints/endpoints/sls.php"
            },
            "assertionConsumerService": {
              "url": "http://stuff.com/endpoints/endpoints/acs.php"
            },
            "entityId": "http://stuff.com/endpoints/metadata.php",
            "NameIDFormat": "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified"
          },
          "custom_base_path": "../../../tests/data/customPath/",
          "organization": {
            "en-US": {
              "displayname": "SP test",
              "url": "http://sp.example.com",
              "name": "sp_test"
            }
          }
        }
        """
        expected_settings2 = json.loads(expected_settings2_json)
        self.assertEqual(expected_settings2, settings_result2)
