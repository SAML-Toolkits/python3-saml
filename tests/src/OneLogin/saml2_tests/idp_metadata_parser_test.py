# -*- coding: utf-8 -*-

# Copyright (c) 2010-2018 OneLogin, Inc.
# MIT License

try:
    from urllib.error import URLError
except ImportError:
    from urllib2 import URLError

from copy import deepcopy
import json
from os.path import dirname, join, exists
from lxml.etree import XMLSyntaxError
import unittest

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
            data = OneLogin_Saml2_IdPMetadataParser.get_metadata('https://idp.testshib.org/idp/shibboleth')
            self.assertTrue(data is not None and data is not {})
        except URLError:
            pass

    def testParseRemote(self):
        """
        Tests the parse_remote method of the OneLogin_Saml2_IdPMetadataParser
        """
        with self.assertRaises(Exception):
            data = OneLogin_Saml2_IdPMetadataParser.parse_remote('http://google.es')

        try:
            data = OneLogin_Saml2_IdPMetadataParser.parse_remote('https://idp.testshib.org/idp/shibboleth')
        except URLError:
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
            "x509cert": "MIIDAzCCAeugAwIBAgIVAPX0G6LuoXnKS0Muei006mVSBXbvMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAMMEGlkcC50ZXN0c2hpYi5vcmcwHhcNMTYwODIzMjEyMDU0WhcNMzYwODIzMjEyMDU0WjAbMRkwFwYDVQQDDBBpZHAudGVzdHNoaWIub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAg9C4J2DiRTEhJAWzPt1S3ryhm3M2P3hPpwJwvt2q948vdTUxhhvNMuc3M3S4WNh6JYBs53R+YmjqJAII4ShMGNEmlGnSVfHorex7IxikpuDPKV3SNf28mCAZbQrX+hWA+ann/uifVzqXktOjs6DdzdBnxoVhniXgC8WCJwKcx6JO/hHsH1rG/0DSDeZFpTTcZHj4S9MlLNUtt5JxRzV/MmmB3ObaX0CMqsSWUOQeE4nylSlp5RWHCnx70cs9kwz5WrflnbnzCeHU2sdbNotBEeTHot6a2cj/pXlRJIgPsrL/4VSicPZcGYMJMPoLTJ8mdy6mpR6nbCmP7dVbCIm/DQIDAQABoz4wPDAdBgNVHQ4EFgQUUfaDa2mPi24x09yWp1OFXmZ2GPswGwYDVR0RBBQwEoIQaWRwLnRlc3RzaGliLm9yZzANBgkqhkiG9w0BAQsFAAOCAQEASKKgqTxhqBzROZ1eVy++si+eTTUQZU4+8UywSKLia2RattaAPMAcXUjO+3cYOQXLVASdlJtt+8QPdRkfp8SiJemHPXC8BES83pogJPYEGJsKo19l4XFJHPnPy+Dsn3mlJyOfAa8RyWBS80u5lrvAcr2TJXt9fXgkYs7BOCigxtZoR8flceGRlAZ4p5FPPxQR6NDYb645jtOTMVr3zgfjP6Wh2dt+2p04LG7ENJn8/gEwtXVuXCsPoSCDx9Y0QmyXTJNdV1aB0AhORkWPlFYwp+zOyOIR+3m1+pqWFpn0eT/HrxpdKa74FA3R2kq4R7dXe4G0kUgXTdqXMLRKhDgdmA==",
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
            "x509cert": "MIIEHjCCAwagAwIBAgIBATANBgkqhkiG9w0BAQUFADBnMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UEBwwMU2FudGEgTW9uaWNhMREwDwYDVQQKDAhPbmVMb2dpbjEZMBcGA1UEAwwQYXBwLm9uZWxvZ2luLmNvbTAeFw0xMzA2MDUxNzE2MjBaFw0xODA2MDUxNzE2MjBaMGcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQHDAxTYW50YSBNb25pY2ExETAPBgNVBAoMCE9uZUxvZ2luMRkwFwYDVQQDDBBhcHAub25lbG9naW4uY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAse8rnep4qL2GmhH10pMQyJ2Jae+AQHyfgVjaQZ7Z0QQog5jX91vcJRSMi0XWJnUtOr6lF0dq1+yckjZ92wyLrH+7fvngNO1aV4Mjk9sTgf+iqMrae6y6fRxDt9PXrEFVjvd3vv7QTJf2FuIPy4vVP06Dt8EMkQIr8rmLmU0mTr1k2DkrdtdlCuNFTXuAu3QqfvNCRrRwfNObn9MP6JeOUdcGLJsBjGF8exfcN1SFzRF0JFr3dmOlx761zK5liD0T1sYWnDquatj/JD9fZMbKecBKni1NglH/LVd+b6aJUAr5LulERULUjLqYJRKW31u91/4Qazdo9tbvwqyFxaoUrwIDAQABo4HUMIHRMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFPWcXvQSlTXnzZD2xziuoUvrrDedMIGRBgNVHSMEgYkwgYaAFPWcXvQSlTXnzZD2xziuoUvrrDedoWukaTBnMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UEBwwMU2FudGEgTW9uaWNhMREwDwYDVQQKDAhPbmVMb2dpbjEZMBcGA1UEAwwQYXBwLm9uZWxvZ2luLmNvbYIBATAOBgNVHQ8BAf8EBAMCBPAwDQYJKoZIhvcNAQEFBQADggEBAB/8xe3rzqXQVxzHyAHuAuPa73ClDoL1cko0Fp8CGcqEIyj6Te9gx5z6wyfv+Lo8RFvBLlnB1lXqbC+fTGcVgG/4oKLJ5UwRFxInqpZPnOAudVNnd0PYOODn9FWs6u+OTIQIaIcPUv3MhB9lwHIJsTk/bs9xcru5TPyLIxLLd6ib/pRceKH2mTkzUd0DYk9CQNXXeoGx/du5B9nh3ClPTbVakRzl3oswgI5MQIphYxkW70SopEh4kOFSRE1ND31NNIq1YrXlgtkguQBFsZWuQOPR6cEwFZzP0tHTYbI839WgxX6hfhIUTUz6mLqq4+3P4BG3+1OXeVDg63y8Uh781sE=",
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
            "x509cert": "MIIDAzCCAeugAwIBAgIVAPX0G6LuoXnKS0Muei006mVSBXbvMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAMMEGlkcC50ZXN0c2hpYi5vcmcwHhcNMTYwODIzMjEyMDU0WhcNMzYwODIzMjEyMDU0WjAbMRkwFwYDVQQDDBBpZHAudGVzdHNoaWIub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAg9C4J2DiRTEhJAWzPt1S3ryhm3M2P3hPpwJwvt2q948vdTUxhhvNMuc3M3S4WNh6JYBs53R+YmjqJAII4ShMGNEmlGnSVfHorex7IxikpuDPKV3SNf28mCAZbQrX+hWA+ann/uifVzqXktOjs6DdzdBnxoVhniXgC8WCJwKcx6JO/hHsH1rG/0DSDeZFpTTcZHj4S9MlLNUtt5JxRzV/MmmB3ObaX0CMqsSWUOQeE4nylSlp5RWHCnx70cs9kwz5WrflnbnzCeHU2sdbNotBEeTHot6a2cj/pXlRJIgPsrL/4VSicPZcGYMJMPoLTJ8mdy6mpR6nbCmP7dVbCIm/DQIDAQABoz4wPDAdBgNVHQ4EFgQUUfaDa2mPi24x09yWp1OFXmZ2GPswGwYDVR0RBBQwEoIQaWRwLnRlc3RzaGliLm9yZzANBgkqhkiG9w0BAQsFAAOCAQEASKKgqTxhqBzROZ1eVy++si+eTTUQZU4+8UywSKLia2RattaAPMAcXUjO+3cYOQXLVASdlJtt+8QPdRkfp8SiJemHPXC8BES83pogJPYEGJsKo19l4XFJHPnPy+Dsn3mlJyOfAa8RyWBS80u5lrvAcr2TJXt9fXgkYs7BOCigxtZoR8flceGRlAZ4p5FPPxQR6NDYb645jtOTMVr3zgfjP6Wh2dt+2p04LG7ENJn8/gEwtXVuXCsPoSCDx9Y0QmyXTJNdV1aB0AhORkWPlFYwp+zOyOIR+3m1+pqWFpn0eT/HrxpdKa74FA3R2kq4R7dXe4G0kUgXTdqXMLRKhDgdmA==",
            "singleSignOnService": {
              "url": "https://idp.testshib.org/idp/profile/SAML2/Redirect/SSO",
              "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            }
          }
        }
        """
        try:
            xmldoc = OneLogin_Saml2_IdPMetadataParser.get_metadata(
                'https://idp.testshib.org/idp/shibboleth')
        except URLError:
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
            "x509cert": "MIIDAzCCAeugAwIBAgIVAPX0G6LuoXnKS0Muei006mVSBXbvMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAMMEGlkcC50ZXN0c2hpYi5vcmcwHhcNMTYwODIzMjEyMDU0WhcNMzYwODIzMjEyMDU0WjAbMRkwFwYDVQQDDBBpZHAudGVzdHNoaWIub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAg9C4J2DiRTEhJAWzPt1S3ryhm3M2P3hPpwJwvt2q948vdTUxhhvNMuc3M3S4WNh6JYBs53R+YmjqJAII4ShMGNEmlGnSVfHorex7IxikpuDPKV3SNf28mCAZbQrX+hWA+ann/uifVzqXktOjs6DdzdBnxoVhniXgC8WCJwKcx6JO/hHsH1rG/0DSDeZFpTTcZHj4S9MlLNUtt5JxRzV/MmmB3ObaX0CMqsSWUOQeE4nylSlp5RWHCnx70cs9kwz5WrflnbnzCeHU2sdbNotBEeTHot6a2cj/pXlRJIgPsrL/4VSicPZcGYMJMPoLTJ8mdy6mpR6nbCmP7dVbCIm/DQIDAQABoz4wPDAdBgNVHQ4EFgQUUfaDa2mPi24x09yWp1OFXmZ2GPswGwYDVR0RBBQwEoIQaWRwLnRlc3RzaGliLm9yZzANBgkqhkiG9w0BAQsFAAOCAQEASKKgqTxhqBzROZ1eVy++si+eTTUQZU4+8UywSKLia2RattaAPMAcXUjO+3cYOQXLVASdlJtt+8QPdRkfp8SiJemHPXC8BES83pogJPYEGJsKo19l4XFJHPnPy+Dsn3mlJyOfAa8RyWBS80u5lrvAcr2TJXt9fXgkYs7BOCigxtZoR8flceGRlAZ4p5FPPxQR6NDYb645jtOTMVr3zgfjP6Wh2dt+2p04LG7ENJn8/gEwtXVuXCsPoSCDx9Y0QmyXTJNdV1aB0AhORkWPlFYwp+zOyOIR+3m1+pqWFpn0eT/HrxpdKa74FA3R2kq4R7dXe4G0kUgXTdqXMLRKhDgdmA==",
            "singleSignOnService": {
              "url": "https://idp.testshib.org/idp/profile/SAML2/POST/SSO",
              "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            }
          }
        }
        """
        try:
            xmldoc = OneLogin_Saml2_IdPMetadataParser.get_metadata(
                'https://idp.testshib.org/idp/shibboleth')
        except URLError:
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

    def test_parse_with_entity_id(self):
        """
        Tests the parse method of the OneLogin_Saml2_IdPMetadataParser
        Case: Provide entity_id to identify the desired IdPDescriptor from
              EntitiesDescriptor
        """
        xml_idp_metadata = self.file_contents(join(self.data_path, 'metadata', 'idp_multiple_descriptors.xml'))

        # should find first descriptor
        data = OneLogin_Saml2_IdPMetadataParser.parse(xml_idp_metadata)
        self.assertEqual("https://foo.example.com/access/saml/idp.xml", data["idp"]["entityId"])

        # should find desired descriptor
        data2 = OneLogin_Saml2_IdPMetadataParser.parse(xml_idp_metadata, entity_id="https://bar.example.com/access/saml/idp.xml")
        self.assertEqual("https://bar.example.com/access/saml/idp.xml", data2["idp"]["entityId"])

        expected_settings_json = """
        {
            "sp": {
                "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
            },
            "idp": {
                "singleLogoutService": {
                    "url": "https://hello.example.com/access/saml/logout",
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                },
                "entityId": "https://bar.example.com/access/saml/idp.xml",
                "x509cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURxekNDQXhTZ0F3SUJBZ0lCQVRBTkJna3Foa2lHOXcwQkFRc0ZBRENCaGpFTE1Ba0dBMVVFQmhNQ1FWVXgKRERBS0JnTlZCQWdUQTA1VFZ6RVBNQTBHQTFVRUJ4TUdVM2xrYm1WNU1Rd3dDZ1lEVlFRS0RBTlFTVlF4Q1RBSApCZ05WQkFzTUFERVlNQllHQTFVRUF3d1BiR0YzY21WdVkyVndhWFF1WTI5dE1TVXdJd1lKS29aSWh2Y05BUWtCCkRCWnNZWGR5Wlc1alpTNXdhWFJBWjIxaGFXd3VZMjl0TUI0WERURXlNRFF4T1RJeU5UUXhPRm9YRFRNeU1EUXgKTkRJeU5UUXhPRm93Z1lZeEN6QUpCZ05WQkFZVEFrRlZNUXd3Q2dZRFZRUUlFd05PVTFjeER6QU5CZ05WQkFjVApCbE41Wkc1bGVURU1NQW9HQTFVRUNnd0RVRWxVTVFrd0J3WURWUVFMREFBeEdEQVdCZ05WQkFNTUQyeGhkM0psCmJtTmxjR2wwTG1OdmJURWxNQ01HQ1NxR1NJYjNEUUVKQVF3V2JHRjNjbVZ1WTJVdWNHbDBRR2R0WVdsc0xtTnYKYlRDQm56QU5CZ2txaGtpRzl3MEJBUUVGQUFPQmpRQXdnWWtDZ1lFQXFqaWUzUjJvaStwRGFldndJeXMvbWJVVApubkdsa3h0ZGlrcnExMXZleHd4SmlQTmhtaHFSVzNtVXVKRXpsbElkVkw2RW14R1lUcXBxZjkzSGxoa3NhZUowCjhVZ2pQOVVtTVlyaFZKdTFqY0ZXVjdmei9yKzIxL2F3VG5EVjlzTVlRcXVJUllZeTdiRzByMU9iaXdkb3ZudGsKN2dGSTA2WjB2WmFjREU1Ym9xVUNBd0VBQWFPQ0FTVXdnZ0VoTUFrR0ExVWRFd1FDTUFBd0N3WURWUjBQQkFRRApBZ1VnTUIwR0ExVWREZ1FXQkJTUk9OOEdKOG8rOGpnRnRqa3R3WmRxeDZCUnlUQVRCZ05WSFNVRUREQUtCZ2dyCkJnRUZCUWNEQVRBZEJnbGdoa2dCaHZoQ0FRMEVFQllPVkdWemRDQllOVEE1SUdObGNuUXdnYk1HQTFVZEl3U0IKcXpDQnFJQVVrVGpmQmlmS1B2STRCYlk1TGNHWGFzZWdVY21oZ1l5a2dZa3dnWVl4Q3pBSkJnTlZCQVlUQWtGVgpNUXd3Q2dZRFZRUUlFd05PVTFjeER6QU5CZ05WQkFjVEJsTjVaRzVsZVRFTU1Bb0dBMVVFQ2d3RFVFbFVNUWt3CkJ3WURWUVFMREFBeEdEQVdCZ05WQkFNTUQyeGhkM0psYm1ObGNHbDBMbU52YlRFbE1DTUdDU3FHU0liM0RRRUoKQVF3V2JHRjNjbVZ1WTJVdWNHbDBRR2R0WVdsc0xtTnZiWUlCQVRBTkJna3Foa2lHOXcwQkFRc0ZBQU9CZ1FDRQpUQWVKVERTQVc2ejFVRlRWN1FyZWg0VUxGT1JhajkrZUN1RjNLV0RIYyswSVFDajlyZG5ERzRRL3dmNy9yYVEwCkpuUFFDU0NkclBMSmV5b1BIN1FhVHdvYUY3ZHpWdzRMQ3N5TkpURld4NGNNNTBWdzZSNWZET2dpQzhic2ZmUzgKQkptb3VscnJaRE5OVmpHOG1XNmNMeHJZdlZRT3JSVmVjQ0ZJZ3NzQ2JBPT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=",
                "singleSignOnService": {
                    "url": "https://hello.example.com/access/saml/login",
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                }
            }
        }
        """
        expected_settings = json.loads(expected_settings_json)
        self.assertEqual(expected_settings, data2)

    def test_parse_multi_certs(self):
        """
        Tests the parse method of the OneLogin_Saml2_IdPMetadataParser
        Case: IdP metadata contains multiple certs
        """
        xml_idp_metadata = self.file_contents(join(self.data_path, 'metadata', 'idp_metadata_multi_certs.xml'))
        data = OneLogin_Saml2_IdPMetadataParser.parse(xml_idp_metadata)

        expected_settings_json = """
        {
            "sp": {
                "NameIDFormat": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
            },
            "idp": {
                "singleLogoutService": {
                    "url": "https://idp.examle.com/saml/slo",
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                },
                "x509certMulti": {
                    "encryption": [
                        "MIIEZTCCA02gAwIBAgIUPyy/A3bZAZ4m28PzEUUoT7RJhxIwDQYJKoZIhvcNAQEFBQAwcjELMAkGA1UEBhMCVVMxKzApBgNVBAoMIk9uZUxvZ2luIFRlc3QgKHNnYXJjaWEtdXMtcHJlcHJvZCkxFTATBgNVBAsMDE9uZUxvZ2luIElkUDEfMB0GA1UEAwwWT25lTG9naW4gQWNjb3VudCA4OTE0NjAeFw0xNjA4MDQyMjI5MzdaFw0yMTA4MDUyMjI5MzdaMHIxCzAJBgNVBAYTAlVTMSswKQYDVQQKDCJPbmVMb2dpbiBUZXN0IChzZ2FyY2lhLXVzLXByZXByb2QpMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgODkxNDYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDN6iqQGcLOCglNO42I2rkzE05UXSiMXT6c8ALThMMiaDw6qqzo3sd/tKK+NcNKWLIIC8TozWVyh5ykUiVZps+08xil7VsTU7E+wKu3kvmOsvw2wlRwtnoKZJwYhnr+RkBa+h1r3ZYUgXm1ZPeHMKj1g18KaWz9+MxYL6BhKqrOzfW/P2xxVRcFH7/pq+ZsDdgNzD2GD+apzY4MZyZj/N6BpBWJ0GlFsmtBegpbX3LBitJuFkk5L4/U/jjF1AJa3boBdCUVfATqO5G03H4XS1GySjBIRQXmlUF52rLjg6xCgWJ30/+t1X+IHLJeixiQ0vxyh6C4/usCEt94cgD1r8ADAgMBAAGjgfIwge8wDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUPW0DcH0G3IwynWgi74co4wZ6n7gwga8GA1UdIwSBpzCBpIAUPW0DcH0G3IwynWgi74co4wZ6n7ihdqR0MHIxCzAJBgNVBAYTAlVTMSswKQYDVQQKDCJPbmVMb2dpbiBUZXN0IChzZ2FyY2lhLXVzLXByZXByb2QpMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgODkxNDaCFD8svwN22QGeJtvD8xFFKE+0SYcSMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQUFAAOCAQEAQhB4q9jrycwbHrDSoYR1X4LFFzvJ9Us75wQquRHXpdyS9D6HUBXMGI6ahPicXCQrfLgN8vzMIiqZqfySXXv/8/dxe/X4UsWLYKYJHDJmxXD5EmWTa65chjkeP1oJAc8f3CKCpcP2lOBTthbnk2fEVAeLHR4xNdQO0VvGXWO9BliYPpkYqUIBvlm+Fg9mF7AM/Uagq2503XXIE1Lq//HON68P10vNMwLSKOtYLsoTiCnuIKGJqG37MsZVjQ1ZPRcO+LSLkq0i91gFxrOrVCrgztX4JQi5XkvEsYZGIXXjwHqxTVyt3adZWQO0LPxPqRiUqUzyhDhLo/xXNrHCu4VbMw=="
                    ],
                    "signing": [
                        "MIIEZTCCA02gAwIBAgIUPyy/A3bZAZ4m28PzEUUoT7RJhxIwDQYJKoZIhvcNAQEFBQAwcjELMAkGA1UEBhMCVVMxKzApBgNVBAoMIk9uZUxvZ2luIFRlc3QgKHNnYXJjaWEtdXMtcHJlcHJvZCkxFTATBgNVBAsMDE9uZUxvZ2luIElkUDEfMB0GA1UEAwwWT25lTG9naW4gQWNjb3VudCA4OTE0NjAeFw0xNjA4MDQyMjI5MzdaFw0yMTA4MDUyMjI5MzdaMHIxCzAJBgNVBAYTAlVTMSswKQYDVQQKDCJPbmVMb2dpbiBUZXN0IChzZ2FyY2lhLXVzLXByZXByb2QpMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgODkxNDYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDN6iqQGcLOCglNO42I2rkzE05UXSiMXT6c8ALThMMiaDw6qqzo3sd/tKK+NcNKWLIIC8TozWVyh5ykUiVZps+08xil7VsTU7E+wKu3kvmOsvw2wlRwtnoKZJwYhnr+RkBa+h1r3ZYUgXm1ZPeHMKj1g18KaWz9+MxYL6BhKqrOzfW/P2xxVRcFH7/pq+ZsDdgNzD2GD+apzY4MZyZj/N6BpBWJ0GlFsmtBegpbX3LBitJuFkk5L4/U/jjF1AJa3boBdCUVfATqO5G03H4XS1GySjBIRQXmlUF52rLjg6xCgWJ30/+t1X+IHLJeixiQ0vxyh6C4/usCEt94cgD1r8ADAgMBAAGjgfIwge8wDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUPW0DcH0G3IwynWgi74co4wZ6n7gwga8GA1UdIwSBpzCBpIAUPW0DcH0G3IwynWgi74co4wZ6n7ihdqR0MHIxCzAJBgNVBAYTAlVTMSswKQYDVQQKDCJPbmVMb2dpbiBUZXN0IChzZ2FyY2lhLXVzLXByZXByb2QpMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgODkxNDaCFD8svwN22QGeJtvD8xFFKE+0SYcSMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQUFAAOCAQEAQhB4q9jrycwbHrDSoYR1X4LFFzvJ9Us75wQquRHXpdyS9D6HUBXMGI6ahPicXCQrfLgN8vzMIiqZqfySXXv/8/dxe/X4UsWLYKYJHDJmxXD5EmWTa65chjkeP1oJAc8f3CKCpcP2lOBTthbnk2fEVAeLHR4xNdQO0VvGXWO9BliYPpkYqUIBvlm+Fg9mF7AM/Uagq2503XXIE1Lq//HON68P10vNMwLSKOtYLsoTiCnuIKGJqG37MsZVjQ1ZPRcO+LSLkq0i91gFxrOrVCrgztX4JQi5XkvEsYZGIXXjwHqxTVyt3adZWQO0LPxPqRiUqUzyhDhLo/xXNrHCu4VbMw==",
                        "MIICZDCCAc2gAwIBAgIBADANBgkqhkiG9w0BAQ0FADBPMQswCQYDVQQGEwJ1czEUMBIGA1UECAwLZXhhbXBsZS5jb20xFDASBgNVBAoMC2V4YW1wbGUuY29tMRQwEgYDVQQDDAtleGFtcGxlLmNvbTAeFw0xNzA0MTUxNjMzMThaFw0xODA0MTUxNjMzMThaME8xCzAJBgNVBAYTAnVzMRQwEgYDVQQIDAtleGFtcGxlLmNvbTEUMBIGA1UECgwLZXhhbXBsZS5jb20xFDASBgNVBAMMC2V4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC6GLkl5lDUZdHNDAojp5i24OoPlqrt5TGXJIPqAZYT1hQvJW5nv17MFDHrjmtEnmW4ACKEy0fAX80QWIcHunZSkbEGHb+NG/6oTi5RipXMvmHnfFnPJJ0AdtiLiPE478CV856gXekV4Xx5u3KrylcOgkpYsp0GMIQBDzleMUXlYQIDAQABo1AwTjAdBgNVHQ4EFgQUnP8vlYPGPL2n6ZzDYij2kMDC8wMwHwYDVR0jBBgwFoAUnP8vlYPGPL2n6ZzDYij2kMDC8wMwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQAlQGAl+b8Cpot1g+65lLLjVoY7APJPWLW0klKQNlMU0s4MU+71Y3ExUEOXDAZgKcFoavb1fEOGMwEf38NaJAy1e/l6VNuixXShffq20ymqHQxOG0q8ujeNkgZF9k6XDfn/QZ3AD0o/IrCT7UMc/0QsfgIjWYxwCvp2syApc5CYfQ=="
                    ]
                },
                "entityId": "https://idp.examle.com/saml/metadata",
                "singleSignOnService": {
                    "url": "https://idp.examle.com/saml/sso",
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                }
            }
        }
        """
        expected_settings = json.loads(expected_settings_json)
        self.assertEqual(expected_settings, data)

    def test_parse_multi_singing_certs(self):
        """
        Tests the parse method of the OneLogin_Saml2_IdPMetadataParser
        Case: IdP metadata contains multiple signing certs and no encryption certs
        """
        xml_idp_metadata = self.file_contents(join(self.data_path, 'metadata', 'idp_metadata_multi_signing_certs.xml'))
        data = OneLogin_Saml2_IdPMetadataParser.parse(xml_idp_metadata)

        expected_settings_json = """
        {
            "sp": {
                "NameIDFormat": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
            },
            "idp": {
                "singleLogoutService": {
                    "url": "https://idp.examle.com/saml/slo",
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                },
                "x509certMulti": {
                    "signing": [
                        "MIIEZTCCA02gAwIBAgIUPyy/A3bZAZ4m28PzEUUoT7RJhxIwDQYJKoZIhvcNAQEFBQAwcjELMAkGA1UEBhMCVVMxKzApBgNVBAoMIk9uZUxvZ2luIFRlc3QgKHNnYXJjaWEtdXMtcHJlcHJvZCkxFTATBgNVBAsMDE9uZUxvZ2luIElkUDEfMB0GA1UEAwwWT25lTG9naW4gQWNjb3VudCA4OTE0NjAeFw0xNjA4MDQyMjI5MzdaFw0yMTA4MDUyMjI5MzdaMHIxCzAJBgNVBAYTAlVTMSswKQYDVQQKDCJPbmVMb2dpbiBUZXN0IChzZ2FyY2lhLXVzLXByZXByb2QpMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgODkxNDYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDN6iqQGcLOCglNO42I2rkzE05UXSiMXT6c8ALThMMiaDw6qqzo3sd/tKK+NcNKWLIIC8TozWVyh5ykUiVZps+08xil7VsTU7E+wKu3kvmOsvw2wlRwtnoKZJwYhnr+RkBa+h1r3ZYUgXm1ZPeHMKj1g18KaWz9+MxYL6BhKqrOzfW/P2xxVRcFH7/pq+ZsDdgNzD2GD+apzY4MZyZj/N6BpBWJ0GlFsmtBegpbX3LBitJuFkk5L4/U/jjF1AJa3boBdCUVfATqO5G03H4XS1GySjBIRQXmlUF52rLjg6xCgWJ30/+t1X+IHLJeixiQ0vxyh6C4/usCEt94cgD1r8ADAgMBAAGjgfIwge8wDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUPW0DcH0G3IwynWgi74co4wZ6n7gwga8GA1UdIwSBpzCBpIAUPW0DcH0G3IwynWgi74co4wZ6n7ihdqR0MHIxCzAJBgNVBAYTAlVTMSswKQYDVQQKDCJPbmVMb2dpbiBUZXN0IChzZ2FyY2lhLXVzLXByZXByb2QpMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgODkxNDaCFD8svwN22QGeJtvD8xFFKE+0SYcSMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQUFAAOCAQEAQhB4q9jrycwbHrDSoYR1X4LFFzvJ9Us75wQquRHXpdyS9D6HUBXMGI6ahPicXCQrfLgN8vzMIiqZqfySXXv/8/dxe/X4UsWLYKYJHDJmxXD5EmWTa65chjkeP1oJAc8f3CKCpcP2lOBTthbnk2fEVAeLHR4xNdQO0VvGXWO9BliYPpkYqUIBvlm+Fg9mF7AM/Uagq2503XXIE1Lq//HON68P10vNMwLSKOtYLsoTiCnuIKGJqG37MsZVjQ1ZPRcO+LSLkq0i91gFxrOrVCrgztX4JQi5XkvEsYZGIXXjwHqxTVyt3adZWQO0LPxPqRiUqUzyhDhLo/xXNrHCu4VbMw==",
                        "MIICZDCCAc2gAwIBAgIBADANBgkqhkiG9w0BAQ0FADBPMQswCQYDVQQGEwJ1czEUMBIGA1UECAwLZXhhbXBsZS5jb20xFDASBgNVBAoMC2V4YW1wbGUuY29tMRQwEgYDVQQDDAtleGFtcGxlLmNvbTAeFw0xNzA0MTUxNjMzMThaFw0xODA0MTUxNjMzMThaME8xCzAJBgNVBAYTAnVzMRQwEgYDVQQIDAtleGFtcGxlLmNvbTEUMBIGA1UECgwLZXhhbXBsZS5jb20xFDASBgNVBAMMC2V4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC6GLkl5lDUZdHNDAojp5i24OoPlqrt5TGXJIPqAZYT1hQvJW5nv17MFDHrjmtEnmW4ACKEy0fAX80QWIcHunZSkbEGHb+NG/6oTi5RipXMvmHnfFnPJJ0AdtiLiPE478CV856gXekV4Xx5u3KrylcOgkpYsp0GMIQBDzleMUXlYQIDAQABo1AwTjAdBgNVHQ4EFgQUnP8vlYPGPL2n6ZzDYij2kMDC8wMwHwYDVR0jBBgwFoAUnP8vlYPGPL2n6ZzDYij2kMDC8wMwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQAlQGAl+b8Cpot1g+65lLLjVoY7APJPWLW0klKQNlMU0s4MU+71Y3ExUEOXDAZgKcFoavb1fEOGMwEf38NaJAy1e/l6VNuixXShffq20ymqHQxOG0q8ujeNkgZF9k6XDfn/QZ3AD0o/IrCT7UMc/0QsfgIjWYxwCvp2syApc5CYfQ==",
                        "MIIEZTCCA02gAwIBAgIUPyy/A3bZAZ4m28PzEUUoT7RJhxIwDQYJKoZIhvcNAQEFBQAwcjELMAkGA1UEBhMCVVMxKzApBgNVBAoMIk9uZUxvZ2luIFRlc3QgKHNnYXJjaWEtdXMtcHJlcHJvZCkxFTATBgNVBAsMDE9uZUxvZ2luIElkUDEfMB0GA1UEAwwWT25lTG9naW4gQWNjb3VudCA4OTE0NjAeFw0xNjA4MDQyMjI5MzdaFw0yMTA4MDUyMjI5MzdaMHIxCzAJBgNVBAYTAlVTMSswKQYDVQQKDCJPbmVMb2dpbiBUZXN0IChzZ2FyY2lhLXVzLXByZXByb2QpMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgODkxNDYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDN6iqQGcLOCglNO42I2rkzE05UXSiMXT6c8ALThMMiaDw6qqzo3sd/tKK+NcNKWLIIC8TozWVyh5ykUiVZps+08xil7VsTU7E+wKu3kvmOsvw2wlRwtnoKZJwYhnr+RkBa+h1r3ZYUgXm1ZPeHMKj1g18KaWz9+MxYL6BhKqrOzfW/P2xxVRcFH7/pq+ZsDdgNzD2GD+apzY4MZyZj/N6BpBWJ0GlFsmtBegpbX3LBitJuFkk5L4/U/jjF1AJa3boBdCUVfATqO5G03H4XS1GySjBIRQXmlUF52rLjg6xCgWJ30/+t1X+IHLJeixiQ0vxyh6C4/usCEt94cgD1r8ADAgMBAAGjgfIwge8wDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUPW0DcH0G3IwynWgi74co4wZ6n7gwga8GA1UdIwSBpzCBpIAUPW0DcH0G3IwynWgi74co4wZ6n7ihdqR0MHIxCzAJBgNVBAYTAlVTMSswKQYDVQQKDCJPbmVMb2dpbiBUZXN0IChzZ2FyY2lhLXVzLXByZXByb2QpMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgODkxNDaCFD8svwN22QGeJtvD8xFFKE+0SYcSMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQUFAAOCAQEAQhB4q9jrycwbHrDSoYR1X4LFFzvJ9Us75wQquRHXpdyS9D6HUBXMGI6ahPicXCQrfLgN8vzMIiqZqfySXXv/8/dxe/X4UsWLYKYJHDJmxXD5EmWTa65chjkeP1oJAc8f3CKCpcP2lOBTthbnk2fEVAeLHR4xNdQO0VvGXWO9BliYPpkYqUIBvlm+Fg9mF7AM/Uagq2503XXIE1Lq//HON68P10vNMwLSKOtYLsoTiCnuIKGJqG37MsZVjQ1ZPRcO+LSLkq0i91gFxrOrVCrgztX4JQi5XkvEsYZGIXXjwHqxTVyt3adZWQO0LPxPqRiUqUzyhDhLo/xXNrHCu4VbMw=="
                    ]
                },
                "entityId": "https://idp.examle.com/saml/metadata",
                "singleSignOnService": {
                    "url": "https://idp.examle.com/saml/sso",
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                }
            }
        }
        """
        expected_settings = json.loads(expected_settings_json)
        self.assertEqual(expected_settings, data)

    def test_parse_multi_same_signing_and_encrypt_cert(self):
        """
        Tests the parse method of the OneLogin_Saml2_IdPMetadataParser
        Case: IdP metadata contains multiple signature cert and encrypt cert
              that is the same
        """
        xml_idp_metadata = self.file_contents(join(self.data_path, 'metadata', 'idp_metadata_same_sign_and_encrypt_cert.xml'))
        data = OneLogin_Saml2_IdPMetadataParser.parse(xml_idp_metadata)

        expected_settings_json = """
        {
            "sp": {
                "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
            },
            "idp": {
                "x509cert": "MIIEHjCCAwagAwIBAgIBATANBgkqhkiG9w0BAQUFADBnMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UEBwwMU2FudGEgTW9uaWNhMREwDwYDVQQKDAhPbmVMb2dpbjEZMBcGA1UEAwwQYXBwLm9uZWxvZ2luLmNvbTAeFw0xMzA2MDUxNzE2MjBaFw0xODA2MDUxNzE2MjBaMGcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQHDAxTYW50YSBNb25pY2ExETAPBgNVBAoMCE9uZUxvZ2luMRkwFwYDVQQDDBBhcHAub25lbG9naW4uY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAse8rnep4qL2GmhH10pMQyJ2Jae+AQHyfgVjaQZ7Z0QQog5jX91vcJRSMi0XWJnUtOr6lF0dq1+yckjZ92wyLrH+7fvngNO1aV4Mjk9sTgf+iqMrae6y6fRxDt9PXrEFVjvd3vv7QTJf2FuIPy4vVP06Dt8EMkQIr8rmLmU0mTr1k2DkrdtdlCuNFTXuAu3QqfvNCRrRwfNObn9MP6JeOUdcGLJsBjGF8exfcN1SFzRF0JFr3dmOlx761zK5liD0T1sYWnDquatj/JD9fZMbKecBKni1NglH/LVd+b6aJUAr5LulERULUjLqYJRKW31u91/4Qazdo9tbvwqyFxaoUrwIDAQABo4HUMIHRMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFPWcXvQSlTXnzZD2xziuoUvrrDedMIGRBgNVHSMEgYkwgYaAFPWcXvQSlTXnzZD2xziuoUvrrDedoWukaTBnMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UEBwwMU2FudGEgTW9uaWNhMREwDwYDVQQKDAhPbmVMb2dpbjEZMBcGA1UEAwwQYXBwLm9uZWxvZ2luLmNvbYIBATAOBgNVHQ8BAf8EBAMCBPAwDQYJKoZIhvcNAQEFBQADggEBAB/8xe3rzqXQVxzHyAHuAuPa73ClDoL1cko0Fp8CGcqEIyj6Te9gx5z6wyfv+Lo8RFvBLlnB1lXqbC+fTGcVgG/4oKLJ5UwRFxInqpZPnOAudVNnd0PYOODn9FWs6u+OTIQIaIcPUv3MhB9lwHIJsTk/bs9xcru5TPyLIxLLd6ib/pRceKH2mTkzUd0DYk9CQNXXeoGx/du5B9nh3ClPTbVakRzl3oswgI5MQIphYxkW70SopEh4kOFSRE1ND31NNIq1YrXlgtkguQBFsZWuQOPR6cEwFZzP0tHTYbI839WgxX6hfhIUTUz6mLqq4+3P4BG3+1OXeVDg63y8Uh781sE=",
                "entityId": "https://app.onelogin.com/saml/metadata/383123",
                "singleSignOnService": {
                    "url": "https://app.onelogin.com/trust/saml2/http-post/sso/383123",
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                }
            }
        }
        """
        expected_settings = json.loads(expected_settings_json)
        self.assertEqual(expected_settings, data)

        xml_idp_metadata_2 = self.file_contents(join(self.data_path, 'metadata', 'idp_metadata_different_sign_and_encrypt_cert.xml'))
        data_2 = OneLogin_Saml2_IdPMetadataParser.parse(xml_idp_metadata_2)
        expected_settings_json_2 = """
        {
            "sp": {
                "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
            },
            "idp": {
                "x509certMulti": {
                    "encryption": [
                        "MIIEZTCCA02gAwIBAgIUPyy/A3bZAZ4m28PzEUUoT7RJhxIwDQYJKoZIhvcNAQEFBQAwcjELMAkGA1UEBhMCVVMxKzApBgNVBAoMIk9uZUxvZ2luIFRlc3QgKHNnYXJjaWEtdXMtcHJlcHJvZCkxFTATBgNVBAsMDE9uZUxvZ2luIElkUDEfMB0GA1UEAwwWT25lTG9naW4gQWNjb3VudCA4OTE0NjAeFw0xNjA4MDQyMjI5MzdaFw0yMTA4MDUyMjI5MzdaMHIxCzAJBgNVBAYTAlVTMSswKQYDVQQKDCJPbmVMb2dpbiBUZXN0IChzZ2FyY2lhLXVzLXByZXByb2QpMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgODkxNDYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDN6iqQGcLOCglNO42I2rkzE05UXSiMXT6c8ALThMMiaDw6qqzo3sd/tKK+NcNKWLIIC8TozWVyh5ykUiVZps+08xil7VsTU7E+wKu3kvmOsvw2wlRwtnoKZJwYhnr+RkBa+h1r3ZYUgXm1ZPeHMKj1g18KaWz9+MxYL6BhKqrOzfW/P2xxVRcFH7/pq+ZsDdgNzD2GD+apzY4MZyZj/N6BpBWJ0GlFsmtBegpbX3LBitJuFkk5L4/U/jjF1AJa3boBdCUVfATqO5G03H4XS1GySjBIRQXmlUF52rLjg6xCgWJ30/+t1X+IHLJeixiQ0vxyh6C4/usCEt94cgD1r8ADAgMBAAGjgfIwge8wDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUPW0DcH0G3IwynWgi74co4wZ6n7gwga8GA1UdIwSBpzCBpIAUPW0DcH0G3IwynWgi74co4wZ6n7ihdqR0MHIxCzAJBgNVBAYTAlVTMSswKQYDVQQKDCJPbmVMb2dpbiBUZXN0IChzZ2FyY2lhLXVzLXByZXByb2QpMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgODkxNDaCFD8svwN22QGeJtvD8xFFKE+0SYcSMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQUFAAOCAQEAQhB4q9jrycwbHrDSoYR1X4LFFzvJ9Us75wQquRHXpdyS9D6HUBXMGI6ahPicXCQrfLgN8vzMIiqZqfySXXv/8/dxe/X4UsWLYKYJHDJmxXD5EmWTa65chjkeP1oJAc8f3CKCpcP2lOBTthbnk2fEVAeLHR4xNdQO0VvGXWO9BliYPpkYqUIBvlm+Fg9mF7AM/Uagq2503XXIE1Lq//HON68P10vNMwLSKOtYLsoTiCnuIKGJqG37MsZVjQ1ZPRcO+LSLkq0i91gFxrOrVCrgztX4JQi5XkvEsYZGIXXjwHqxTVyt3adZWQO0LPxPqRiUqUzyhDhLo/xXNrHCu4VbMw=="
                    ],
                    "signing": [
                        "MIIEHjCCAwagAwIBAgIBATANBgkqhkiG9w0BAQUFADBnMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UEBwwMU2FudGEgTW9uaWNhMREwDwYDVQQKDAhPbmVMb2dpbjEZMBcGA1UEAwwQYXBwLm9uZWxvZ2luLmNvbTAeFw0xMzA2MDUxNzE2MjBaFw0xODA2MDUxNzE2MjBaMGcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQHDAxTYW50YSBNb25pY2ExETAPBgNVBAoMCE9uZUxvZ2luMRkwFwYDVQQDDBBhcHAub25lbG9naW4uY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAse8rnep4qL2GmhH10pMQyJ2Jae+AQHyfgVjaQZ7Z0QQog5jX91vcJRSMi0XWJnUtOr6lF0dq1+yckjZ92wyLrH+7fvngNO1aV4Mjk9sTgf+iqMrae6y6fRxDt9PXrEFVjvd3vv7QTJf2FuIPy4vVP06Dt8EMkQIr8rmLmU0mTr1k2DkrdtdlCuNFTXuAu3QqfvNCRrRwfNObn9MP6JeOUdcGLJsBjGF8exfcN1SFzRF0JFr3dmOlx761zK5liD0T1sYWnDquatj/JD9fZMbKecBKni1NglH/LVd+b6aJUAr5LulERULUjLqYJRKW31u91/4Qazdo9tbvwqyFxaoUrwIDAQABo4HUMIHRMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFPWcXvQSlTXnzZD2xziuoUvrrDedMIGRBgNVHSMEgYkwgYaAFPWcXvQSlTXnzZD2xziuoUvrrDedoWukaTBnMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UEBwwMU2FudGEgTW9uaWNhMREwDwYDVQQKDAhPbmVMb2dpbjEZMBcGA1UEAwwQYXBwLm9uZWxvZ2luLmNvbYIBATAOBgNVHQ8BAf8EBAMCBPAwDQYJKoZIhvcNAQEFBQADggEBAB/8xe3rzqXQVxzHyAHuAuPa73ClDoL1cko0Fp8CGcqEIyj6Te9gx5z6wyfv+Lo8RFvBLlnB1lXqbC+fTGcVgG/4oKLJ5UwRFxInqpZPnOAudVNnd0PYOODn9FWs6u+OTIQIaIcPUv3MhB9lwHIJsTk/bs9xcru5TPyLIxLLd6ib/pRceKH2mTkzUd0DYk9CQNXXeoGx/du5B9nh3ClPTbVakRzl3oswgI5MQIphYxkW70SopEh4kOFSRE1ND31NNIq1YrXlgtkguQBFsZWuQOPR6cEwFZzP0tHTYbI839WgxX6hfhIUTUz6mLqq4+3P4BG3+1OXeVDg63y8Uh781sE="
                    ]
                },
                "entityId": "https://app.onelogin.com/saml/metadata/383123",
                "singleSignOnService": {
                    "url": "https://app.onelogin.com/trust/saml2/http-post/sso/383123",
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                }
            }
        }
        """
        expected_settings_2 = json.loads(expected_settings_json_2)
        self.assertEqual(expected_settings_2, data_2)

    def test_merge_settings(self):
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
        # print("%s" % json.dumps(settings_result, indent=2)

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
            "x509cert": "MIIEHjCCAwagAwIBAgIBATANBgkqhkiG9w0BAQUFADBnMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UEBwwMU2FudGEgTW9uaWNhMREwDwYDVQQKDAhPbmVMb2dpbjEZMBcGA1UEAwwQYXBwLm9uZWxvZ2luLmNvbTAeFw0xMzA2MDUxNzE2MjBaFw0xODA2MDUxNzE2MjBaMGcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQHDAxTYW50YSBNb25pY2ExETAPBgNVBAoMCE9uZUxvZ2luMRkwFwYDVQQDDBBhcHAub25lbG9naW4uY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAse8rnep4qL2GmhH10pMQyJ2Jae+AQHyfgVjaQZ7Z0QQog5jX91vcJRSMi0XWJnUtOr6lF0dq1+yckjZ92wyLrH+7fvngNO1aV4Mjk9sTgf+iqMrae6y6fRxDt9PXrEFVjvd3vv7QTJf2FuIPy4vVP06Dt8EMkQIr8rmLmU0mTr1k2DkrdtdlCuNFTXuAu3QqfvNCRrRwfNObn9MP6JeOUdcGLJsBjGF8exfcN1SFzRF0JFr3dmOlx761zK5liD0T1sYWnDquatj/JD9fZMbKecBKni1NglH/LVd+b6aJUAr5LulERULUjLqYJRKW31u91/4Qazdo9tbvwqyFxaoUrwIDAQABo4HUMIHRMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFPWcXvQSlTXnzZD2xziuoUvrrDedMIGRBgNVHSMEgYkwgYaAFPWcXvQSlTXnzZD2xziuoUvrrDedoWukaTBnMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UEBwwMU2FudGEgTW9uaWNhMREwDwYDVQQKDAhPbmVMb2dpbjEZMBcGA1UEAwwQYXBwLm9uZWxvZ2luLmNvbYIBATAOBgNVHQ8BAf8EBAMCBPAwDQYJKoZIhvcNAQEFBQADggEBAB/8xe3rzqXQVxzHyAHuAuPa73ClDoL1cko0Fp8CGcqEIyj6Te9gx5z6wyfv+Lo8RFvBLlnB1lXqbC+fTGcVgG/4oKLJ5UwRFxInqpZPnOAudVNnd0PYOODn9FWs6u+OTIQIaIcPUv3MhB9lwHIJsTk/bs9xcru5TPyLIxLLd6ib/pRceKH2mTkzUd0DYk9CQNXXeoGx/du5B9nh3ClPTbVakRzl3oswgI5MQIphYxkW70SopEh4kOFSRE1ND31NNIq1YrXlgtkguQBFsZWuQOPR6cEwFZzP0tHTYbI839WgxX6hfhIUTUz6mLqq4+3P4BG3+1OXeVDg63y8Uh781sE="
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
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
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

        # Test merging multiple certs
        xml_idp_metadata = self.file_contents(join(self.data_path, 'metadata', 'idp_metadata_multi_certs.xml'))
        data3 = OneLogin_Saml2_IdPMetadataParser.parse(xml_idp_metadata)
        settings_result3 = OneLogin_Saml2_IdPMetadataParser.merge_settings(settings, data3)
        expected_settings3_json = """
        {
          "debug": false,
          "strict": false,
          "custom_base_path": "../../../tests/data/customPath/",
          "sp": {
            "singleLogoutService": {
              "url": "http://stuff.com/endpoints/endpoints/sls.php"
            },
            "assertionConsumerService": {
              "url": "http://stuff.com/endpoints/endpoints/acs.php"
            },
            "entityId": "http://stuff.com/endpoints/metadata.php",
            "NameIDFormat": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
          },
          "idp": {
            "singleLogoutService": {
              "url": "https://idp.examle.com/saml/slo",
              "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            },
            "x509certMulti": {
              "encryption": [
                "MIIEZTCCA02gAwIBAgIUPyy/A3bZAZ4m28PzEUUoT7RJhxIwDQYJKoZIhvcNAQEFBQAwcjELMAkGA1UEBhMCVVMxKzApBgNVBAoMIk9uZUxvZ2luIFRlc3QgKHNnYXJjaWEtdXMtcHJlcHJvZCkxFTATBgNVBAsMDE9uZUxvZ2luIElkUDEfMB0GA1UEAwwWT25lTG9naW4gQWNjb3VudCA4OTE0NjAeFw0xNjA4MDQyMjI5MzdaFw0yMTA4MDUyMjI5MzdaMHIxCzAJBgNVBAYTAlVTMSswKQYDVQQKDCJPbmVMb2dpbiBUZXN0IChzZ2FyY2lhLXVzLXByZXByb2QpMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgODkxNDYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDN6iqQGcLOCglNO42I2rkzE05UXSiMXT6c8ALThMMiaDw6qqzo3sd/tKK+NcNKWLIIC8TozWVyh5ykUiVZps+08xil7VsTU7E+wKu3kvmOsvw2wlRwtnoKZJwYhnr+RkBa+h1r3ZYUgXm1ZPeHMKj1g18KaWz9+MxYL6BhKqrOzfW/P2xxVRcFH7/pq+ZsDdgNzD2GD+apzY4MZyZj/N6BpBWJ0GlFsmtBegpbX3LBitJuFkk5L4/U/jjF1AJa3boBdCUVfATqO5G03H4XS1GySjBIRQXmlUF52rLjg6xCgWJ30/+t1X+IHLJeixiQ0vxyh6C4/usCEt94cgD1r8ADAgMBAAGjgfIwge8wDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUPW0DcH0G3IwynWgi74co4wZ6n7gwga8GA1UdIwSBpzCBpIAUPW0DcH0G3IwynWgi74co4wZ6n7ihdqR0MHIxCzAJBgNVBAYTAlVTMSswKQYDVQQKDCJPbmVMb2dpbiBUZXN0IChzZ2FyY2lhLXVzLXByZXByb2QpMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgODkxNDaCFD8svwN22QGeJtvD8xFFKE+0SYcSMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQUFAAOCAQEAQhB4q9jrycwbHrDSoYR1X4LFFzvJ9Us75wQquRHXpdyS9D6HUBXMGI6ahPicXCQrfLgN8vzMIiqZqfySXXv/8/dxe/X4UsWLYKYJHDJmxXD5EmWTa65chjkeP1oJAc8f3CKCpcP2lOBTthbnk2fEVAeLHR4xNdQO0VvGXWO9BliYPpkYqUIBvlm+Fg9mF7AM/Uagq2503XXIE1Lq//HON68P10vNMwLSKOtYLsoTiCnuIKGJqG37MsZVjQ1ZPRcO+LSLkq0i91gFxrOrVCrgztX4JQi5XkvEsYZGIXXjwHqxTVyt3adZWQO0LPxPqRiUqUzyhDhLo/xXNrHCu4VbMw=="
              ],
              "signing": [
                "MIIEZTCCA02gAwIBAgIUPyy/A3bZAZ4m28PzEUUoT7RJhxIwDQYJKoZIhvcNAQEFBQAwcjELMAkGA1UEBhMCVVMxKzApBgNVBAoMIk9uZUxvZ2luIFRlc3QgKHNnYXJjaWEtdXMtcHJlcHJvZCkxFTATBgNVBAsMDE9uZUxvZ2luIElkUDEfMB0GA1UEAwwWT25lTG9naW4gQWNjb3VudCA4OTE0NjAeFw0xNjA4MDQyMjI5MzdaFw0yMTA4MDUyMjI5MzdaMHIxCzAJBgNVBAYTAlVTMSswKQYDVQQKDCJPbmVMb2dpbiBUZXN0IChzZ2FyY2lhLXVzLXByZXByb2QpMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgODkxNDYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDN6iqQGcLOCglNO42I2rkzE05UXSiMXT6c8ALThMMiaDw6qqzo3sd/tKK+NcNKWLIIC8TozWVyh5ykUiVZps+08xil7VsTU7E+wKu3kvmOsvw2wlRwtnoKZJwYhnr+RkBa+h1r3ZYUgXm1ZPeHMKj1g18KaWz9+MxYL6BhKqrOzfW/P2xxVRcFH7/pq+ZsDdgNzD2GD+apzY4MZyZj/N6BpBWJ0GlFsmtBegpbX3LBitJuFkk5L4/U/jjF1AJa3boBdCUVfATqO5G03H4XS1GySjBIRQXmlUF52rLjg6xCgWJ30/+t1X+IHLJeixiQ0vxyh6C4/usCEt94cgD1r8ADAgMBAAGjgfIwge8wDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUPW0DcH0G3IwynWgi74co4wZ6n7gwga8GA1UdIwSBpzCBpIAUPW0DcH0G3IwynWgi74co4wZ6n7ihdqR0MHIxCzAJBgNVBAYTAlVTMSswKQYDVQQKDCJPbmVMb2dpbiBUZXN0IChzZ2FyY2lhLXVzLXByZXByb2QpMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgODkxNDaCFD8svwN22QGeJtvD8xFFKE+0SYcSMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQUFAAOCAQEAQhB4q9jrycwbHrDSoYR1X4LFFzvJ9Us75wQquRHXpdyS9D6HUBXMGI6ahPicXCQrfLgN8vzMIiqZqfySXXv/8/dxe/X4UsWLYKYJHDJmxXD5EmWTa65chjkeP1oJAc8f3CKCpcP2lOBTthbnk2fEVAeLHR4xNdQO0VvGXWO9BliYPpkYqUIBvlm+Fg9mF7AM/Uagq2503XXIE1Lq//HON68P10vNMwLSKOtYLsoTiCnuIKGJqG37MsZVjQ1ZPRcO+LSLkq0i91gFxrOrVCrgztX4JQi5XkvEsYZGIXXjwHqxTVyt3adZWQO0LPxPqRiUqUzyhDhLo/xXNrHCu4VbMw==",
                "MIICZDCCAc2gAwIBAgIBADANBgkqhkiG9w0BAQ0FADBPMQswCQYDVQQGEwJ1czEUMBIGA1UECAwLZXhhbXBsZS5jb20xFDASBgNVBAoMC2V4YW1wbGUuY29tMRQwEgYDVQQDDAtleGFtcGxlLmNvbTAeFw0xNzA0MTUxNjMzMThaFw0xODA0MTUxNjMzMThaME8xCzAJBgNVBAYTAnVzMRQwEgYDVQQIDAtleGFtcGxlLmNvbTEUMBIGA1UECgwLZXhhbXBsZS5jb20xFDASBgNVBAMMC2V4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC6GLkl5lDUZdHNDAojp5i24OoPlqrt5TGXJIPqAZYT1hQvJW5nv17MFDHrjmtEnmW4ACKEy0fAX80QWIcHunZSkbEGHb+NG/6oTi5RipXMvmHnfFnPJJ0AdtiLiPE478CV856gXekV4Xx5u3KrylcOgkpYsp0GMIQBDzleMUXlYQIDAQABo1AwTjAdBgNVHQ4EFgQUnP8vlYPGPL2n6ZzDYij2kMDC8wMwHwYDVR0jBBgwFoAUnP8vlYPGPL2n6ZzDYij2kMDC8wMwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQAlQGAl+b8Cpot1g+65lLLjVoY7APJPWLW0klKQNlMU0s4MU+71Y3ExUEOXDAZgKcFoavb1fEOGMwEf38NaJAy1e/l6VNuixXShffq20ymqHQxOG0q8ujeNkgZF9k6XDfn/QZ3AD0o/IrCT7UMc/0QsfgIjWYxwCvp2syApc5CYfQ=="
              ]
            },
            "entityId": "https://idp.examle.com/saml/metadata",
            "singleSignOnService": {
              "url": "https://idp.examle.com/saml/sso",
              "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            }
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
          "organization": {
            "en-US": {
              "displayname": "SP test",
              "url": "http://sp.example.com",
              "name": "sp_test"
            }
          }
        }
        """
        expected_settings3 = json.loads(expected_settings3_json)
        self.assertEqual(expected_settings3, settings_result3)
