# -*- coding: utf-8 -*-

# Copyright (c) 2010-2018 OneLogin, Inc.
# MIT License

from base64 import b64decode
import json
from lxml import etree
from os.path import dirname, join, exists
import unittest
from defusedxml.lxml import fromstring
from xml.dom.minidom import parseString

from onelogin.saml2 import compat
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils


class OneLogin_Saml2_Utils_Test(unittest.TestCase):
    data_path = join(dirname(dirname(dirname(dirname(__file__)))), 'data')
    settings_path = join(dirname(dirname(dirname(dirname(__file__)))), 'settings')

    # assertRegexpMatches deprecated on python3
    def assertRaisesRegex(self, exception, regexp, msg=None):
        if hasattr(unittest.TestCase, 'assertRaisesRegex'):
            return super(OneLogin_Saml2_Utils_Test, self).assertRaisesRegex(exception, regexp, msg=msg)
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

    def testFormatCert(self):
        """
        Tests the format_cert method of the OneLogin_Saml2_Utils
        """
        settings_info = self.loadSettingsJSON()
        cert = settings_info['idp']['x509cert']
        self.assertNotIn('-----BEGIN CERTIFICATE-----', cert)
        self.assertNotIn('-----END CERTIFICATE-----', cert)
        self.assertEqual(len(cert), 860)

        formated_cert1 = OneLogin_Saml2_Utils.format_cert(cert)
        self.assertIn('-----BEGIN CERTIFICATE-----', formated_cert1)
        self.assertIn('-----END CERTIFICATE-----', formated_cert1)

        formated_cert2 = OneLogin_Saml2_Utils.format_cert(cert, True)
        self.assertEqual(formated_cert1, formated_cert2)

        formated_cert3 = OneLogin_Saml2_Utils.format_cert(cert, False)
        self.assertNotIn('-----BEGIN CERTIFICATE-----', formated_cert3)
        self.assertNotIn('-----END CERTIFICATE-----', formated_cert3)
        self.assertEqual(len(formated_cert3), 860)

    def testFormatPrivateKey(self):
        """
        Tests the format_private_key method of the OneLogin_Saml2_Utils
        """
        key = "-----BEGIN RSA PRIVATE KEY-----\nMIICXgIBAAKBgQDivbhR7P516x/S3BqKxupQe0LONoliupiBOesCO3SHbDrl3+q9\nIbfnfmE04rNuMcPsIxB161TdDpIesLCn7c8aPHISKOtPlAeTZSnb8QAu7aRjZq3+\nPbrP5uW3TcfCGPtKTytHOge/OlJbo078dVhXQ14d1EDwXJW1rRXuUt4C8QIDAQAB\nAoGAD4/Z4LWVWV6D1qMIp1Gzr0ZmdWTE1SPdZ7Ej8glGnCzPdguCPuzbhGXmIg0V\nJ5D+02wsqws1zd48JSMXXM8zkYZVwQYIPUsNn5FetQpwxDIMPmhHg+QNBgwOnk8J\nK2sIjjLPL7qY7Itv7LT7Gvm5qSOkZ33RCgXcgz+okEIQMYkCQQDzbTOyDL0c5WQV\n6A2k06T/azdhUdGXF9C0+WkWSfNaovmTgRXh1G+jMlr82Snz4p4/STt7P/XtyWzF\n3pkVgZr3AkEA7nPjXwHlttNEMo6AtxHd47nizK2NUN803ElIUT8P9KSCoERmSXq6\n6PDekGNic4ldpsSvOeYCk8MAYoDBy9kvVwJBAMLgX4xg6lzhv7hR5+pWjTb1rIY6\nrCHbrPfU264+UZXz9v2BT/VUznLF81WMvStD9xAPHpFS6R0OLghSZhdzhI0CQQDL\n8Duvfxzrn4b9QlmduV8wLERoT6rEVxKLsPVz316TGrxJvBZLk/cV0SRZE1cZf4uk\nXSWMfEcJ/0Zt+LdG1CqjAkEAqwLSglJ9Dy3HpgMz4vAAyZWzAxvyA1zW0no9GOLc\nPQnYaNUN/Fy2SYtETXTb0CQ9X1rt8ffkFP7ya+5TC83aMg==\n-----END RSA PRIVATE KEY-----\n"
        formated_key = OneLogin_Saml2_Utils.format_private_key(key, True)
        self.assertIn('-----BEGIN RSA PRIVATE KEY-----', formated_key)
        self.assertIn('-----END RSA PRIVATE KEY-----', formated_key)
        self.assertEqual(len(formated_key), 891)

        formated_key = OneLogin_Saml2_Utils.format_private_key(key, False)
        self.assertNotIn('-----BEGIN RSA PRIVATE KEY-----', formated_key)
        self.assertNotIn('-----END RSA PRIVATE KEY-----', formated_key)
        self.assertEqual(len(formated_key), 816)

        key_2 = "-----BEGIN PRIVATE KEY-----\nMIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAM62buSW9Zgh7CmZ\nouJekK0ac9sgEZkspemjv7SyE6Hbdz+KmUr3C7MI6JuPfVyJbxvMDf3FbgBBK7r5\nyfGgehXwplLMZj8glvV3NkdLMLPWmaw9U5sOzRoym46pVvsEo1PUL2qDK5Wrsm1g\nuY1KIDSHL59NQ7PzDKgm1dxioeXFAgMBAAECgYA/fvRzTReloo3rfWD2Tfv84EpE\nPgaJ2ZghO4Zwl97F8icgIo/R4i760Lq6xgnI+gJiNHz7vcB7XYl0RrRMf3HgbA7z\npJxREmOVltESDHy6lH0TmCdv9xMmHltB+pbGOhqBvuGgFbEOR73lDDV0ln2rEITJ\nA2zjYF+hWe8b0JFeQQJBAOsIIIlHAMngjhCQDD6kla/vce972gCFU7ZeFw16ZMmb\n8W4rGRfQoQWYxSLAFIFsYewSBTccanyYbBNe3njki3ECQQDhJ4cgV6VpTwez4dkp\nU/xCHKoReedAEJhXucTNGpiIqu+TDgIz9aRbrgnUKkS1s06UJhcDRTl/+pCSRRt/\nCA2VAkBkPw4pn1hNwvK1S8t9OJQD+5xcKjZcvIFtKoqonAi7GUGL3OQSDVFw4q1K\n2iSk40aM+06wJ/WfeR+3z2ISrGBxAkAJ20YiF1QpcQlASbHNCl0vs7uKOlDyUAer\nR3mjFPf6e6kzQdi815MTZGIPxK3vWmMlPymgvgYPYTO1A4t5myulAkEA1QioAWcJ\noO26qhUlFRBCR8BMJoVPImV7ndVHE7usHdJvP7V2P9RyuRcMCTVul8RRmyoh/+yG\n4ghMaHo/v0YY5Q==\n-----END PRIVATE KEY-----\n"
        formated_key_2 = OneLogin_Saml2_Utils.format_private_key(key_2, True)
        self.assertIn('-----BEGIN PRIVATE KEY-----', formated_key_2)
        self.assertIn('-----END PRIVATE KEY-----', formated_key_2)
        self.assertEqual(len(formated_key_2), 916)

        formated_key_2 = OneLogin_Saml2_Utils.format_private_key(key_2, False)
        self.assertNotIn('-----BEGIN PRIVATE KEY-----', formated_key_2)
        self.assertNotIn('-----END PRIVATE KEY-----', formated_key_2)
        self.assertEqual(len(formated_key_2), 848)

        key_3 = 'MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAM62buSW9Zgh7CmZouJekK0ac9sgEZkspemjv7SyE6Hbdz+KmUr3C7MI6JuPfVyJbxvMDf3FbgBBK7r5yfGgehXwplLMZj8glvV3NkdLMLPWmaw9U5sOzRoym46pVvsEo1PUL2qDK5Wrsm1guY1KIDSHL59NQ7PzDKgm1dxioeXFAgMBAAECgYA/fvRzTReloo3rfWD2Tfv84EpEPgaJ2ZghO4Zwl97F8icgIo/R4i760Lq6xgnI+gJiNHz7vcB7XYl0RrRMf3HgbA7zpJxREmOVltESDHy6lH0TmCdv9xMmHltB+pbGOhqBvuGgFbEOR73lDDV0ln2rEITJA2zjYF+hWe8b0JFeQQJBAOsIIIlHAMngjhCQDD6kla/vce972gCFU7ZeFw16ZMmb8W4rGRfQoQWYxSLAFIFsYewSBTccanyYbBNe3njki3ECQQDhJ4cgV6VpTwez4dkpU/xCHKoReedAEJhXucTNGpiIqu+TDgIz9aRbrgnUKkS1s06UJhcDRTl/+pCSRRt/CA2VAkBkPw4pn1hNwvK1S8t9OJQD+5xcKjZcvIFtKoqonAi7GUGL3OQSDVFw4q1K2iSk40aM+06wJ/WfeR+3z2ISrGBxAkAJ20YiF1QpcQlASbHNCl0vs7uKOlDyUAerR3mjFPf6e6kzQdi815MTZGIPxK3vWmMlPymgvgYPYTO1A4t5myulAkEA1QioAWcJoO26qhUlFRBCR8BMJoVPImV7ndVHE7usHdJvP7V2P9RyuRcMCTVul8RRmyoh/+yG4ghMaHo/v0YY5Q=='
        formated_key_3 = OneLogin_Saml2_Utils.format_private_key(key_3, True)
        self.assertIn('-----BEGIN RSA PRIVATE KEY-----', formated_key_3)
        self.assertIn('-----END RSA PRIVATE KEY-----', formated_key_3)
        self.assertEqual(len(formated_key_3), 924)

        formated_key_3 = OneLogin_Saml2_Utils.format_private_key(key_3, False)
        self.assertNotIn('-----BEGIN PRIVATE KEY-----', formated_key_3)
        self.assertNotIn('-----END PRIVATE KEY-----', formated_key_3)
        self.assertNotIn('-----BEGIN RSA PRIVATE KEY-----', formated_key_3)
        self.assertNotIn('-----END RSA PRIVATE KEY-----', formated_key_3)
        self.assertEqual(len(formated_key_3), 848)

    def testRedirect(self):
        """
        Tests the redirect method of the OneLogin_Saml2_Utils
        """
        request_data = {
            'http_host': 'example.com'
        }

        # Check relative and absolute
        hostname = OneLogin_Saml2_Utils.get_self_host(request_data)
        url = 'http://%s/example' % hostname
        url2 = '/example'

        target_url = OneLogin_Saml2_Utils.redirect(url, {}, request_data)
        target_url2 = OneLogin_Saml2_Utils.redirect(url2, {}, request_data)

        self.assertEqual(target_url, target_url2)

        # Check that accept http/https and reject other protocols
        url3 = 'https://%s/example?test=true' % hostname
        url4 = 'ftp://%s/example' % hostname

        target_url3 = OneLogin_Saml2_Utils.redirect(url3, {}, request_data)
        self.assertIn('test=true', target_url3)
        with self.assertRaises(Exception) as context:
            OneLogin_Saml2_Utils.redirect(url4, {}, request_data)
            exception = context.exception
            self.assertIn("Redirect to invalid URL", str(exception))

        # Review parameter prefix
        parameters1 = {
            'value1': 'a'
        }

        target_url5 = OneLogin_Saml2_Utils.redirect(url, parameters1, request_data)
        self.assertEqual('http://%s/example?value1=a' % hostname, target_url5)

        target_url6 = OneLogin_Saml2_Utils.redirect(url3, parameters1, request_data)
        self.assertEqual('https://%s/example?test=true&value1=a' % hostname, target_url6)

        # Review parameters
        parameters2 = {
            'alphavalue': 'a',
            'numvaluelist': ['1', '2'],
            'testing': None
        }

        target_url7 = OneLogin_Saml2_Utils.redirect(url, parameters2, request_data)
        parameters2_decoded = {"alphavalue": "alphavalue=a", "numvaluelist": "numvaluelist[]=1&numvaluelist[]=2", "testing": "testing"}
        parameters2_str = "&".join(parameters2_decoded[x] for x in parameters2)
        self.assertEqual('http://%s/example?%s' % (hostname, parameters2_str), target_url7)

        parameters3 = {
            'alphavalue': 'a',
            'emptynumvaluelist': [],
            'numvaluelist': [''],
        }
        parameters3_decoded = {"alphavalue": "alphavalue=a", "numvaluelist": "numvaluelist[]="}
        parameters3_str = "&".join((parameters3_decoded[x] for x in parameters3.keys() if x in parameters3_decoded))
        target_url8 = OneLogin_Saml2_Utils.redirect(url, parameters3, request_data)
        self.assertEqual('http://%s/example?%s' % (hostname, parameters3_str), target_url8)

    def testGetselfhost(self):
        """
        Tests the get_self_host method of the OneLogin_Saml2_Utils
        """
        request_data = {}
        with self.assertRaises(Exception) as context:
            OneLogin_Saml2_Utils.get_self_url_host(request_data)
            exception = context.exception
            self.assertIn("No hostname defined", str(exception))

        request_data = {
            'server_name': 'example.com'
        }
        self.assertEqual('example.com', OneLogin_Saml2_Utils.get_self_host(request_data))

        request_data = {
            'http_host': 'example.com'
        }
        self.assertEqual('example.com', OneLogin_Saml2_Utils.get_self_host(request_data))

        request_data = {
            'http_host': 'example.com:443'
        }
        self.assertEqual('example.com', OneLogin_Saml2_Utils.get_self_host(request_data))

        request_data = {
            'http_host': 'example.com:ok'
        }
        self.assertEqual('example.com:ok', OneLogin_Saml2_Utils.get_self_host(request_data))

    def testisHTTPS(self):
        """
        Tests the is_https method of the OneLogin_Saml2_Utils
        """
        request_data = {
            'https': 'off'
        }
        self.assertFalse(OneLogin_Saml2_Utils.is_https(request_data))

        request_data = {
            'https': 'on'
        }
        self.assertTrue(OneLogin_Saml2_Utils.is_https(request_data))

        request_data = {
            'server_port': '80'
        }
        self.assertFalse(OneLogin_Saml2_Utils.is_https(request_data))

        request_data = {
            'server_port': '443'
        }
        self.assertTrue(OneLogin_Saml2_Utils.is_https(request_data))

    def testGetSelfURLhost(self):
        """
        Tests the get_self_url_host method of the OneLogin_Saml2_Utils
        """
        request_data = {
            'http_host': 'example.com'
        }
        self.assertEqual('http://example.com', OneLogin_Saml2_Utils.get_self_url_host(request_data))

        request_data['server_port'] = '80'
        self.assertEqual('http://example.com', OneLogin_Saml2_Utils.get_self_url_host(request_data))

        request_data['server_port'] = '81'
        self.assertEqual('http://example.com:81', OneLogin_Saml2_Utils.get_self_url_host(request_data))

        request_data['server_port'] = '443'
        self.assertEqual('https://example.com', OneLogin_Saml2_Utils.get_self_url_host(request_data))

        del request_data['server_port']
        request_data['https'] = 'on'
        self.assertEqual('https://example.com', OneLogin_Saml2_Utils.get_self_url_host(request_data))

        request_data['server_port'] = '444'
        self.assertEqual('https://example.com:444', OneLogin_Saml2_Utils.get_self_url_host(request_data))

        request_data['server_port'] = '443'
        request_data['request_uri'] = ''
        self.assertEqual('https://example.com', OneLogin_Saml2_Utils.get_self_url_host(request_data))

        request_data['request_uri'] = '/'
        self.assertEqual('https://example.com', OneLogin_Saml2_Utils.get_self_url_host(request_data))

        request_data['request_uri'] = 'onelogin/'
        self.assertEqual('https://example.com', OneLogin_Saml2_Utils.get_self_url_host(request_data))

        request_data['request_uri'] = '/onelogin'
        self.assertEqual('https://example.com', OneLogin_Saml2_Utils.get_self_url_host(request_data))

        request_data['request_uri'] = 'https://example.com/onelogin/sso'
        self.assertEqual('https://example.com', OneLogin_Saml2_Utils.get_self_url_host(request_data))

        request_data2 = {
            'request_uri': 'example.com/onelogin/sso'
        }
        with self.assertRaises(Exception) as context:
            OneLogin_Saml2_Utils.get_self_url_host(request_data2)
            exception = context.exception
            self.assertIn("No hostname defined", str(exception))

    def testGetSelfURL(self):
        """
        Tests the get_self_url method of the OneLogin_Saml2_Utils
        """
        request_data = {
            'http_host': 'example.com'
        }
        url = OneLogin_Saml2_Utils.get_self_url_host(request_data)
        self.assertEqual(url, OneLogin_Saml2_Utils.get_self_url(request_data))

        request_data['request_uri'] = ''
        self.assertEqual(url, OneLogin_Saml2_Utils.get_self_url(request_data))

        request_data['request_uri'] = '/'
        self.assertEqual(url + '/', OneLogin_Saml2_Utils.get_self_url(request_data))

        request_data['request_uri'] = 'index.html'
        self.assertEqual(url + 'index.html', OneLogin_Saml2_Utils.get_self_url(request_data))

        request_data['request_uri'] = '?index.html'
        self.assertEqual(url + '?index.html', OneLogin_Saml2_Utils.get_self_url(request_data))

        request_data['request_uri'] = '/index.html'
        self.assertEqual(url + '/index.html', OneLogin_Saml2_Utils.get_self_url(request_data))

        request_data['request_uri'] = '/index.html?testing'
        self.assertEqual(url + '/index.html?testing', OneLogin_Saml2_Utils.get_self_url(request_data))

        request_data['request_uri'] = '/test/index.html?testing'
        self.assertEqual(url + '/test/index.html?testing', OneLogin_Saml2_Utils.get_self_url(request_data))

        request_data['request_uri'] = 'https://example.com/testing'
        self.assertEqual(url + '/testing', OneLogin_Saml2_Utils.get_self_url(request_data))

    def testGetSelfURLNoQuery(self):
        """
        Tests the get_self_url_no_query method of the OneLogin_Saml2_Utils
        """
        request_data = {
            'http_host': 'example.com',
            'script_name': '/index.html'
        }
        url = OneLogin_Saml2_Utils.get_self_url_host(request_data) + request_data['script_name']
        self.assertEqual(url, OneLogin_Saml2_Utils.get_self_url_no_query(request_data))

        request_data['path_info'] = '/test'
        self.assertEqual(url + '/test', OneLogin_Saml2_Utils.get_self_url_no_query(request_data))

    def testGetSelfRoutedURLNoQuery(self):
        """
        Tests the get_self_routed_url_no_query method of the OneLogin_Saml2_Utils
        """
        request_data = {
            'http_host': 'example.com',
            'request_uri': '/example1/route?x=test',
            'query_string': '?x=test'
        }
        url = OneLogin_Saml2_Utils.get_self_url_host(request_data) + '/example1/route'
        self.assertEqual(url, OneLogin_Saml2_Utils.get_self_routed_url_no_query(request_data))

        request_data_2 = {
            'http_host': 'example.com',
            'request_uri': '',
        }
        url_2 = OneLogin_Saml2_Utils.get_self_url_host(request_data_2)
        self.assertEqual(url_2, OneLogin_Saml2_Utils.get_self_routed_url_no_query(request_data_2))

        request_data_3 = {
            'http_host': 'example.com',
        }
        url_3 = OneLogin_Saml2_Utils.get_self_url_host(request_data_3)
        self.assertEqual(url_3, OneLogin_Saml2_Utils.get_self_routed_url_no_query(request_data_3))

        request_data_4 = {
            'http_host': 'example.com',
            'request_uri': '/example1/route/test/',
            'query_string': '?invalid=1'
        }
        url_4 = OneLogin_Saml2_Utils.get_self_url_host(request_data_4) + '/example1/route/test/'
        self.assertEqual(url_4, OneLogin_Saml2_Utils.get_self_routed_url_no_query(request_data_4))

        request_data_5 = {
            'http_host': 'example.com',
            'request_uri': '/example1/route/test/',
            'query_string': ''
        }
        url_5 = OneLogin_Saml2_Utils.get_self_url_host(request_data_5) + '/example1/route/test/'
        self.assertEqual(url_5, OneLogin_Saml2_Utils.get_self_routed_url_no_query(request_data_5))

        request_data_6 = {
            'http_host': 'example.com',
            'request_uri': '/example1/route/test/',
        }
        url_6 = OneLogin_Saml2_Utils.get_self_url_host(request_data_6) + '/example1/route/test/'
        self.assertEqual(url_6, OneLogin_Saml2_Utils.get_self_routed_url_no_query(request_data_6))

    def testGetStatus(self):
        """
        Gets the status of a message
        """
        xml = self.file_contents(join(self.data_path, 'responses', 'response1.xml.base64'))
        xml = b64decode(xml)
        dom = etree.fromstring(xml)

        status = OneLogin_Saml2_Utils.get_status(dom)
        self.assertEqual(OneLogin_Saml2_Constants.STATUS_SUCCESS, status['code'])

        xml2 = self.file_contents(join(self.data_path, 'responses', 'invalids', 'status_code_responder.xml.base64'))
        xml2 = b64decode(xml2)
        dom2 = etree.fromstring(xml2)

        status2 = OneLogin_Saml2_Utils.get_status(dom2)
        self.assertEqual(OneLogin_Saml2_Constants.STATUS_RESPONDER, status2['code'])
        self.assertEqual('', status2['msg'])

        xml3 = self.file_contents(join(self.data_path, 'responses', 'invalids', 'status_code_responer_and_msg.xml.base64'))
        xml3 = b64decode(xml3)
        dom3 = etree.fromstring(xml3)

        status3 = OneLogin_Saml2_Utils.get_status(dom3)
        self.assertEqual(OneLogin_Saml2_Constants.STATUS_RESPONDER, status3['code'])
        self.assertEqual('something_is_wrong', status3['msg'])

        xml_inv = self.file_contents(join(self.data_path, 'responses', 'invalids', 'no_status.xml.base64'))
        xml_inv = b64decode(xml_inv)
        dom_inv = etree.fromstring(xml_inv)

        with self.assertRaisesRegex(Exception, 'Missing Status on response'):
            OneLogin_Saml2_Utils.get_status(dom_inv)

        xml_inv2 = self.file_contents(join(self.data_path, 'responses', 'invalids', 'no_status_code.xml.base64'))
        xml_inv2 = b64decode(xml_inv2)
        dom_inv2 = etree.fromstring(xml_inv2)

        with self.assertRaisesRegex(Exception, 'Missing Status Code on response'):
            OneLogin_Saml2_Utils.get_status(dom_inv2)

    def testParseDuration(self):
        """
        Tests the parse_duration method of the OneLogin_Saml2_Utils
        """
        duration = 'PT1393462294S'
        timestamp = 1393876825

        parsed_duration = OneLogin_Saml2_Utils.parse_duration(duration, timestamp)
        self.assertEqual(2787339119, parsed_duration)

        parsed_duration_2 = OneLogin_Saml2_Utils.parse_duration(duration)
        self.assertTrue(parsed_duration_2 > parsed_duration)

        invalid_duration = 'PT1Y'
        with self.assertRaises(Exception) as context:
            OneLogin_Saml2_Utils.parse_duration(invalid_duration)
            exception = context.exception
            self.assertIn("Unrecognised ISO 8601 date format", str(exception))

        new_duration = 'P1Y1M'
        parsed_duration_4 = OneLogin_Saml2_Utils.parse_duration(new_duration, timestamp)
        self.assertEqual(1428091225, parsed_duration_4)

        neg_duration = '-P14M'
        parsed_duration_5 = OneLogin_Saml2_Utils.parse_duration(neg_duration, timestamp)
        self.assertEqual(1357243225, parsed_duration_5)

    def testParseSAML2Time(self):
        """
        Tests the parse_SAML_to_time method of the OneLogin_Saml2_Utils
        """
        time = 1386650371
        saml_time = '2013-12-10T04:39:31Z'
        self.assertEqual(time, OneLogin_Saml2_Utils.parse_SAML_to_time(saml_time))
        with self.assertRaises(Exception) as context:
            OneLogin_Saml2_Utils.parse_SAML_to_time('invalidSAMLTime')
            exception = context.exception
            self.assertIn("does not match format", str(exception))

        # Now test if toolkit supports miliseconds
        saml_time2 = '2013-12-10T04:39:31.120Z'
        self.assertEqual(time, OneLogin_Saml2_Utils.parse_SAML_to_time(saml_time2))

    def testParseTime2SAML(self):
        """
        Tests the parse_time_to_SAML method of the OneLogin_Saml2_Utils
        """
        time = 1386650371
        saml_time = '2013-12-10T04:39:31Z'
        self.assertEqual(saml_time, OneLogin_Saml2_Utils.parse_time_to_SAML(time))
        with self.assertRaises(Exception) as context:
            OneLogin_Saml2_Utils.parse_time_to_SAML('invalidtime')
            exception = context.exception
            self.assertIn("could not convert string to float", str(exception))

    def testGetExpireTime(self):
        """
        Tests the get_expire_time method of the OneLogin_Saml2_Utils
        """
        self.assertEqual(None, OneLogin_Saml2_Utils.get_expire_time())
        self.assertNotEqual(None, OneLogin_Saml2_Utils.get_expire_time('PT360000S'))

        self.assertEqual('1291955971', OneLogin_Saml2_Utils.get_expire_time('PT360000S', '2010-12-10T04:39:31Z'))
        self.assertEqual('1291955971', OneLogin_Saml2_Utils.get_expire_time('PT360000S', 1291955971))

        self.assertNotEqual('3311642371', OneLogin_Saml2_Utils.get_expire_time('PT360000S', '2074-12-10T04:39:31Z'))
        self.assertNotEqual('3311642371', OneLogin_Saml2_Utils.get_expire_time('PT360000S', 1418186371))

    def _generate_name_id_element(self, name_qualifier):
        name_id_value = 'value'
        entity_id = 'sp-entity-id'
        name_id_format = 'name-id-format'

        raw_name_id = OneLogin_Saml2_Utils.generate_name_id(
            name_id_value,
            entity_id,
            name_id_format,
            nq=name_qualifier,
        )
        parser = etree.XMLParser(recover=True)
        return etree.fromstring(raw_name_id, parser)

    def testNameidGenerationIncludesNameQualifierAttribute(self):
        """
        Tests the inclusion of NameQualifier in the generateNameId method of the OneLogin_Saml2_Utils
        """
        idp_name_qualifier = 'idp-name-qualifier'
        idp_name_qualifier_attribute = ('NameQualifier', idp_name_qualifier)

        name_id = self._generate_name_id_element(idp_name_qualifier)

        self.assertIn(idp_name_qualifier_attribute, name_id.attrib.items())

    def testNameidGenerationDoesNotIncludeNameQualifierAttribute(self):
        """
        Tests the (not) inclusion of NameQualifier in the generateNameId method of the OneLogin_Saml2_Utils
        """
        idp_name_qualifier = None
        not_expected_attribute = 'NameQualifier'

        name_id = self._generate_name_id_element(idp_name_qualifier)

        self.assertNotIn(not_expected_attribute, name_id.attrib.keys())

    def testGenerateNameIdWithoutFormat(self):
        """
        Tests the generateNameId method of the OneLogin_Saml2_Utils
        """
        name_id_value = 'ONELOGIN_ce998811003f4e60f8b07a311dc641621379cfde'
        name_id_format = None

        name_id = OneLogin_Saml2_Utils.generate_name_id(name_id_value, None, name_id_format)
        expected_name_id = '<saml:NameID>ONELOGIN_ce998811003f4e60f8b07a311dc641621379cfde</saml:NameID>'
        self.assertEqual(name_id, expected_name_id)

    def testGenerateNameIdWithSPNameQualifier(self):
        """
        Tests the generateNameId method of the OneLogin_Saml2_Utils
        """
        name_id_value = 'ONELOGIN_ce998811003f4e60f8b07a311dc641621379cfde'
        entity_id = 'http://stuff.com/endpoints/metadata.php'
        name_id_format = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'

        name_id = OneLogin_Saml2_Utils.generate_name_id(name_id_value, entity_id, name_id_format)
        expected_name_id = '<saml:NameID SPNameQualifier="http://stuff.com/endpoints/metadata.php" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">ONELOGIN_ce998811003f4e60f8b07a311dc641621379cfde</saml:NameID>'
        self.assertEqual(expected_name_id, name_id)

        settings_info = self.loadSettingsJSON()
        x509cert = settings_info['idp']['x509cert']
        key = OneLogin_Saml2_Utils.format_cert(x509cert)

        name_id_enc = OneLogin_Saml2_Utils.generate_name_id(name_id_value, entity_id, name_id_format, key)
        expected_name_id_enc = '<saml:EncryptedID><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Type="http://www.w3.org/2001/04/xmlenc#Element">\n<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>\n<dsig:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">\n<xenc:EncryptedKey>\n<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>\n<xenc:CipherData>\n<xenc:CipherValue>'
        self.assertIn(expected_name_id_enc, name_id_enc)

    def testGenerateNameIdWithoutSPNameQualifier(self):
        """
        Tests the generateNameId method of the OneLogin_Saml2_Utils
        """
        name_id_value = 'ONELOGIN_ce998811003f4e60f8b07a311dc641621379cfde'
        name_id_format = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'

        name_id = OneLogin_Saml2_Utils.generate_name_id(name_id_value, None, name_id_format)
        expected_name_id = '<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">ONELOGIN_ce998811003f4e60f8b07a311dc641621379cfde</saml:NameID>'
        self.assertEqual(expected_name_id, name_id)

        settings_info = self.loadSettingsJSON()
        x509cert = settings_info['idp']['x509cert']
        key = OneLogin_Saml2_Utils.format_cert(x509cert)

        name_id_enc = OneLogin_Saml2_Utils.generate_name_id(name_id_value, None, name_id_format, key)
        expected_name_id_enc = '<saml:EncryptedID><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Type="http://www.w3.org/2001/04/xmlenc#Element">\n<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>\n<dsig:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">\n<xenc:EncryptedKey>\n<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>\n<xenc:CipherData>\n<xenc:CipherValue>'
        self.assertIn(expected_name_id_enc, name_id_enc)

    def testCalculateX509Fingerprint(self):
        """
        Tests the calculateX509Fingerprint method of the OneLogin_Saml2_Utils
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        cert_path = settings.get_cert_path()

        key = self.file_contents(cert_path + 'sp.key')
        cert = self.file_contents(cert_path + 'sp.crt')

        self.assertEqual(None, OneLogin_Saml2_Utils.calculate_x509_fingerprint(key))
        self.assertEqual('afe71c28ef740bc87425be13a2263d37971da1f9', OneLogin_Saml2_Utils.calculate_x509_fingerprint(cert))
        self.assertEqual('afe71c28ef740bc87425be13a2263d37971da1f9', OneLogin_Saml2_Utils.calculate_x509_fingerprint(cert, 'sha1'))

        self.assertEqual('c51cfa06c7a49767f6eab18238eae1c56708e29264da3d11f538a12cd2c357ba', OneLogin_Saml2_Utils.calculate_x509_fingerprint(cert, 'sha256'))

        self.assertEqual('bc5826e6f9429247254bae5e3c650e6968a36a62d23075eb168134978d88600559c10830c28711b2c29c7947c0c2eb1d', OneLogin_Saml2_Utils.calculate_x509_fingerprint(cert, 'sha384'))

        self.assertEqual('3db29251b97559c67988ea0754cb0573fc409b6f75d89282d57cfb75089539b0bbdb2dcd9ec6e032549ecbc466439d5992e18db2cf5494ca2fe1b2e16f348dff', OneLogin_Saml2_Utils.calculate_x509_fingerprint(cert, 'sha512'))

    def testDeleteLocalSession(self):
        """
        Tests the delete_local_session method of the OneLogin_Saml2_Utils
        """
        global local_session_test
        local_session_test = 1

        OneLogin_Saml2_Utils.delete_local_session()
        self.assertEqual(1, local_session_test)

        dscb = lambda: self.session_cear()
        OneLogin_Saml2_Utils.delete_local_session(dscb)
        self.assertEqual(0, local_session_test)

    def session_cear(self):
        """
        Auxiliar method to test the delete_local_session method of the OneLogin_Saml2_Utils
        """
        global local_session_test
        local_session_test = 0

    def testFormatFingerPrint(self):
        """
        Tests the format_finger_print method of the OneLogin_Saml2_Utils
        """
        finger_print_1 = 'AF:E7:1C:28:EF:74:0B:C8:74:25:BE:13:A2:26:3D:37:97:1D:A1:F9'
        self.assertEqual('afe71c28ef740bc87425be13a2263d37971da1f9', OneLogin_Saml2_Utils.format_finger_print(finger_print_1))

        finger_print_2 = 'afe71c28ef740bc87425be13a2263d37971da1f9'
        self.assertEqual('afe71c28ef740bc87425be13a2263d37971da1f9', OneLogin_Saml2_Utils.format_finger_print(finger_print_2))

    def testDecryptElement(self):
        """
        Tests the decrypt_element method of the OneLogin_Saml2_Utils
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())

        key = settings.get_sp_key()

        xml_nameid_enc = b64decode(self.file_contents(join(self.data_path, 'responses', 'response_encrypted_nameid.xml.base64')))
        dom_nameid_enc = etree.fromstring(xml_nameid_enc)
        encrypted_nameid_nodes = dom_nameid_enc.find('.//saml:EncryptedID', namespaces=OneLogin_Saml2_Constants.NSMAP)
        encrypted_data = encrypted_nameid_nodes[0]
        decrypted_nameid = OneLogin_Saml2_Utils.decrypt_element(encrypted_data, key)
        self.assertEqual('saml:NameID', decrypted_nameid.tag)
        self.assertEqual('2de11defd199f8d5bb63f9b7deb265ba5c675c10', decrypted_nameid.text)

        xml_assertion_enc = b64decode(self.file_contents(join(self.data_path, 'responses', 'valid_encrypted_assertion_encrypted_nameid.xml.base64')))
        dom_assertion_enc = etree.fromstring(xml_assertion_enc)
        encrypted_assertion_enc_nodes = dom_assertion_enc.find('.//saml:EncryptedAssertion', namespaces=OneLogin_Saml2_Constants.NSMAP)
        encrypted_data_assert = encrypted_assertion_enc_nodes[0]

        decrypted_assertion = OneLogin_Saml2_Utils.decrypt_element(encrypted_data_assert, key)
        self.assertEqual('{%s}Assertion' % OneLogin_Saml2_Constants.NS_SAML, decrypted_assertion.tag)
        self.assertEqual('_6fe189b1c241827773902f2b1d3a843418206a5c97', decrypted_assertion.get('ID'))

        encrypted_nameid_nodes = decrypted_assertion.xpath('./saml:Subject/saml:EncryptedID', namespaces=OneLogin_Saml2_Constants.NSMAP)
        encrypted_data = encrypted_nameid_nodes[0][0]
        decrypted_nameid = OneLogin_Saml2_Utils.decrypt_element(encrypted_data, key)
        self.assertEqual('{%s}NameID' % OneLogin_Saml2_Constants.NS_SAML, decrypted_nameid.tag)
        self.assertEqual('457bdb600de717891c77647b0806ce59c089d5b8', decrypted_nameid.text)

        key_2_file_name = join(self.data_path, 'misc', 'sp2.key')
        f = open(key_2_file_name, 'r')
        key2 = f.read()
        f.close()

        # sp.key and sp2.key are equivalent we should be able to decrypt the nameID again
        decrypted_nameid = OneLogin_Saml2_Utils.decrypt_element(encrypted_data, key2)
        self.assertIn('{%s}NameID' % (OneLogin_Saml2_Constants.NS_SAML), decrypted_nameid.tag)
        self.assertEqual('457bdb600de717891c77647b0806ce59c089d5b8', decrypted_nameid.text)

        key_3_file_name = join(self.data_path, 'misc', 'sp3.key')
        f = open(key_3_file_name, 'r')
        key3 = f.read()
        f.close()

        # sp.key and sp3.key are equivalent we should be able to decrypt the nameID again
        decrypted_nameid = OneLogin_Saml2_Utils.decrypt_element(encrypted_data, key3)
        self.assertIn('{%s}NameID' % (OneLogin_Saml2_Constants.NS_SAML), decrypted_nameid.tag)
        self.assertEqual('457bdb600de717891c77647b0806ce59c089d5b8', decrypted_nameid.text)

        key_4_file_name = join(self.data_path, 'misc', 'sp4.key')
        f = open(key_4_file_name, 'r')
        key4 = f.read()
        f.close()

        with self.assertRaisesRegex(Exception, "(1, 'failed to decrypt')"):
            OneLogin_Saml2_Utils.decrypt_element(encrypted_data, key4)

        xml_nameid_enc_2 = b64decode(self.file_contents(join(self.data_path, 'responses', 'invalids', 'encrypted_nameID_without_EncMethod.xml.base64')))
        dom_nameid_enc_2 = parseString(xml_nameid_enc_2)
        encrypted_nameid_nodes_2 = dom_nameid_enc_2.getElementsByTagName('saml:EncryptedID')
        encrypted_data_2 = encrypted_nameid_nodes_2[0].firstChild

        with self.assertRaisesRegex(Exception, "(1, 'failed to decrypt')"):
            OneLogin_Saml2_Utils.decrypt_element(encrypted_data_2, key)

        xml_nameid_enc_3 = b64decode(self.file_contents(join(self.data_path, 'responses', 'invalids', 'encrypted_nameID_without_keyinfo.xml.base64')))
        dom_nameid_enc_3 = parseString(xml_nameid_enc_3)
        encrypted_nameid_nodes_3 = dom_nameid_enc_3.getElementsByTagName('saml:EncryptedID')
        encrypted_data_3 = encrypted_nameid_nodes_3[0].firstChild

        with self.assertRaisesRegex(Exception, "(1, 'failed to decrypt')"):
            OneLogin_Saml2_Utils.decrypt_element(encrypted_data_3, key)

    def testDecryptElementInplace(self):
        """
        Tests the decrypt_element method of the OneLogin_Saml2_Utils with inplace=True
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())

        key = settings.get_sp_key()

        xml_nameid_enc = b64decode(self.file_contents(join(self.data_path, 'responses', 'response_encrypted_nameid.xml.base64')))
        dom = fromstring(xml_nameid_enc)
        encrypted_node = dom.xpath('//saml:EncryptedID/xenc:EncryptedData', namespaces=OneLogin_Saml2_Constants.NSMAP)[0]

        # can be decrypted twice when copy the node first
        for _ in range(2):
            decrypted_nameid = OneLogin_Saml2_Utils.decrypt_element(encrypted_node, key, inplace=False)
            self.assertIn('NameID', decrypted_nameid.tag)
            self.assertEqual('2de11defd199f8d5bb63f9b7deb265ba5c675c10', decrypted_nameid.text)

        # can only be decrypted once in place
        decrypted_nameid = OneLogin_Saml2_Utils.decrypt_element(encrypted_node, key, inplace=True)
        self.assertIn('NameID', decrypted_nameid.tag)
        self.assertEqual('2de11defd199f8d5bb63f9b7deb265ba5c675c10', decrypted_nameid.text)

        # can't be decrypted twice since it has been decrypted inplace
        with self.assertRaisesRegex(Exception, "(1, 'failed to decrypt')"):
            OneLogin_Saml2_Utils.decrypt_element(encrypted_node, key, inplace=True)

    def testAddSign(self):
        """
        Tests the add_sign method of the OneLogin_Saml2_Utils
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        key = settings.get_sp_key()
        cert = settings.get_sp_cert()

        xml_authn = b64decode(self.file_contents(join(self.data_path, 'requests', 'authn_request.xml.base64')))
        xml_authn_signed = compat.to_string(OneLogin_Saml2_Utils.add_sign(xml_authn, key, cert))
        self.assertIn('<ds:SignatureValue>', xml_authn_signed)

        res = parseString(xml_authn_signed)
        ds_signature = res.firstChild.firstChild.nextSibling.nextSibling
        self.assertIn('ds:Signature', ds_signature.tagName)

        xml_authn_dom = parseString(xml_authn)
        xml_authn_signed_2 = compat.to_string(OneLogin_Saml2_Utils.add_sign(xml_authn_dom.toxml(), key, cert))
        self.assertIn('<ds:SignatureValue>', xml_authn_signed_2)
        res_2 = parseString(xml_authn_signed_2)
        ds_signature_2 = res_2.firstChild.firstChild.nextSibling.nextSibling
        self.assertIn('ds:Signature', ds_signature_2.tagName)

        xml_authn_signed_3 = compat.to_string(OneLogin_Saml2_Utils.add_sign(xml_authn_dom.firstChild.toxml(), key, cert))
        self.assertIn('<ds:SignatureValue>', xml_authn_signed_3)
        res_3 = parseString(xml_authn_signed_3)
        ds_signature_3 = res_3.firstChild.firstChild.nextSibling.nextSibling
        self.assertIn('ds:Signature', ds_signature_3.tagName)

        xml_authn_etree = etree.fromstring(xml_authn)
        xml_authn_signed_4 = compat.to_string(OneLogin_Saml2_Utils.add_sign(xml_authn_etree, key, cert))
        self.assertIn('<ds:SignatureValue>', xml_authn_signed_4)
        res_4 = parseString(xml_authn_signed_4)
        ds_signature_4 = res_4.firstChild.firstChild.nextSibling.nextSibling
        self.assertIn('ds:Signature', ds_signature_4.tagName)

        xml_authn_signed_5 = compat.to_string(OneLogin_Saml2_Utils.add_sign(xml_authn_etree, key, cert))
        self.assertIn('<ds:SignatureValue>', xml_authn_signed_5)
        res_5 = parseString(xml_authn_signed_5)
        ds_signature_5 = res_5.firstChild.firstChild.nextSibling.nextSibling
        self.assertIn('ds:Signature', ds_signature_5.tagName)

        xml_logout_req = b64decode(self.file_contents(join(self.data_path, 'logout_requests', 'logout_request.xml.base64')))
        xml_logout_req_signed = compat.to_string(OneLogin_Saml2_Utils.add_sign(xml_logout_req, key, cert))
        self.assertIn('<ds:SignatureValue>', xml_logout_req_signed)
        res_6 = parseString(xml_logout_req_signed)
        ds_signature_6 = res_6.firstChild.firstChild.nextSibling.nextSibling
        self.assertIn('ds:Signature', ds_signature_6.tagName)

        xml_logout_res = b64decode(self.file_contents(join(self.data_path, 'logout_responses', 'logout_response.xml.base64')))
        xml_logout_res_signed = compat.to_string(OneLogin_Saml2_Utils.add_sign(xml_logout_res, key, cert))
        self.assertIn('<ds:SignatureValue>', xml_logout_res_signed)
        res_7 = parseString(xml_logout_res_signed)
        ds_signature_7 = res_7.firstChild.firstChild.nextSibling.nextSibling
        self.assertIn('ds:Signature', ds_signature_7.tagName)

        xml_metadata = self.file_contents(join(self.data_path, 'metadata', 'metadata_settings1.xml'))
        xml_metadata_signed = compat.to_string(OneLogin_Saml2_Utils.add_sign(xml_metadata, key, cert))
        self.assertIn('<ds:SignatureValue>', xml_metadata_signed)
        res_8 = parseString(xml_metadata_signed)
        ds_signature_8 = res_8.firstChild.firstChild.nextSibling
        self.assertIn('ds:Signature', ds_signature_8.tagName)

    def testAddSignCheckAlg(self):
        """
        Tests the add_sign method of the OneLogin_Saml2_Utils
        Case: Review signature & digest algorithm
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        key = settings.get_sp_key()
        cert = settings.get_sp_cert()

        xml_authn = b64decode(self.file_contents(join(self.data_path, 'requests', 'authn_request.xml.base64')))
        xml_authn_signed = compat.to_string(OneLogin_Saml2_Utils.add_sign(xml_authn, key, cert))
        self.assertIn('<ds:SignatureValue>', xml_authn_signed)
        self.assertIn('<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>', xml_authn_signed)
        self.assertIn('<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>', xml_authn_signed)

        xml_authn_signed_2 = compat.to_string(OneLogin_Saml2_Utils.add_sign(xml_authn, key, cert, False, OneLogin_Saml2_Constants.RSA_SHA256, OneLogin_Saml2_Constants.SHA384))
        self.assertIn('<ds:SignatureValue>', xml_authn_signed_2)
        self.assertIn('<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#sha384"/>', xml_authn_signed_2)
        self.assertIn('<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>', xml_authn_signed_2)

        xml_authn_signed_3 = compat.to_string(OneLogin_Saml2_Utils.add_sign(xml_authn, key, cert, False, OneLogin_Saml2_Constants.RSA_SHA384, OneLogin_Saml2_Constants.SHA512))
        self.assertIn('<ds:SignatureValue>', xml_authn_signed_3)
        self.assertIn('<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>', xml_authn_signed_3)
        self.assertIn('<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"/>', xml_authn_signed_3)

    def testValidateSign(self):
        """
        Tests the validate_sign method of the OneLogin_Saml2_Utils
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        idp_data = settings.get_idp_data()
        cert = idp_data['x509cert']

        settings_2 = OneLogin_Saml2_Settings(self.loadSettingsJSON('settings2.json'))
        idp_data2 = settings_2.get_idp_data()
        cert_2 = idp_data2['x509cert']
        fingerprint_2 = OneLogin_Saml2_Utils.calculate_x509_fingerprint(cert_2)
        fingerprint_2_256 = OneLogin_Saml2_Utils.calculate_x509_fingerprint(cert_2, 'sha256')

        try:
            self.assertFalse(OneLogin_Saml2_Utils.validate_sign('', cert))
        except Exception as e:
            self.assertEqual('Empty string supplied as input', str(e))

        # expired cert
        xml_metadata_signed = self.file_contents(join(self.data_path, 'metadata', 'signed_metadata_settings1.xml'))
        self.assertTrue(OneLogin_Saml2_Utils.validate_metadata_sign(xml_metadata_signed, cert))
        # expired cert, verified it
        self.assertFalse(OneLogin_Saml2_Utils.validate_metadata_sign(xml_metadata_signed, cert, validatecert=True))

        xml_metadata_signed_2 = self.file_contents(join(self.data_path, 'metadata', 'signed_metadata_settings2.xml'))
        self.assertTrue(OneLogin_Saml2_Utils.validate_metadata_sign(xml_metadata_signed_2, cert_2))
        self.assertTrue(OneLogin_Saml2_Utils.validate_metadata_sign(xml_metadata_signed_2, None, fingerprint_2))

        xml_response_msg_signed = b64decode(self.file_contents(join(self.data_path, 'responses', 'signed_message_response.xml.base64')))

        # expired cert
        self.assertTrue(OneLogin_Saml2_Utils.validate_sign(xml_response_msg_signed, cert))
        # expired cert, verified it
        self.assertFalse(OneLogin_Saml2_Utils.validate_sign(xml_response_msg_signed, cert, validatecert=True))

        # modified cert
        other_cert_path = join(dirname(__file__), '..', '..', '..', 'certs')
        f = open(other_cert_path + '/certificate1', 'r')
        cert_x = f.read()
        f.close()
        self.assertFalse(OneLogin_Saml2_Utils.validate_sign(xml_response_msg_signed, cert_x))
        self.assertFalse(OneLogin_Saml2_Utils.validate_sign(xml_response_msg_signed, cert_x, validatecert=True))

        xml_response_msg_signed_2 = b64decode(self.file_contents(join(self.data_path, 'responses', 'signed_message_response2.xml.base64')))
        self.assertTrue(OneLogin_Saml2_Utils.validate_sign(xml_response_msg_signed_2, cert_2))
        self.assertTrue(OneLogin_Saml2_Utils.validate_sign(xml_response_msg_signed_2, None, fingerprint_2))
        self.assertTrue(OneLogin_Saml2_Utils.validate_sign(xml_response_msg_signed_2, None, fingerprint_2, 'sha1'))
        self.assertTrue(OneLogin_Saml2_Utils.validate_sign(xml_response_msg_signed_2, None, fingerprint_2_256, 'sha256'))

        xml_response_assert_signed = b64decode(self.file_contents(join(self.data_path, 'responses', 'signed_assertion_response.xml.base64')))

        # expired cert
        self.assertTrue(OneLogin_Saml2_Utils.validate_sign(xml_response_assert_signed, cert))
        # expired cert, verified it
        self.assertFalse(OneLogin_Saml2_Utils.validate_sign(xml_response_assert_signed, cert, validatecert=True))

        xml_response_assert_signed_2 = b64decode(self.file_contents(join(self.data_path, 'responses', 'signed_assertion_response2.xml.base64')))
        self.assertTrue(OneLogin_Saml2_Utils.validate_sign(xml_response_assert_signed_2, cert_2))
        self.assertTrue(OneLogin_Saml2_Utils.validate_sign(xml_response_assert_signed_2, None, fingerprint_2))

        xml_response_double_signed = b64decode(self.file_contents(join(self.data_path, 'responses', 'double_signed_response.xml.base64')))

        # expired cert
        self.assertTrue(OneLogin_Saml2_Utils.validate_sign(xml_response_double_signed, cert))
        # expired cert, verified it
        self.assertFalse(OneLogin_Saml2_Utils.validate_sign(xml_response_double_signed, cert, validatecert=True))

        xml_response_double_signed_2 = b64decode(self.file_contents(join(self.data_path, 'responses', 'double_signed_response2.xml.base64')))
        self.assertTrue(OneLogin_Saml2_Utils.validate_sign(xml_response_double_signed_2, cert_2))
        self.assertTrue(OneLogin_Saml2_Utils.validate_sign(xml_response_double_signed_2, None, fingerprint_2))

        dom = parseString(xml_response_msg_signed_2)
        self.assertTrue(OneLogin_Saml2_Utils.validate_sign(dom.toxml(), cert_2))

        dom.firstChild.firstChild.firstChild.nodeValue = 'https://idp.example.com/simplesaml/saml2/idp/metadata.php'

        dom.firstChild.getAttributeNode('ID').nodeValue = u'_34fg27g212d63k1f923845324475802ac0fc24530b'
        # Reference validation failed
        self.assertFalse(OneLogin_Saml2_Utils.validate_sign(dom.toxml(), cert_2))

        invalid_fingerprint = 'afe71c34ef740bc87434be13a2263d31271da1f9'
        # Wrong fingerprint
        self.assertFalse(OneLogin_Saml2_Utils.validate_metadata_sign(xml_metadata_signed_2, None, invalid_fingerprint))

        dom_2 = parseString(xml_response_double_signed_2)
        self.assertTrue(OneLogin_Saml2_Utils.validate_sign(dom_2.toxml(), cert_2))
        dom_2.firstChild.firstChild.firstChild.nodeValue = 'https://example.com/other-idp'
        # Modified message
        self.assertFalse(OneLogin_Saml2_Utils.validate_sign(dom_2.toxml(), cert_2))

        # Try to validate directly the Assertion
        dom_3 = parseString(xml_response_double_signed_2)
        assert_elem_3 = dom_3.firstChild.firstChild.nextSibling.nextSibling.nextSibling
        assert_elem_3.setAttributeNS(OneLogin_Saml2_Constants.NS_SAML, 'xmlns:saml', OneLogin_Saml2_Constants.NS_SAML)
        self.assertFalse(OneLogin_Saml2_Utils.validate_sign(assert_elem_3.toxml(), cert_2))

        # Wrong scheme
        no_signed = b64decode(self.file_contents(join(self.data_path, 'responses', 'invalids', 'no_signature.xml.base64')))
        self.assertFalse(OneLogin_Saml2_Utils.validate_sign(no_signed, cert))

        no_key = b64decode(self.file_contents(join(self.data_path, 'responses', 'invalids', 'no_key.xml.base64')))
        self.assertFalse(OneLogin_Saml2_Utils.validate_sign(no_key, cert))

        # Signature Wrapping attack
        wrapping_attack1 = b64decode(self.file_contents(join(self.data_path, 'responses', 'invalids', 'signature_wrapping_attack.xml.base64')))
        self.assertFalse(OneLogin_Saml2_Utils.validate_sign(wrapping_attack1, cert))
