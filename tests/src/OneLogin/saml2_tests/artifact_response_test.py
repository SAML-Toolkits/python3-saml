from base64 import b64decode, b64encode
from lxml import etree
from datetime import datetime
from datetime import timedelta
from freezegun import freeze_time
import json
from os.path import dirname, join, exists
import unittest
from xml.dom.minidom import parseString

from onelogin.saml2 import compat
from onelogin.saml2.artifact_response import Artifact_Response
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils, OneLogin_Saml2_ValidationError
from onelogin.saml2.xml_utils import OneLogin_Saml2_XML

class Saml2_Artifact_Response_Test(unittest.TestCase):
    data_path = join(dirname(dirname(dirname(dirname(__file__)))), 'data')
    settings_path = join(dirname(dirname(dirname(dirname(__file__)))), 'settings')

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

    def testConstruct(self):
        response = self.file_contents(join(
            self.data_path, 'artifact_response', 'artifact_response.xml'
        ))
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        response_enc = Artifact_Response(settings, response)

        self.assertIsInstance(response_enc, Artifact_Response)

    def testGetResponseXml(self):
        response_data = self.file_contents(join(
            self.data_path, 'artifact_response', 'artifact_response.xml'
        ))
        response_etree = OneLogin_Saml2_XML.to_etree(response_data)
        samlp_response = OneLogin_Saml2_XML.query(response_etree, '//samlp:Response')[0]
        expected_data = b64encode(OneLogin_Saml2_XML.to_string(samlp_response))

        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        response = Artifact_Response(settings, response_data)

        self.assertEqual(
            response.get_response_xml(),
            expected_data
        )

    def testIsValid(self):
        response = self.file_contents(join(
            self.data_path, 'artifact_response', 'artifact_response.xml'
        ))
        json_settings = self.loadSettingsJSON(name='settings11.json')
        json_settings['strict'] = True
        settings = OneLogin_Saml2_Settings(json_settings)
        response = Artifact_Response(settings, response)

        self.assertTrue(response.is_valid(
            'ONELOGIN_5ba93c9db0cff93f52b521d7420e43f6eda2784f'
        ))

    def testGetIssuer(self):
        response = self.file_contents(join(
            self.data_path, 'artifact_response', 'artifact_response.xml'
        ))
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        response = Artifact_Response(settings, response)

        self.assertEqual(response.get_issuer(), 'https://idp.com/saml/idp/metadata')

    def testGetStatus(self):
        response = self.file_contents(join(
            self.data_path, 'artifact_response', 'artifact_response.xml'
        ))
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        response = Artifact_Response(settings, response)

        self.assertEqual(response.get_status(), 'urn:oasis:names:tc:SAML:2.0:status:Success')

    def testCheckStatus(self):
        response = self.file_contents(join(
            self.data_path, 'artifact_response', 'artifact_response_invalid.xml'
        ))
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        response = Artifact_Response(settings, response)

        with self.assertRaises(OneLogin_Saml2_ValidationError) as context:
            response.check_status()

        self.assertEqual(
            str(context.exception),
            'The status code of the ArtifactResponse was not Success, was Responder'
        )