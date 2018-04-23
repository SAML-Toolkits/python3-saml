# -*- coding: utf-8 -*-

# Copyright (c) 2010-2018 OneLogin, Inc.
# MIT License

import json
import unittest

from base64 import b64decode
from lxml import etree
from os.path import dirname, join, exists
from onelogin.saml2.utils import OneLogin_Saml2_XML


class TestOneLoginSaml2Xml(unittest.TestCase):
    data_path = join(dirname(__file__), '..', '..', '..', 'data')

    def loadSettingsJSON(self, filename=None):
        if filename:
            filename = join(dirname(__file__), '..', '..', '..', 'settings', filename)
        else:
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

    def testValidateXML(self):
        """
        Tests the validate_xml method of the OneLogin_Saml2_XML
        """
        metadata_unloaded = '<xml><EntityDescriptor>'
        res = OneLogin_Saml2_XML.validate_xml(metadata_unloaded, 'saml-schema-metadata-2.0.xsd')
        self.assertIsInstance(res, str)
        self.assertIn('unloaded_xml', res)

        metadata_invalid = self.file_contents(join(self.data_path, 'metadata', 'noentity_metadata_settings1.xml'))

        res = OneLogin_Saml2_XML.validate_xml(metadata_invalid, 'saml-schema-metadata-2.0.xsd')
        self.assertIsInstance(res, str)
        self.assertIn('invalid_xml', res)

        metadata_expired = self.file_contents(join(self.data_path, 'metadata', 'expired_metadata_settings1.xml'))
        res = OneLogin_Saml2_XML.validate_xml(metadata_expired, 'saml-schema-metadata-2.0.xsd')
        self.assertIsInstance(res, OneLogin_Saml2_XML._element_class)

        metadata_ok = self.file_contents(join(self.data_path, 'metadata', 'metadata_settings1.xml'))
        res = OneLogin_Saml2_XML.validate_xml(metadata_ok, 'saml-schema-metadata-2.0.xsd')
        self.assertIsInstance(res, OneLogin_Saml2_XML._element_class)

    def testToString(self):
        """
        Tests the to_string method of the OneLogin_Saml2_XML
        """
        xml = '<test>test1</test>'
        elem = etree.fromstring(xml)
        bxml = xml.encode('utf8')

        self.assertIs(xml, OneLogin_Saml2_XML.to_string(xml))
        self.assertIs(bxml, OneLogin_Saml2_XML.to_string(bxml))
        self.assertEqual(etree.tostring(elem), OneLogin_Saml2_XML.to_string(elem))
        with self.assertRaises(ValueError) as context:
            OneLogin_Saml2_XML.to_string(1)
            exception = context.exception
            self.assertIn("unsupported type", str(exception))

    def testToElement(self):
        """
        Tests the to_etree method of the OneLogin_Saml2_XML
        """
        xml = '<test>test1</test>'
        elem = etree.fromstring(xml)
        xml_expected = etree.tostring(elem)

        res = OneLogin_Saml2_XML.to_etree(xml)
        self.assertIsInstance(res, etree._Element)
        self.assertEqual(xml_expected, etree.tostring(res))

        res = OneLogin_Saml2_XML.to_etree(xml.encode('utf8'))
        self.assertIsInstance(res, etree._Element)
        self.assertEqual(xml_expected, etree.tostring(res))

        self.assertIsInstance(res, etree._Element)
        self.assertEqual(xml_expected, etree.tostring(res))

        res = OneLogin_Saml2_XML.to_etree(elem)
        self.assertIs(res, elem)

        with self.assertRaises(ValueError) as context:
            OneLogin_Saml2_XML.to_etree(1)
            exception = context.exception
            self.assertIn("unsupported type", str(exception))

    def testQuery(self):
        """
        Tests the query method of the OneLogin_Saml2_Utils
        """
        xml = self.file_contents(join(self.data_path, 'responses', 'valid_response.xml.base64'))
        xml = b64decode(xml)
        dom = etree.fromstring(xml)

        assertion_nodes = OneLogin_Saml2_XML.query(dom, '/samlp:Response/saml:Assertion')
        self.assertEqual(1, len(assertion_nodes))
        assertion = assertion_nodes[0]
        self.assertIn('Assertion', assertion.tag)

        attribute_statement_nodes = OneLogin_Saml2_XML.query(dom, '/samlp:Response/saml:Assertion/saml:AttributeStatement')
        self.assertEqual(1, len(assertion_nodes))
        attribute_statement = attribute_statement_nodes[0]
        self.assertIn('AttributeStatement', attribute_statement.tag)

        attribute_statement_nodes_2 = OneLogin_Saml2_XML.query(dom, './saml:AttributeStatement', assertion)
        self.assertEqual(1, len(attribute_statement_nodes_2))
        attribute_statement_2 = attribute_statement_nodes_2[0]
        self.assertEqual(attribute_statement, attribute_statement_2)

        signature_res_nodes = OneLogin_Saml2_XML.query(dom, '/samlp:Response/ds:Signature')
        self.assertEqual(1, len(signature_res_nodes))
        signature_res = signature_res_nodes[0]
        self.assertIn('Signature', signature_res.tag)

        signature_nodes = OneLogin_Saml2_XML.query(dom, '/samlp:Response/saml:Assertion/ds:Signature')
        self.assertEqual(1, len(signature_nodes))
        signature = signature_nodes[0]
        self.assertIn('Signature', signature.tag)

        signature_nodes_2 = OneLogin_Saml2_XML.query(dom, './ds:Signature', assertion)
        self.assertEqual(1, len(signature_nodes_2))
        signature2 = signature_nodes_2[0]
        self.assertNotEqual(signature_res, signature2)
        self.assertEqual(signature, signature2)

        signature_nodes_3 = OneLogin_Saml2_XML.query(dom, './ds:SignatureValue', assertion)
        self.assertEqual(0, len(signature_nodes_3))

        signature_nodes_4 = OneLogin_Saml2_XML.query(dom, './ds:Signature/ds:SignatureValue', assertion)
        self.assertEqual(1, len(signature_nodes_4))

        signature_nodes_5 = OneLogin_Saml2_XML.query(dom, './/ds:SignatureValue', assertion)
        self.assertEqual(1, len(signature_nodes_5))
