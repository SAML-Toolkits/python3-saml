# -*- coding: utf-8 -*-

# Copyright (c) 2010-2018 OneLogin, Inc.
# MIT License

import json
from os.path import dirname, join, exists
from time import strftime
from datetime import datetime
import unittest

from onelogin.saml2 import compat
from onelogin.saml2.metadata import OneLogin_Saml2_Metadata
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from onelogin.saml2.xml_utils import OneLogin_Saml2_XML


class OneLogin_Saml2_Metadata_Test(unittest.TestCase):
    def loadSettingsJSON(self, filename='settings1.json'):
        filename = join(dirname(__file__), '..', '..', '..', 'settings', filename)
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

    def testBuilder(self):
        """
        Tests the builder method of the OneLogin_Saml2_Metadata
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        sp_data = settings.get_sp_data()
        security = settings.get_security_data()
        organization = settings.get_organization()
        contacts = settings.get_contacts()

        metadata = OneLogin_Saml2_Metadata.builder(
            sp_data, security['authnRequestsSigned'],
            security['wantAssertionsSigned'], None, None, contacts,
            organization
        )

        self.assertIsNotNone(metadata)

        self.assertIn('<md:SPSSODescriptor', metadata)
        self.assertIn('entityID="http://stuff.com/endpoints/metadata.php"', metadata)
        self.assertIn('AuthnRequestsSigned="false"', metadata)
        self.assertIn('WantAssertionsSigned="false"', metadata)

        self.assertIn('<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"', metadata)
        self.assertIn('Location="http://stuff.com/endpoints/endpoints/acs.php"', metadata)
        self.assertIn('<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"', metadata)
        self.assertIn('Location="http://stuff.com/endpoints/endpoints/sls.php"', metadata)

        self.assertIn('<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>', metadata)

        self.assertIn('<md:OrganizationName xml:lang="en-US">sp_test</md:OrganizationName>', metadata)
        self.assertIn('<md:ContactPerson contactType="technical">', metadata)
        self.assertIn('<md:GivenName>technical_name</md:GivenName>', metadata)

        security['authnRequestsSigned'] = True
        security['wantAssertionsSigned'] = True
        del sp_data['singleLogoutService']['url']

        metadata2 = OneLogin_Saml2_Metadata.builder(
            sp_data, security['authnRequestsSigned'],
            security['wantAssertionsSigned']
        )

        self.assertIsNotNone(metadata2)
        self.assertIn('<md:SPSSODescriptor', metadata2)

        self.assertIn('AuthnRequestsSigned="true"', metadata2)
        self.assertIn('WantAssertionsSigned="true"', metadata2)

        self.assertNotIn('<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"', metadata2)
        self.assertNotIn(' Location="http://stuff.com/endpoints/endpoints/sls.php"/>', metadata2)

        metadata3 = OneLogin_Saml2_Metadata.builder(
            sp_data, security['authnRequestsSigned'],
            security['wantAssertionsSigned'],
            '2014-10-01T11:04:29Z',
            'P1Y',
            contacts,
            organization
        )
        self.assertIsNotNone(metadata3)
        self.assertIn('<md:SPSSODescriptor', metadata3)
        self.assertIn('cacheDuration="P1Y"', metadata3)
        self.assertIn('validUntil="2014-10-01T11:04:29Z"', metadata3)

        # Test no validUntil, only cacheDuration:
        metadata4 = OneLogin_Saml2_Metadata.builder(
            sp_data, security['authnRequestsSigned'],
            security['wantAssertionsSigned'],
            '',
            86400 * 10,  # 10 days
            contacts,
            organization
        )
        self.assertIsNotNone(metadata4)
        self.assertIn('<md:SPSSODescriptor', metadata4)
        self.assertIn('cacheDuration="PT864000S"', metadata4)
        self.assertNotIn('validUntil', metadata4)

        # Test no cacheDuration, only validUntil:
        metadata5 = OneLogin_Saml2_Metadata.builder(
            sp_data, security['authnRequestsSigned'],
            security['wantAssertionsSigned'],
            '2014-10-01T11:04:29Z',
            '',
            contacts,
            organization
        )
        self.assertIsNotNone(metadata5)
        self.assertIn('<md:SPSSODescriptor', metadata5)
        self.assertNotIn('cacheDuration', metadata5)
        self.assertIn('validUntil="2014-10-01T11:04:29Z"', metadata5)

        datetime_value = datetime.now()
        metadata6 = OneLogin_Saml2_Metadata.builder(
            sp_data, security['authnRequestsSigned'],
            security['wantAssertionsSigned'],
            datetime_value,
            'P1Y',
            contacts,
            organization
        )
        self.assertIsNotNone(metadata5)
        self.assertIn('<md:SPSSODescriptor', metadata6)
        self.assertIn('cacheDuration="P1Y"', metadata6)
        parsed_datetime = strftime(r'%Y-%m-%dT%H:%M:%SZ', datetime_value.timetuple())
        self.assertIn('validUntil="%s"' % parsed_datetime, metadata6)

    def testBuilderAttributeConsumingService(self):
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON('settings4.json'))
        sp_data = settings.get_sp_data()
        security = settings.get_security_data()
        organization = settings.get_organization()
        contacts = settings.get_contacts()

        metadata = OneLogin_Saml2_Metadata.builder(
            sp_data, security['authnRequestsSigned'],
            security['wantAssertionsSigned'], None, None, contacts,
            organization
        )
        self.assertIn("""        <md:AttributeConsumingService index="1">
            <md:ServiceName xml:lang="en">Test Service</md:ServiceName>
            <md:ServiceDescription xml:lang="en">Test Service</md:ServiceDescription>
            <md:RequestedAttribute Name="urn:oid:2.5.4.42" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="givenName" />
            <md:RequestedAttribute Name="urn:oid:2.5.4.4" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="sn" />
            <md:RequestedAttribute Name="urn:oid:2.16.840.1.113730.3.1.241" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="displayName" />
            <md:RequestedAttribute Name="urn:oid:0.9.2342.19200300.100.1.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="mail" />
            <md:RequestedAttribute Name="urn:oid:0.9.2342.19200300.100.1.1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="uid" />
        </md:AttributeConsumingService>""", metadata)

    def testBuilderAttributeConsumingServiceWithMultipleAttributeValue(self):
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON('settings5.json'))
        sp_data = settings.get_sp_data()
        security = settings.get_security_data()
        organization = settings.get_organization()
        contacts = settings.get_contacts()

        metadata = OneLogin_Saml2_Metadata.builder(
            sp_data, security['authnRequestsSigned'],
            security['wantAssertionsSigned'], None, None, contacts,
            organization
        )
        self.assertIn("""        <md:AttributeConsumingService index="1">
            <md:ServiceName xml:lang="en">Test Service</md:ServiceName>
            <md:ServiceDescription xml:lang="en">Test Service</md:ServiceDescription>
            <md:RequestedAttribute Name="userType" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
                <saml:AttributeValue xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">userType</saml:AttributeValue>
                <saml:AttributeValue xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">admin</saml:AttributeValue>
            </md:RequestedAttribute>
            <md:RequestedAttribute Name="urn:oid:0.9.2342.19200300.100.1.1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="uid" />
        </md:AttributeConsumingService>""", metadata)

    def testSignMetadata(self):
        """
        Tests the signMetadata method of the OneLogin_Saml2_Metadata
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        sp_data = settings.get_sp_data()
        security = settings.get_security_data()

        metadata = OneLogin_Saml2_Metadata.builder(
            sp_data, security['authnRequestsSigned'],
            security['wantAssertionsSigned']
        )

        self.assertIsNotNone(metadata)

        cert_path = settings.get_cert_path()
        key = self.file_contents(join(cert_path, 'sp.key'))
        cert = self.file_contents(join(cert_path, 'sp.crt'))

        signed_metadata = compat.to_string(OneLogin_Saml2_Metadata.sign_metadata(metadata, key, cert))
        self.assertTrue(OneLogin_Saml2_Utils.validate_metadata_sign(signed_metadata, cert))

        self.assertIn('<md:SPSSODescriptor', signed_metadata)
        self.assertIn('entityID="http://stuff.com/endpoints/metadata.php"', signed_metadata)
        self.assertIn('ID="ONELOGIN_', signed_metadata)
        self.assertIn('AuthnRequestsSigned="false"', signed_metadata)
        self.assertIn('WantAssertionsSigned="false"', signed_metadata)

        self.assertIn('<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"', signed_metadata)
        self.assertIn('Location="http://stuff.com/endpoints/endpoints/acs.php"', signed_metadata)
        self.assertIn('<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"', signed_metadata)
        self.assertIn(' Location="http://stuff.com/endpoints/endpoints/sls.php"/>', signed_metadata)

        self.assertIn('<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>', signed_metadata)

        self.assertIn('<ds:SignedInfo>\n<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>', signed_metadata)
        self.assertIn('<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>', signed_metadata)
        self.assertIn('<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>', signed_metadata)
        self.assertIn('<ds:Reference', signed_metadata)
        self.assertIn('<ds:KeyInfo>\n<ds:X509Data>\n<ds:X509Certificate>', signed_metadata)

        with self.assertRaises(Exception) as context:
            OneLogin_Saml2_Metadata.sign_metadata('', key, cert)
            exception = context.exception
            self.assertIn("Empty string supplied as input", str(exception))

        signed_metadata_2 = compat.to_string(OneLogin_Saml2_Metadata.sign_metadata(metadata, key, cert, OneLogin_Saml2_Constants.RSA_SHA256, OneLogin_Saml2_Constants.SHA384))
        self.assertTrue(OneLogin_Saml2_Utils.validate_metadata_sign(signed_metadata_2, cert))

        self.assertIn('<md:SPSSODescriptor', signed_metadata_2)
        self.assertIn('entityID="http://stuff.com/endpoints/metadata.php"', signed_metadata_2)
        self.assertIn('ID="ONELOGIN_', signed_metadata_2)
        self.assertIn('AuthnRequestsSigned="false"', signed_metadata_2)
        self.assertIn('WantAssertionsSigned="false"', signed_metadata_2)

        self.assertIn('<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"', signed_metadata_2)
        self.assertIn('Location="http://stuff.com/endpoints/endpoints/acs.php"', signed_metadata_2)
        self.assertIn('<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"', signed_metadata_2)
        self.assertIn(' Location="http://stuff.com/endpoints/endpoints/sls.php"/>', signed_metadata_2)

        self.assertIn('<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>', signed_metadata_2)

        self.assertIn('<ds:SignedInfo>\n<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>', signed_metadata_2)
        self.assertIn('<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#sha384"/>', signed_metadata_2)
        self.assertIn('<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>', signed_metadata_2)
        self.assertIn('<ds:Reference', signed_metadata_2)
        self.assertIn('<ds:KeyInfo>\n<ds:X509Data>\n<ds:X509Certificate>', signed_metadata_2)

        root = OneLogin_Saml2_XML.to_etree(signed_metadata_2)
        first_child = OneLogin_Saml2_XML.query(root, '/md:EntityDescriptor/*[1]')[0]
        self.assertEqual('{http://www.w3.org/2000/09/xmldsig#}Signature', first_child.tag)

    def testAddX509KeyDescriptors(self):
        """
        Tests the addX509KeyDescriptors method of the OneLogin_Saml2_Metadata
        """
        settings = OneLogin_Saml2_Settings(self.loadSettingsJSON())
        sp_data = settings.get_sp_data()

        metadata = OneLogin_Saml2_Metadata.builder(sp_data)
        self.assertNotIn('<md:KeyDescriptor use="signing"', metadata)
        self.assertNotIn('<md:KeyDescriptor use="encryption"', metadata)

        metadata_without_descriptors = OneLogin_Saml2_Metadata.add_x509_key_descriptors(metadata, None)
        self.assertNotIn('<md:KeyDescriptor use="signing"', metadata_without_descriptors)
        self.assertNotIn('<md:KeyDescriptor use="encryption"', metadata_without_descriptors)

        metadata_without_descriptors = OneLogin_Saml2_Metadata.add_x509_key_descriptors(metadata, '')
        self.assertNotIn('<md:KeyDescriptor use="signing"', metadata_without_descriptors)
        self.assertNotIn('<md:KeyDescriptor use="encryption"', metadata_without_descriptors)

        cert_path = settings.get_cert_path()
        cert = self.file_contents(join(cert_path, 'sp.crt'))

        metadata_with_descriptors = compat.to_string(OneLogin_Saml2_Metadata.add_x509_key_descriptors(metadata, cert))
        self.assertIn('<md:KeyDescriptor use="signing"', metadata_with_descriptors)
        self.assertIn('<md:KeyDescriptor use="encryption"', metadata_with_descriptors)

        with self.assertRaises(Exception) as context:
            OneLogin_Saml2_Metadata.add_x509_key_descriptors('', cert)
            exception = context.exception
            self.assertIn("Error parsing metadata", str(exception))

        base_path = dirname(dirname(dirname(dirname(__file__))))
        unparsed_metadata = self.file_contents(join(base_path, 'data', 'metadata', 'unparsed_metadata.xml'))

        with self.assertRaises(Exception) as context:
            OneLogin_Saml2_Metadata.add_x509_key_descriptors(unparsed_metadata, cert)
            exception = context.exception
            self.assertIn("Error parsing metadata", str(exception))
