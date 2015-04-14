# -*- coding: utf-8 -*-

# Copyright (c) 2014, OneLogin, Inc.
# All rights reserved.

import json
from os.path import dirname, join, exists
import unittest

from onelogin.saml2 import compat
from onelogin.saml2.metadata import OneLogin_Saml2_Metadata
from onelogin.saml2.settings import OneLogin_Saml2_Settings


class OneLogin_Saml2_Metadata_Test(unittest.TestCase):
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

        self.assertIn('<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified</md:NameIDFormat>', metadata)

        self.assertIn('<md:OrganizationName xml:lang="en-US">sp_test</md:OrganizationName>', metadata)
        self.assertIn('<md:ContactPerson contactType="technical">', metadata)
        self.assertIn('<md:GivenName>technical_name</md:GivenName>', metadata)

        security['authnRequestsSigned'] = True
        security['wantAssertionsSigned'] = True
        del sp_data['singleLogoutService']

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
            'PT1412593469S',
            contacts,
            organization
        )
        self.assertIsNotNone(metadata3)
        self.assertIn('<md:SPSSODescriptor', metadata3)
        self.assertIn('cacheDuration="PT1412593469S"', metadata3)
        self.assertIn('validUntil="2014-10-01T11:04:29Z"', metadata3)

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

        self.assertIn('<md:SPSSODescriptor', signed_metadata)
        self.assertIn('entityID="http://stuff.com/endpoints/metadata.php"', signed_metadata)
        self.assertIn('AuthnRequestsSigned="false"', signed_metadata)
        self.assertIn('WantAssertionsSigned="false"', signed_metadata)

        self.assertIn('<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"', signed_metadata)
        self.assertIn('Location="http://stuff.com/endpoints/endpoints/acs.php"', signed_metadata)
        self.assertIn('<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"', signed_metadata)
        self.assertIn(' Location="http://stuff.com/endpoints/endpoints/sls.php"/>', signed_metadata)

        self.assertIn('<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified</md:NameIDFormat>', signed_metadata)

        self.assertIn('<ds:SignedInfo>\n<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>', signed_metadata)
        self.assertIn('<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>', signed_metadata)
        self.assertIn('<ds:Reference', signed_metadata)
        self.assertIn('<ds:KeyInfo>\n<ds:X509Data>\n<ds:X509Certificate>', signed_metadata)

        self.assertRaisesRegexp(Exception, 'Empty string supplied as input',
                                OneLogin_Saml2_Metadata.sign_metadata, '', key, cert)

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

        self.assertRaisesRegexp(Exception, 'Error parsing metadata',
                                OneLogin_Saml2_Metadata.add_x509_key_descriptors, '', cert)

        base_path = dirname(dirname(dirname(dirname(__file__))))
        unparsed_metadata = self.file_contents(join(base_path, 'data', 'metadata', 'unparsed_metadata.xml'))
        self.assertRaisesRegexp(Exception, 'Error parsing metadata',
                                OneLogin_Saml2_Metadata.add_x509_key_descriptors, unparsed_metadata, cert)
