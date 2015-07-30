# -*- coding: utf-8 -*-

""" OneLoginSaml2Metadata class

Copyright (c) 2014, OneLogin, Inc.
All rights reserved.

Metadata class of OneLogin's Python Toolkit.

"""

from time import gmtime, strftime
from datetime import datetime

from onelogin.saml2 import compat
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from onelogin.saml2.xml_templates import OneLogin_Saml2_Templates
from onelogin.saml2.xml_utils import OneLogin_Saml2_XML

try:
    basestring
except NameError:
    basestring = str


class OneLogin_Saml2_Metadata(object):
    """

    A class that contains methods related to the metadata of the SP

    """

    TIME_VALID = 172800   # 2 days
    TIME_CACHED = 604800  # 1 week

    @staticmethod
    def builder(sp, authnsign=False, wsign=False, valid_until=None, cache_duration=None, contacts=None, organization=None):
        """
        Builds the metadata of the SP

        :param sp: The SP data
        :type sp: string

        :param authnsign: authnRequestsSigned attribute
        :type authnsign: string

        :param wsign: wantAssertionsSigned attribute
        :type wsign: string

        :param valid_until: Metadata's expiry date
        :type valid_until: string|DateTime|Timestamp

        :param cache_duration: Duration of the cache in seconds
        :type cache_duration: int|string

        :param contacts: Contacts info
        :type contacts: dict

        :param organization: Organization ingo
        :type organization: dict
        """
        if valid_until is None:
            valid_until = int(datetime.now().strftime("%s")) + OneLogin_Saml2_Metadata.TIME_VALID
        if not isinstance(valid_until, basestring):
            if isinstance(valid_until, datetime):
                valid_until_time = valid_until.timetuple()
            else:
                valid_until_time = gmtime(valid_until)
            valid_until_str = strftime(r'%Y-%m-%dT%H:%M:%SZ', valid_until_time)
        else:
            valid_until_str = valid_until

        if cache_duration is None:
            cache_duration = OneLogin_Saml2_Metadata.TIME_CACHED
        if not isinstance(cache_duration, compat.str_type):
            cache_duration_str = 'PT%sS' % cache_duration  # Period of Time x Seconds
        else:
            cache_duration_str = cache_duration

        if contacts is None:
            contacts = {}
        if organization is None:
            organization = {}

        sls = ''
        if 'singleLogoutService' in sp and 'url' in sp['singleLogoutService']:
            sls = """        <md:SingleLogoutService Binding="%(binding)s"
                                Location="%(location)s" />\n""" % \
                {
                    'binding': sp['singleLogoutService']['binding'],
                    'location': sp['singleLogoutService']['url'],
                }

        str_authnsign = 'true' if authnsign else 'false'
        str_wsign = 'true' if wsign else 'false'

        str_organization = ''
        if len(organization) > 0:
            organization_info = []
            for (lang, info) in organization.items():
                org = OneLogin_Saml2_Templates.MD_ORGANISATION % \
                    {
                        'lang': lang,
                        'name': info['name'],
                        'display_name': info['displayname'],
                        'url': info['url'],
                    }
                organization_info.append(org)
            str_organization = '\n'.join(organization_info)

        str_contacts = ''
        if len(contacts) > 0:
            contacts_info = []
            for (ctype, info) in contacts.items():
                contact = OneLogin_Saml2_Templates.MD_CONTACT_PERSON % \
                    {
                        'type': ctype,
                        'name': info['givenName'],
                        'email': info['emailAddress'],
                    }
                contacts_info.append(contact)
            str_contacts = '\n'.join(contacts_info)

        metadata = OneLogin_Saml2_Templates.MD_ENTITY_DESCRIPTOR % \
            {
                'valid': ('validUntil="%s"' % valid_until_str) if valid_until_str else '',
                'cache': ('cacheDuration="%s"' % cache_duration_str) if cache_duration_str else '',
                'entity_id': sp['entityId'],
                'authnsign': str_authnsign,
                'wsign': str_wsign,
                'name_id_format': sp['NameIDFormat'],
                'binding': sp['assertionConsumerService']['binding'],
                'location': sp['assertionConsumerService']['url'],
                'sls': sls,
                'organization': str_organization,
                'contacts': str_contacts,
            }

        return metadata

    @staticmethod
    def sign_metadata(metadata, key, cert, sign_algorithm=OneLogin_Saml2_Constants.RSA_SHA1):
        """
        Signs the metadata with the key/cert provided

        :param metadata: SAML Metadata XML
        :type metadata: string

        :param key: x509 key
        :type key: string

        :param cert: x509 cert
        :type cert: string

        :returns: Signed Metadata
        :rtype: string

        :param sign_algorithm: Signature algorithm method
        :type sign_algorithm: string
        """
        return OneLogin_Saml2_Utils.add_sign(metadata, key, cert, False, sign_algorithm)

    @staticmethod
    def __add_x509_key_descriptors(root, cert, signing):
        key_descriptor = OneLogin_Saml2_XML.make_child(root, '{%s}KeyDescriptor' % OneLogin_Saml2_Constants.NS_MD)
        root.remove(key_descriptor)
        root.insert(0, key_descriptor)
        key_info = OneLogin_Saml2_XML.make_child(key_descriptor, '{%s}KeyInfo' % OneLogin_Saml2_Constants.NS_DS)
        key_data = OneLogin_Saml2_XML.make_child(key_info, '{%s}X509Data' % OneLogin_Saml2_Constants.NS_DS)

        x509_certificate = OneLogin_Saml2_XML.make_child(key_data, '{%s}X509Certificate' % OneLogin_Saml2_Constants.NS_DS)
        x509_certificate.text = OneLogin_Saml2_Utils.format_cert(cert, False)
        key_descriptor.set('use', ('encryption', 'signing')[signing])

    @staticmethod
    def add_x509_key_descriptors(metadata, cert=None):
        """
        Adds the x509 descriptors (sign/encriptation) to the metadata
        The same cert will be used for sign/encrypt

        :param metadata: SAML Metadata XML
        :type metadata: string

        :param cert: x509 cert
        :type cert: string

        :returns: Metadata with KeyDescriptors
        :rtype: string
        """
        if cert is None or cert == '':
            return metadata
        try:
            root = OneLogin_Saml2_XML.to_etree(metadata)
        except Exception as e:
            raise Exception('Error parsing metadata. ' + str(e))

        assert root.tag == '{%s}EntityDescriptor' % OneLogin_Saml2_Constants.NS_MD
        try:
            sp_sso_descriptor = next(root.iterfind('.//md:SPSSODescriptor', namespaces=OneLogin_Saml2_Constants.NSMAP))
        except StopIteration:
            raise Exception('Malformed metadata.')

        OneLogin_Saml2_Metadata.__add_x509_key_descriptors(sp_sso_descriptor, cert, False)
        OneLogin_Saml2_Metadata.__add_x509_key_descriptors(sp_sso_descriptor, cert, True)
        return OneLogin_Saml2_XML.to_string(root)
