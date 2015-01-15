# -*- coding: utf-8 -*-

""" OneLogin_Saml2_Metadata class

Copyright (c) 2014, OneLogin, Inc.
All rights reserved.

Metadata class of OneLogin's Python Toolkit.

"""

from time import gmtime, strftime
from datetime import datetime
from defusedxml.minidom import parseString

from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.utils import OneLogin_Saml2_Utils


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

        :param valid_until: Metadata's valid time
        :type valid_until: string|DateTime

        :param cache_duration: Duration of the cache in seconds
        :type cache_duration: string|Timestamp

        :param contacts: Contacts info
        :type contacts: dict

        :param organization: Organization ingo
        :type organization: dict
        """
        if valid_until is None:
            valid_until = int(datetime.now().strftime("%s")) + OneLogin_Saml2_Metadata.TIME_VALID
        if not isinstance(valid_until, basestring):
            valid_until_time = gmtime(valid_until)
            valid_until_time = strftime(r'%Y-%m-%dT%H:%M:%SZ', valid_until_time)
        else:
            valid_until_time = valid_until

        if cache_duration is None:
            cache_duration = int(datetime.now().strftime("%s")) + OneLogin_Saml2_Metadata.TIME_CACHED
        if not isinstance(cache_duration, basestring):
            cache_duration_str = 'PT%sS' % cache_duration
        else:
            cache_duration_str = cache_duration

        if contacts is None:
            contacts = {}
        if organization is None:
            organization = {}

        sls = ''
        if 'singleLogoutService' in sp:
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
                org = """    <md:Organization>
        <md:OrganizationName xml:lang="%(lang)s">%(name)s</md:OrganizationName>
        <md:OrganizationDisplayName xml:lang="%(lang)s">%(display_name)s</md:OrganizationDisplayName>
        <md:OrganizationURL xml:lang="%(lang)s">%(url)s</md:OrganizationURL>
    </md:Organization>""" % \
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
                contact = """    <md:ContactPerson contactType="%(type)s">
        <md:GivenName>%(name)s</md:GivenName>
        <md:EmailAddress>%(email)s</md:EmailAddress>
    </md:ContactPerson>""" % \
                    {
                        'type': ctype,
                        'name': info['givenName'],
                        'email': info['emailAddress'],
                    }
                contacts_info.append(contact)
            str_contacts = '\n'.join(contacts_info)

        metadata = """<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     validUntil="%(valid)s"
                     cacheDuration="%(cache)s"
                     entityID="%(entity_id)s">
    <md:SPSSODescriptor AuthnRequestsSigned="%(authnsign)s" WantAssertionsSigned="%(wsign)s" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
%(sls)s        <md:NameIDFormat>%(name_id_format)s</md:NameIDFormat>
        <md:AssertionConsumerService Binding="%(binding)s"
                                     Location="%(location)s"
                                     index="1" />
    </md:SPSSODescriptor>
%(organization)s
%(contacts)s
</md:EntityDescriptor>""" % \
            {
                'valid': valid_until_time,
                'cache': cache_duration_str,
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
    def sign_metadata(metadata, key, cert):
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
        """
        return OneLogin_Saml2_Utils.add_sign(metadata, key, cert)

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
            xml = parseString(metadata)
        except Exception as e:
            raise Exception('Error parsing metadata. ' + e.message)

        formated_cert = OneLogin_Saml2_Utils.format_cert(cert, False)
        x509_certificate = xml.createElementNS(OneLogin_Saml2_Constants.NS_DS, 'ds:X509Certificate')
        content = xml.createTextNode(formated_cert)
        x509_certificate.appendChild(content)

        key_data = xml.createElementNS(OneLogin_Saml2_Constants.NS_DS, 'ds:X509Data')
        key_data.appendChild(x509_certificate)

        key_info = xml.createElementNS(OneLogin_Saml2_Constants.NS_DS, 'ds:KeyInfo')
        key_info.appendChild(key_data)

        key_descriptor = xml.createElementNS(OneLogin_Saml2_Constants.NS_DS, 'md:KeyDescriptor')

        entity_descriptor = xml.getElementsByTagName('md:EntityDescriptor')[0]

        sp_sso_descriptor = entity_descriptor.getElementsByTagName('md:SPSSODescriptor')[0]
        sp_sso_descriptor.insertBefore(key_descriptor.cloneNode(True), sp_sso_descriptor.firstChild)
        sp_sso_descriptor.insertBefore(key_descriptor.cloneNode(True), sp_sso_descriptor.firstChild)

        signing = xml.getElementsByTagName('md:KeyDescriptor')[0]
        signing.setAttribute('use', 'signing')

        encryption = xml.getElementsByTagName('md:KeyDescriptor')[1]
        encryption.setAttribute('use', 'encryption')

        signing.appendChild(key_info)
        encryption.appendChild(key_info.cloneNode(True))

        signing.setAttribute('xmlns:ds', OneLogin_Saml2_Constants.NS_DS)
        encryption.setAttribute('xmlns:ds', OneLogin_Saml2_Constants.NS_DS)

        return xml.toxml()
