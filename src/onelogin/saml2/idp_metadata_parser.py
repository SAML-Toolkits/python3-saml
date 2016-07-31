# -*- coding: utf-8 -*-

""" OneLogin_Saml2_IdPMetadataParser class
Copyright (c) 2014, OneLogin, Inc.
All rights reserved.
Metadata class of OneLogin's Python Toolkit.
"""


from copy import deepcopy


try:
    import urllib.request as urllib2
except ImportError:
    import urllib2

from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.xml_utils import OneLogin_Saml2_XML


class OneLogin_Saml2_IdPMetadataParser(object):
    """
    A class that contain methods related to obtaining and parsing metadata from IdP
    """

    @staticmethod
    def get_metadata(url):
        """
        Gets the metadata XML from the provided URL
        :param url: Url where the XML of the Identity Provider Metadata is published.
        :type url: string
        :returns: metadata XML
        :rtype: string
        """
        valid = False
        response = urllib2.urlopen(url)
        xml = response.read()

        if xml:
            try:
                dom = OneLogin_Saml2_XML.to_etree(xml)
                idp_descriptor_nodes = OneLogin_Saml2_XML.query(dom, '//md:IDPSSODescriptor')
                if idp_descriptor_nodes:
                    valid = True
            except:
                pass

        if not valid:
            raise Exception('Not valid IdP XML found from URL: %s' % (url))

        return xml

    @staticmethod
    def parse_remote(url, **kwargs):
        """
        Gets the metadata XML from the provided URL and parse it, returning a dict with extracted data
        :param url: Url where the XML of the Identity Provider Metadata is published.
        :type url: string
        :returns: settings dict with extracted data
        :rtype: dict
        """
        idp_metadata = OneLogin_Saml2_IdPMetadataParser.get_metadata(url)
        return OneLogin_Saml2_IdPMetadataParser.parse(idp_metadata, **kwargs)

    @staticmethod
    def parse(
            idp_metadata,
            required_sso_binding=OneLogin_Saml2_Constants.BINDING_HTTP_REDIRECT,
            required_slo_binding=OneLogin_Saml2_Constants.BINDING_HTTP_REDIRECT):
        """
        Parses the Identity Provider metadata and return a dict with extracted data.

        If there are multiple <IDPSSODescriptor> tags, parse only the first.

        Parses only those SSO endpoints with the same binding as given by
        the `required_sso_binding` parameter.

        Parses only those SLO endpoints with the same binding as given by
        the `required_slo_binding` parameter.

        If the metadata specifies multiple SSO endpoints with the required
        binding, extract only the first (the same holds true for SLO
        endpoints).

        :param idp_metadata: XML of the Identity Provider Metadata.
        :type idp_metadata: string

        :param required_sso_binding: Parse only POST or REDIRECT SSO endpoints.
        :type required_sso_binding: one of OneLogin_Saml2_Constants.BINDING_HTTP_REDIRECT
            or OneLogin_Saml2_Constants.BINDING_HTTP_POST

        :param required_slo_binding: Parse only POST or REDIRECT SLO endpoints.
        :type required_slo_binding: one of OneLogin_Saml2_Constants.BINDING_HTTP_REDIRECT
            or OneLogin_Saml2_Constants.BINDING_HTTP_POST

        :returns: settings dict with extracted data
        :rtype: dict
        """
        data = {}

        dom = OneLogin_Saml2_XML.to_etree(idp_metadata)
        entity_descriptor_nodes = OneLogin_Saml2_XML.query(dom, '//md:EntityDescriptor')

        idp_entity_id = want_authn_requests_signed = idp_name_id_format = idp_sso_url = idp_slo_url = idp_x509_cert = None

        if len(entity_descriptor_nodes) > 0:
            for entity_descriptor_node in entity_descriptor_nodes:
                idp_descriptor_nodes = OneLogin_Saml2_XML.query(entity_descriptor_node, './md:IDPSSODescriptor')
                if len(idp_descriptor_nodes) > 0:
                    idp_descriptor_node = idp_descriptor_nodes[0]

                    idp_entity_id = entity_descriptor_node.get('entityID', None)

                    want_authn_requests_signed = entity_descriptor_node.get('WantAuthnRequestsSigned', None)

                    name_id_format_nodes = OneLogin_Saml2_XML.query(idp_descriptor_node, './md:NameIDFormat')
                    if len(name_id_format_nodes) > 0:
                        idp_name_id_format = name_id_format_nodes[0].text

                    sso_nodes = OneLogin_Saml2_XML.query(
                        idp_descriptor_node,
                        "./md:SingleSignOnService[@Binding='%s']" % required_sso_binding
                    )

                    if len(sso_nodes) > 0:
                        idp_sso_url = sso_nodes[0].get('Location', None)

                    slo_nodes = OneLogin_Saml2_XML.query(
                        idp_descriptor_node,
                        "./md:SingleLogoutService[@Binding='%s']" % required_slo_binding
                    )

                    if len(slo_nodes) > 0:
                        idp_slo_url = slo_nodes[0].get('Location', None)

                    cert_nodes = OneLogin_Saml2_XML.query(idp_descriptor_node, "./md:KeyDescriptor[@use='signing']/ds:KeyInfo/ds:X509Data/ds:X509Certificate")
                    if len(cert_nodes) > 0:
                        idp_x509_cert = cert_nodes[0].text

                    data['idp'] = {}

                    if idp_entity_id is not None:
                        data['idp']['entityId'] = idp_entity_id

                    if idp_sso_url is not None:
                        data['idp']['singleSignOnService'] = {}
                        data['idp']['singleSignOnService']['url'] = idp_sso_url
                        data['idp']['singleSignOnService']['binding'] = required_sso_binding

                    if idp_slo_url is not None:
                        data['idp']['singleLogoutService'] = {}
                        data['idp']['singleLogoutService']['url'] = idp_slo_url
                        data['idp']['singleLogoutService']['binding'] = required_slo_binding

                    if idp_x509_cert is not None:
                        data['idp']['x509cert'] = idp_x509_cert

                    if want_authn_requests_signed is not None:
                        data['security'] = {}
                        data['security']['authnRequestsSigned'] = want_authn_requests_signed

                    if idp_name_id_format:
                        data['sp'] = {}
                        data['sp']['NameIDFormat'] = idp_name_id_format

                    break
        return data

    @staticmethod
    def merge_settings(settings, new_metadata_settings):
        """
        Will update the settings with the provided new settings data extracted from the IdP metadata
        :param settings: Current settings dict data
        :type settings: string
        :param new_metadata_settings: Settings to be merged (extracted from IdP metadata after parsing)
        :type new_metadata_settings: string
        :returns: merged settings
        :rtype: dict
        """
        for d in (settings, new_metadata_settings):
            if not isinstance(d, dict):
                raise TypeError('Both arguments must be dictionaries.')

        # Guarantee to not modify original data (`settings.copy()` would not
        # be sufficient, as it's just a shallow copy).
        result_settings = deepcopy(settings)
        # Merge `new_metadata_settings` into `result_settings`.
        dict_deep_merge(result_settings, new_metadata_settings)
        return result_settings


def dict_deep_merge(a, b, path=None):
    """Deep-merge dictionary `b` into dictionary `a`.

    Kudos to http://stackoverflow.com/a/7205107/145400
    """
    if path is None:
        path = []
    for key in b:
        if key in a:
            if isinstance(a[key], dict) and isinstance(b[key], dict):
                dict_deep_merge(a[key], b[key], path + [str(key)])
            elif a[key] == b[key]:
                # Key conflict, but equal value.
                pass
            else:
                # Key/value conflict. Prioritize b over a.
                a[key] = b[key]
        else:
            a[key] = b[key]
    return a
