# -*- coding: utf-8 -*-

""" OneLogin_Saml2_Logout_Request class

Copyright (c) 2014, OneLogin, Inc.
All rights reserved.

Logout Request class of OneLogin's Python Toolkit.

"""

from zlib import decompress
from base64 import b64decode
from lxml import etree
from defusedxml.lxml import fromstring
from urllib import quote_plus
from xml.dom.minidom import Document

from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.utils import OneLogin_Saml2_Utils


class OneLogin_Saml2_Logout_Request(object):
    """

    This class handles a Logout Request.

    Builds a Logout Response object and validates it.

    """

    def __init__(self, settings, request=None, name_id=None, session_index=None):
        """
        Constructs the Logout Request object.

        :param settings: Setting data
        :type request_data: OneLogin_Saml2_Settings

        :param request: Optional. A LogoutRequest to be loaded instead build one.
        :type request: string

        :param name_id: The NameID that will be set in the LogoutRequest.
        :type name_id: string

        :param session_index: SessionIndex that identifies the session of the user.
        :type session_index: string
        """
        self.__settings = settings
        self.__error = None
        self.id = None

        if request is None:
            sp_data = self.__settings.get_sp_data()
            idp_data = self.__settings.get_idp_data()
            security = self.__settings.get_security_data()

            uid = OneLogin_Saml2_Utils.generate_unique_id()
            self.id = uid

            issue_instant = OneLogin_Saml2_Utils.parse_time_to_SAML(OneLogin_Saml2_Utils.now())

            cert = None
            if 'nameIdEncrypted' in security and security['nameIdEncrypted']:
                cert = idp_data['x509cert']

            if name_id is not None:
                nameIdFormat = sp_data['NameIDFormat']
            else:
                name_id = idp_data['entityId']
                nameIdFormat = OneLogin_Saml2_Constants.NAMEID_ENTITY

            name_id_obj = OneLogin_Saml2_Utils.generate_name_id(
                name_id,
                sp_data['entityId'],
                nameIdFormat,
                cert
            )

            if session_index:
                session_index_str = '<samlp:SessionIndex>%s</samlp:SessionIndex>' % session_index
            else:
                session_index_str = ''

            logout_request = """<samlp:LogoutRequest
        xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        ID="%(id)s"
        Version="2.0"
        IssueInstant="%(issue_instant)s"
        Destination="%(single_logout_url)s">
        <saml:Issuer>%(entity_id)s</saml:Issuer>
        %(name_id)s
        %(session_index)s
    </samlp:LogoutRequest>""" % \
                {
                    'id': uid,
                    'issue_instant': issue_instant,
                    'single_logout_url': idp_data['singleLogoutService']['url'],
                    'entity_id': sp_data['entityId'],
                    'name_id': name_id_obj,
                    'session_index': session_index_str,
                }
        else:
            decoded = b64decode(request)
            # We try to inflate
            try:
                inflated = decompress(decoded, -15)
                logout_request = inflated
            except Exception:
                logout_request = decoded
            self.id = self.get_id(logout_request)

        self.__logout_request = logout_request

    def get_request(self):
        """
        Returns the Logout Request defated, base64encoded
        :return: Deflated base64 encoded Logout Request
        :rtype: str object
        """
        return OneLogin_Saml2_Utils.deflate_and_base64_encode(self.__logout_request)

    @staticmethod
    def get_id(request):
        """
        Returns the ID of the Logout Request
        :param request: Logout Request Message
        :type request: string|DOMDocument
        :return: string ID
        :rtype: str object
        """
        if isinstance(request, etree._Element):
            elem = request
        else:
            if isinstance(request, Document):
                request = request.toxml()
            elem = fromstring(request)
        return elem.get('ID', None)

    @staticmethod
    def get_nameid_data(request, key=None):
        """
        Gets the NameID Data of the the Logout Request
        :param request: Logout Request Message
        :type request: string|DOMDocument
        :param key: The SP key
        :type key: string
        :return: Name ID Data (Value, Format, NameQualifier, SPNameQualifier)
        :rtype: dict
        """
        if isinstance(request, etree._Element):
            elem = request
        else:
            if isinstance(request, Document):
                request = request.toxml()
            elem = fromstring(request)

        name_id = None
        encrypted_entries = OneLogin_Saml2_Utils.query(elem, '/samlp:LogoutRequest/saml:EncryptedID')

        if len(encrypted_entries) == 1:
            if key is None:
                raise Exception('Key is required in order to decrypt the NameID')

            encrypted_data_nodes = OneLogin_Saml2_Utils.query(elem, '/samlp:LogoutRequest/saml:EncryptedID/xenc:EncryptedData')
            if len(encrypted_data_nodes) == 1:
                encrypted_data = encrypted_data_nodes[0]
                name_id = OneLogin_Saml2_Utils.decrypt_element(encrypted_data, key)
        else:
            entries = OneLogin_Saml2_Utils.query(elem, '/samlp:LogoutRequest/saml:NameID')
            if len(entries) == 1:
                name_id = entries[0]

        if name_id is None:
            raise Exception('Not NameID found in the Logout Request')

        name_id_data = {
            'Value': name_id.text
        }
        for attr in ['Format', 'SPNameQualifier', 'NameQualifier']:
            if attr in name_id.attrib.keys():
                name_id_data[attr] = name_id.attrib[attr]

        return name_id_data

    @staticmethod
    def get_nameid(request, key=None):
        """
        Gets the NameID of the Logout Request Message
        :param request: Logout Request Message
        :type request: string|DOMDocument
        :param key: The SP key
        :type key: string
        :return: Name ID Value
        :rtype: string
        """
        name_id = OneLogin_Saml2_Logout_Request.get_nameid_data(request, key)
        return name_id['Value']

    @staticmethod
    def get_issuer(request):
        """
        Gets the Issuer of the Logout Request Message
        :param request: Logout Request Message
        :type request: string|DOMDocument
        :return: The Issuer
        :rtype: string
        """
        if isinstance(request, etree._Element):
            elem = request
        else:
            if isinstance(request, Document):
                request = request.toxml()
            elem = fromstring(request)

        issuer = None
        issuer_nodes = OneLogin_Saml2_Utils.query(elem, '/samlp:LogoutRequest/saml:Issuer')
        if len(issuer_nodes) == 1:
            issuer = issuer_nodes[0].text
        return issuer

    @staticmethod
    def get_session_indexes(request):
        """
        Gets the SessionIndexes from the Logout Request
        :param request: Logout Request Message
        :type request: string|DOMDocument
        :return: The SessionIndex value
        :rtype: list
        """
        if isinstance(request, etree._Element):
            elem = request
        else:
            if isinstance(request, Document):
                request = request.toxml()
            elem = fromstring(request)

        session_indexes = []
        session_index_nodes = OneLogin_Saml2_Utils.query(elem, '/samlp:LogoutRequest/samlp:SessionIndex')
        for session_index_node in session_index_nodes:
            session_indexes.append(session_index_node.text)
        return session_indexes

    def is_valid(self, request_data):
        """
        Checks if the Logout Request recieved is valid
        :param request_data: Request Data
        :type request_data: dict

        :return: If the Logout Request is or not valid
        :rtype: boolean
        """
        self.__error = None
        try:
            dom = fromstring(self.__logout_request)

            idp_data = self.__settings.get_idp_data()
            idp_entity_id = idp_data['entityId']

            if 'get_data' in request_data.keys():
                get_data = request_data['get_data']
            else:
                get_data = {}

            if self.__settings.is_strict():
                res = OneLogin_Saml2_Utils.validate_xml(dom, 'saml-schema-protocol-2.0.xsd', self.__settings.is_debug_active())
                if not isinstance(res, Document):
                    raise Exception('Invalid SAML Logout Request. Not match the saml-schema-protocol-2.0.xsd')

                security = self.__settings.get_security_data()

                current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)

                # Check NotOnOrAfter
                if dom.get('NotOnOrAfter', None):
                    na = OneLogin_Saml2_Utils.parse_SAML_to_time(dom.get('NotOnOrAfter'))
                    if na <= OneLogin_Saml2_Utils.now():
                        raise Exception('Timing issues (please check your clock settings)')

                # Check destination
                if dom.get('Destination', None):
                    destination = dom.get('Destination')
                    if destination != '':
                        if current_url not in destination:
                            raise Exception(
                                'The LogoutRequest was received at '
                                '%(currentURL)s instead of %(destination)s' %
                                {
                                    'currentURL': current_url,
                                    'destination': destination,
                                }
                            )

                # Check issuer
                issuer = OneLogin_Saml2_Logout_Request.get_issuer(dom)
                if issuer is not None and issuer != idp_entity_id:
                    raise Exception('Invalid issuer in the Logout Request')

                if security['wantMessagesSigned']:
                    if 'Signature' not in get_data:
                        raise Exception('The Message of the Logout Request is not signed and the SP require it')

            if 'Signature' in get_data:
                if 'SigAlg' not in get_data:
                    sign_alg = OneLogin_Saml2_Constants.RSA_SHA1
                else:
                    sign_alg = get_data['SigAlg']

                if sign_alg != OneLogin_Saml2_Constants.RSA_SHA1:
                    raise Exception('Invalid signAlg in the recieved Logout Request')

                signed_query = 'SAMLRequest=%s' % quote_plus(get_data['SAMLRequest'])
                if 'RelayState' in get_data:
                    signed_query = '%s&RelayState=%s' % (signed_query, quote_plus(get_data['RelayState']))
                signed_query = '%s&SigAlg=%s' % (signed_query, quote_plus(sign_alg))

                if 'x509cert' not in idp_data or idp_data['x509cert'] is None:
                    raise Exception('In order to validate the sign on the Logout Request, the x509cert of the IdP is required')
                cert = idp_data['x509cert']

                if not OneLogin_Saml2_Utils.validate_binary_sign(signed_query, b64decode(get_data['Signature']), cert):
                    raise Exception('Signature validation failed. Logout Request rejected')

            return True
        except Exception as err:
            # pylint: disable=R0801
            self.__error = err.__str__()
            debug = self.__settings.is_debug_active()
            if debug:
                print err.__str__()
            return False

    def get_error(self):
        """
        After execute a validation process, if fails this method returns the cause
        """
        return self.__error
