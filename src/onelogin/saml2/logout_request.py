# -*- coding: utf-8 -*-

""" OneLogin_Saml2_Logout_Request class

Copyright (c) 2014, OneLogin, Inc.
All rights reserved.

Logout Request class of OneLogin's Python Toolkit.

"""

from onelogin.saml2 import compat
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.utils import OneLogin_Saml2_Utils, OneLogin_Saml2_Error, OneLogin_Saml2_ValidationError
from onelogin.saml2.xml_templates import OneLogin_Saml2_Templates
from onelogin.saml2.xml_utils import OneLogin_Saml2_XML


class OneLogin_Saml2_Logout_Request(object):
    """

    This class handles a Logout Request.

    Builds a Logout Response object and validates it.

    """

    def __init__(self, settings, request=None, name_id=None, session_index=None, nq=None, name_id_format=None):
        """
        Constructs the Logout Request object.

        :param settings: Setting data
        :type settings: OneLogin_Saml2_Settings

        :param request: Optional. A LogoutRequest to be loaded instead build one.
        :type request: string

        :param name_id: The NameID that will be set in the LogoutRequest.
        :type name_id: string

        :param session_index: SessionIndex that identifies the session of the user.
        :type session_index: string

        :param nq: IDP Name Qualifier
        :type: string

        :param name_id_format: The NameID Format that will be set in the LogoutRequest.
        :type: string
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
            if security['nameIdEncrypted']:
                exists_multix509enc = 'x509certMulti' in idp_data and \
                    'encryption' in idp_data['x509certMulti'] and \
                    idp_data['x509certMulti']['encryption']
                if exists_multix509enc:
                    cert = idp_data['x509certMulti']['encryption'][0]
                else:
                    cert = idp_data['x509cert']

            if name_id is not None:
                if name_id_format is None:
                    name_id_format = sp_data['NameIDFormat']
                sp_name_qualifier = None
            else:
                name_id = idp_data['entityId']
                name_id_format = OneLogin_Saml2_Constants.NAMEID_ENTITY
                sp_name_qualifier = sp_data['entityId']

            name_id_obj = OneLogin_Saml2_Utils.generate_name_id(
                name_id,
                sp_name_qualifier,
                name_id_format,
                cert,
                False,
                nq
            )

            if session_index:
                session_index_str = '<samlp:SessionIndex>%s</samlp:SessionIndex>' % session_index
            else:
                session_index_str = ''

            logout_request = OneLogin_Saml2_Templates.LOGOUT_REQUEST % \
                {
                    'id': uid,
                    'issue_instant': issue_instant,
                    'single_logout_url': idp_data['singleLogoutService']['url'],
                    'entity_id': sp_data['entityId'],
                    'name_id': name_id_obj,
                    'session_index': session_index_str,
                }
        else:
            logout_request = OneLogin_Saml2_Utils.decode_base64_and_inflate(request, ignore_zip=True)
            self.id = self.get_id(logout_request)

        self.__logout_request = compat.to_string(logout_request)

    def get_request(self, deflate=True):
        """
        Returns the Logout Request deflated, base64encoded
        :param deflate: It makes the deflate process optional
        :type: bool
        :return: Logout Request maybe deflated and base64 encoded
        :rtype: str object
        """
        if deflate:
            request = OneLogin_Saml2_Utils.deflate_and_base64_encode(self.__logout_request)
        else:
            request = OneLogin_Saml2_Utils.b64encode(self.__logout_request)
        return request

    def get_xml(self):
        """
        Returns the XML that will be sent as part of the request
        or that was received at the SP
        :return: XML request body
        :rtype: string
        """
        return self.__logout_request

    @staticmethod
    def get_id(request):
        """
        Returns the ID of the Logout Request
        :param request: Logout Request Message
        :type request: string|DOMDocument
        :return: string ID
        :rtype: str object
        """

        elem = OneLogin_Saml2_XML.to_etree(request)
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
        elem = OneLogin_Saml2_XML.to_etree(request)
        name_id = None
        encrypted_entries = OneLogin_Saml2_XML.query(elem, '/samlp:LogoutRequest/saml:EncryptedID')

        if len(encrypted_entries) == 1:
            if key is None:
                raise OneLogin_Saml2_Error(
                    'Private Key is required in order to decrypt the NameID, check settings',
                    OneLogin_Saml2_Error.PRIVATE_KEY_NOT_FOUND
                )

            encrypted_data_nodes = OneLogin_Saml2_XML.query(elem, '/samlp:LogoutRequest/saml:EncryptedID/xenc:EncryptedData')
            if len(encrypted_data_nodes) == 1:
                encrypted_data = encrypted_data_nodes[0]
                name_id = OneLogin_Saml2_Utils.decrypt_element(encrypted_data, key)
        else:
            entries = OneLogin_Saml2_XML.query(elem, '/samlp:LogoutRequest/saml:NameID')
            if len(entries) == 1:
                name_id = entries[0]

        if name_id is None:
            raise OneLogin_Saml2_ValidationError(
                'NameID not found in the Logout Request',
                OneLogin_Saml2_ValidationError.NO_NAMEID
            )

        name_id_data = {
            'Value': name_id.text
        }
        for attr in ['Format', 'SPNameQualifier', 'NameQualifier']:
            if attr in name_id.attrib:
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
    def get_nameid_format(request, key=None):
        """
        Gets the NameID Format of the Logout Request Message
        :param request: Logout Request Message
        :type request: string|DOMDocument
        :param key: The SP key
        :type key: string
        :return: Name ID Format
        :rtype: string
        """
        name_id_format = None
        name_id_data = OneLogin_Saml2_Logout_Request.get_nameid_data(request, key)
        if name_id_data and 'Format' in name_id_data.keys():
            name_id_format = name_id_data['Format']
        return name_id_format

    @staticmethod
    def get_issuer(request):
        """
        Gets the Issuer of the Logout Request Message
        :param request: Logout Request Message
        :type request: string|DOMDocument
        :return: The Issuer
        :rtype: string
        """

        elem = OneLogin_Saml2_XML.to_etree(request)
        issuer = None
        issuer_nodes = OneLogin_Saml2_XML.query(elem, '/samlp:LogoutRequest/saml:Issuer')
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

        elem = OneLogin_Saml2_XML.to_etree(request)
        session_indexes = []
        session_index_nodes = OneLogin_Saml2_XML.query(elem, '/samlp:LogoutRequest/samlp:SessionIndex')
        for session_index_node in session_index_nodes:
            session_indexes.append(session_index_node.text)
        return session_indexes

    def is_valid(self, request_data, raise_exceptions=False):
        """
        Checks if the Logout Request received is valid
        :param request_data: Request Data
        :type request_data: dict

        :param raise_exceptions: Whether to return false on failure or raise an exception
        :type raise_exceptions: Boolean

        :return: If the Logout Request is or not valid
        :rtype: boolean
        """
        self.__error = None
        try:
            root = OneLogin_Saml2_XML.to_etree(self.__logout_request)

            idp_data = self.__settings.get_idp_data()
            idp_entity_id = idp_data['entityId']

            get_data = ('get_data' in request_data and request_data['get_data']) or dict()

            if self.__settings.is_strict():
                res = OneLogin_Saml2_XML.validate_xml(root, 'saml-schema-protocol-2.0.xsd', self.__settings.is_debug_active())
                if isinstance(res, str):
                    raise OneLogin_Saml2_ValidationError(
                        'Invalid SAML Logout Request. Not match the saml-schema-protocol-2.0.xsd',
                        OneLogin_Saml2_ValidationError.INVALID_XML_FORMAT
                    )

                security = self.__settings.get_security_data()

                current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)

                # Check NotOnOrAfter
                if root.get('NotOnOrAfter', None):
                    na = OneLogin_Saml2_Utils.parse_SAML_to_time(root.get('NotOnOrAfter'))
                    if na <= OneLogin_Saml2_Utils.now():
                        raise OneLogin_Saml2_ValidationError(
                            'Could not validate timestamp: expired. Check system clock.)',
                            OneLogin_Saml2_ValidationError.RESPONSE_EXPIRED
                        )

                # Check destination
                if root.get('Destination', None):
                    destination = root.get('Destination')
                    if destination != '':
                        if current_url not in destination:
                            raise OneLogin_Saml2_ValidationError(
                                'The LogoutRequest was received at '
                                '%(currentURL)s instead of %(destination)s' %
                                {
                                    'currentURL': current_url,
                                    'destination': destination,
                                },
                                OneLogin_Saml2_ValidationError.WRONG_DESTINATION
                            )

                # Check issuer
                issuer = OneLogin_Saml2_Logout_Request.get_issuer(root)
                if issuer is not None and issuer != idp_entity_id:
                    raise OneLogin_Saml2_ValidationError(
                        'Invalid issuer in the Logout Request',
                        OneLogin_Saml2_ValidationError.WRONG_ISSUER
                    )

                if security['wantMessagesSigned']:
                    if 'Signature' not in get_data:
                        raise OneLogin_Saml2_ValidationError(
                            'The Message of the Logout Request is not signed and the SP require it',
                            OneLogin_Saml2_ValidationError.NO_SIGNED_MESSAGE
                        )

            return True
        except Exception as err:
            # pylint: disable=R0801
            self.__error = str(err)
            debug = self.__settings.is_debug_active()
            if debug:
                print(err)
            if raise_exceptions:
                raise
            return False

    def get_error(self):
        """
        After executing a validation process, if it fails this method returns the cause
        """
        return self.__error
