# -*- coding: utf-8 -*-

""" OneLogin_Saml2_Auth class

Copyright (c) 2014, OneLogin, Inc.
All rights reserved.

Main class of OneLogin's Python Toolkit.

Initializes the SP SAML instance

"""

import xmlsec
from lxml import etree
from defusedxml.lxml import tostring

from onelogin.saml2 import compat
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.response import OneLogin_Saml2_Response
from onelogin.saml2.logout_response import OneLogin_Saml2_Logout_Response
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.utils import OneLogin_Saml2_Utils, OneLogin_Saml2_Error, OneLogin_Saml2_ValidationError
from onelogin.saml2.logout_request import OneLogin_Saml2_Logout_Request
from onelogin.saml2.authn_request import OneLogin_Saml2_Authn_Request


class OneLogin_Saml2_Auth(object):
    """

    This class implements the SP SAML instance.

    Defines the methods that you can invoke in your application in
    order to add SAML support (initiates SSO, initiates SLO, processes a
    SAML Response, a Logout Request or a Logout Response).
    """

    def __init__(self, request_data, old_settings=None, custom_base_path=None):
        """
        Initializes the SP SAML instance.

        :param request_data: Request Data
        :type request_data: dict

        :param old_settings: Optional. SAML Toolkit Settings
        :type old_settings: dict

        :param custom_base_path: Optional. Path where are stored the settings file and the cert folder
        :type custom_base_path: string
        """
        self.__request_data = request_data
        if isinstance(old_settings, OneLogin_Saml2_Settings):
            self.__settings = old_settings
        else:
            self.__settings = OneLogin_Saml2_Settings(old_settings, custom_base_path)
        self.__attributes = dict()
        self.__nameid = None
        self.__nameid_format = None
        self.__session_index = None
        self.__session_expiration = None
        self.__authenticated = False
        self.__errors = []
        self.__error_reason = None
        self.__last_request_id = None
        self.__last_request = None
        self.__last_response = None

    def get_settings(self):
        """
        Returns the settings info
        :return: Setting info
        :rtype: OneLogin_Saml2_Setting object
        """
        return self.__settings

    def set_strict(self, value):
        """
        Set the strict mode active/disable

        :param value:
        :type value: bool
        """
        assert isinstance(value, bool)
        self.__settings.set_strict(value)

    def process_response(self, request_id=None):
        """
        Process the SAML Response sent by the IdP.

        :param request_id: Is an optional argument. Is the ID of the AuthNRequest sent by this SP to the IdP.
        :type request_id: string

        :raises: OneLogin_Saml2_Error.SAML_RESPONSE_NOT_FOUND, when a POST with a SAMLResponse is not found
        """
        self.__errors = []

        if 'post_data' in self.__request_data and 'SAMLResponse' in self.__request_data['post_data']:
            # AuthnResponse -- HTTP_POST Binding
            response = OneLogin_Saml2_Response(self.__settings, self.__request_data['post_data']['SAMLResponse'])
            self.__last_response = response.get_xml_document()

            if response.is_valid(self.__request_data, request_id):
                self.__attributes = response.get_attributes()
                self.__nameid = response.get_nameid()
                self.__nameid_format = response.get_nameid_format()
                self.__session_index = response.get_session_index()
                self.__session_expiration = response.get_session_not_on_or_after()
                self.__authenticated = True

            else:
                self.__errors.append('invalid_response')
                self.__error_reason = response.get_error()

        else:
            self.__errors.append('invalid_binding')
            raise OneLogin_Saml2_Error(
                'SAML Response not found, Only supported HTTP_POST Binding',
                OneLogin_Saml2_Error.SAML_RESPONSE_NOT_FOUND
            )

    def process_slo(self, keep_local_session=False, request_id=None, delete_session_cb=None):
        """
        Process the SAML Logout Response / Logout Request sent by the IdP.

        :param keep_local_session: When false will destroy the local session, otherwise will destroy it
        :type keep_local_session: bool

        :param request_id: The ID of the LogoutRequest sent by this SP to the IdP
        :type request_id: string

        :returns: Redirection url
        """
        self.__errors = []

        get_data = 'get_data' in self.__request_data and self.__request_data['get_data']
        if get_data and 'SAMLResponse' in get_data:
            logout_response = OneLogin_Saml2_Logout_Response(self.__settings, get_data['SAMLResponse'])
            self.__last_response = logout_response.get_xml()
            if not self.validate_response_signature(get_data):
                self.__errors.append('invalid_logout_response_signature')
                self.__errors.append('Signature validation failed. Logout Response rejected')
            elif not logout_response.is_valid(self.__request_data, request_id):
                self.__errors.append('invalid_logout_response')
                self.__error_reason = logout_response.get_error()
            elif logout_response.get_status() != OneLogin_Saml2_Constants.STATUS_SUCCESS:
                self.__errors.append('logout_not_success')
            elif not keep_local_session:
                OneLogin_Saml2_Utils.delete_local_session(delete_session_cb)

        elif get_data and 'SAMLRequest' in get_data:
            logout_request = OneLogin_Saml2_Logout_Request(self.__settings, get_data['SAMLRequest'])
            self.__last_request = logout_request.get_xml()
            if not self.validate_request_signature(get_data):
                self.__errors.append("invalid_logout_request_signature")
                self.__errors.append('Signature validation failed. Logout Request rejected')
            elif not logout_request.is_valid(self.__request_data):
                self.__errors.append('invalid_logout_request')
                self.__error_reason = logout_request.get_error()
            else:
                if not keep_local_session:
                    OneLogin_Saml2_Utils.delete_local_session(delete_session_cb)

                in_response_to = logout_request.id
                response_builder = OneLogin_Saml2_Logout_Response(self.__settings)
                response_builder.build(in_response_to)
                self.__last_response = response_builder.get_xml()
                logout_response = response_builder.get_response()

                parameters = {'SAMLResponse': logout_response}
                if 'RelayState' in self.__request_data['get_data']:
                    parameters['RelayState'] = self.__request_data['get_data']['RelayState']

                security = self.__settings.get_security_data()
                if security['logoutResponseSigned']:
                    self.add_response_signature(parameters, security['signatureAlgorithm'])

                return self.redirect_to(self.get_slo_url(), parameters)
        else:
            self.__errors.append('invalid_binding')
            raise OneLogin_Saml2_Error(
                'SAML LogoutRequest/LogoutResponse not found. Only supported HTTP_REDIRECT Binding',
                OneLogin_Saml2_Error.SAML_LOGOUTMESSAGE_NOT_FOUND
            )

    def redirect_to(self, url=None, parameters={}):
        """
        Redirects the user to the URL passed by parameter or to the URL that we defined in our SSO Request.

        :param url: The target URL to redirect the user
        :type url: string
        :param parameters: Extra parameters to be passed as part of the URL
        :type parameters: dict

        :returns: Redirection URL
        """
        if url is None and 'RelayState' in self.__request_data['get_data']:
            url = self.__request_data['get_data']['RelayState']
        return OneLogin_Saml2_Utils.redirect(url, parameters, request_data=self.__request_data)

    def is_authenticated(self):
        """
        Checks if the user is authenticated or not.

        :returns: True if is authenticated, False if not
        :rtype: bool
        """
        return self.__authenticated

    def get_attributes(self):
        """
        Returns the set of SAML attributes.

        :returns: SAML attributes
        :rtype: dict
        """
        return self.__attributes

    def get_nameid(self):
        """
        Returns the nameID.

        :returns: NameID
        :rtype: string|None
        """
        return self.__nameid

    def get_nameid_format(self):
        """
        Returns the nameID Format.

        :returns: NameID Format
        :rtype: string|None
        """
        return self.__nameid_format

    def get_session_index(self):
        """
        Returns the SessionIndex from the AuthnStatement.
        :returns: The SessionIndex of the assertion
        :rtype: string
        """
        return self.__session_index

    def get_session_expiration(self):
        """
        Returns the SessionNotOnOrAfter from the AuthnStatement.
        :returns: The SessionNotOnOrAfter of the assertion
        :rtype: DateTime|None
        """
        return self.__session_expiration

    def get_errors(self):
        """
        Returns a list with code errors if something went wrong

        :returns: List of errors
        :rtype: list
        """
        return self.__errors

    def get_last_error_reason(self):
        """
        Returns the reason for the last error

        :returns: Reason of the last error
        :rtype: None | string
        """
        return self.__error_reason

    def get_attribute(self, name):
        """
        Returns the requested SAML attribute.

        :param name: Name of the attribute
        :type name: string

        :returns: Attribute value if exists or []
        :rtype: string
        """
        assert isinstance(name, compat.str_type)
        return self.__attributes.get(name)

    def get_last_request_id(self):
        """
        :returns: The ID of the last Request SAML message generated.
        :rtype: string
        """
        return self.__last_request_id

    def login(self, return_to=None, force_authn=False, is_passive=False, set_nameid_policy=True):
        """
        Initiates the SSO process.

        :param return_to: Optional argument. The target URL the user should be redirected to after login.
        :type return_to: string

        :param force_authn: Optional argument. When true the AuthNRequest will set the ForceAuthn='true'.
        :type force_authn: bool

        :param is_passive: Optional argument. When true the AuthNRequest will set the Ispassive='true'.
        :type is_passive: bool

        :param set_nameid_policy: Optional argument. When true the AuthNRequest will set a nameIdPolicy element.
        :type set_nameid_policy: bool

        :returns: Redirection URL
        :rtype: string
        """
        authn_request = OneLogin_Saml2_Authn_Request(self.__settings, force_authn, is_passive, set_nameid_policy)
        self.__last_request = authn_request.get_xml()
        self.__last_request_id = authn_request.get_id()

        saml_request = authn_request.get_request()
        parameters = {'SAMLRequest': saml_request}

        if return_to is not None:
            parameters['RelayState'] = return_to
        else:
            parameters['RelayState'] = OneLogin_Saml2_Utils.get_self_url_no_query(self.__request_data)

        security = self.__settings.get_security_data()
        if security.get('authnRequestsSigned', False):
            self.add_request_signature(parameters, security['signatureAlgorithm'])
        return self.redirect_to(self.get_sso_url(), parameters)

    def logout(self, return_to=None, name_id=None, session_index=None, nq=None, name_id_format=None):
        """
        Initiates the SLO process.

        :param return_to: Optional argument. The target URL the user should be redirected to after logout.
        :type return_to: string

        :param name_id: The NameID that will be set in the LogoutRequest.
        :type name_id: string

        :param session_index: SessionIndex that identifies the session of the user.
        :type session_index: string

        :param nq: IDP Name Qualifier
        :type: string

        :param name_id_format: The NameID Format that will be set in the LogoutRequest.
        :type: string

        :returns: Redirection URL
        """
        slo_url = self.get_slo_url()
        if slo_url is None:
            raise OneLogin_Saml2_Error(
                'The IdP does not support Single Log Out',
                OneLogin_Saml2_Error.SAML_SINGLE_LOGOUT_NOT_SUPPORTED
            )

        if name_id is None and self.__nameid is not None:
            name_id = self.__nameid

        if name_id_format is None and self.__nameid_format is not None:
            name_id_format = self.__nameid_format

        logout_request = OneLogin_Saml2_Logout_Request(
            self.__settings,
            name_id=name_id,
            session_index=session_index,
            nq=nq,
            name_id_format=name_id_format
        )
        self.__last_request = logout_request.get_xml()
        self.__last_request_id = logout_request.id

        parameters = {'SAMLRequest': logout_request.get_request()}
        if return_to is not None:
            parameters['RelayState'] = return_to
        else:
            parameters['RelayState'] = OneLogin_Saml2_Utils.get_self_url_no_query(self.__request_data)

        security = self.__settings.get_security_data()
        if security.get('logoutRequestSigned', False):
            self.add_request_signature(parameters, security['signatureAlgorithm'])
        return self.redirect_to(slo_url, parameters)

    def get_sso_url(self):
        """
        Gets the SSO URL.

        :returns: An URL, the SSO endpoint of the IdP
        :rtype: string
        """
        idp_data = self.__settings.get_idp_data()
        return idp_data['singleSignOnService']['url']

    def get_slo_url(self):
        """
        Gets the SLO URL.

        :returns: An URL, the SLO endpoint of the IdP
        :rtype: string
        """
        idp_data = self.__settings.get_idp_data()
        if 'url' in idp_data['singleLogoutService']:
            return idp_data['singleLogoutService']['url']

    def add_request_signature(self, request_data, sign_algorithm=OneLogin_Saml2_Constants.RSA_SHA1):
        """
        Builds the Signature of the SAML Request.

        :param request_data: The Request parameters
        :type request_data: dict

        :param sign_algorithm: Signature algorithm method
        :type sign_algorithm: string
        """
        return self.__build_signature(request_data, 'SAMLRequest', sign_algorithm)

    def add_response_signature(self, response_data, sign_algorithm=OneLogin_Saml2_Constants.RSA_SHA1):
        """
        Builds the Signature of the SAML Response.
        :param response_data: The Response parameters
        :type response_data: dict

        :param sign_algorithm: Signature algorithm method
        :type sign_algorithm: string
        """
        return self.__build_signature(response_data, 'SAMLResponse', sign_algorithm)

    @staticmethod
    def __build_sign_query(saml_data, relay_state, algorithm, saml_type, lowercase_urlencoding=False):
        """
        Build sign query

        :param saml_data: The Request data
        :type saml_data: str

        :param relay_state: The Relay State
        :type relay_state: str

        :param algorithm: The Signature Algorithm
        :type algorithm: str

        :param saml_type: The target URL the user should be redirected to
        :type saml_type: string  SAMLRequest | SAMLResponse

        :param lowercase_urlencoding: lowercase or no
        :type lowercase_urlencoding: boolean
        """
        sign_data = ['%s=%s' % (saml_type, OneLogin_Saml2_Utils.escape_url(saml_data, lowercase_urlencoding))]
        if relay_state is not None:
            sign_data.append('RelayState=%s' % OneLogin_Saml2_Utils.escape_url(relay_state, lowercase_urlencoding))
        sign_data.append('SigAlg=%s' % OneLogin_Saml2_Utils.escape_url(algorithm, lowercase_urlencoding))
        return '&'.join(sign_data)

    def __build_signature(self, data, saml_type, sign_algorithm=OneLogin_Saml2_Constants.RSA_SHA1):
        """
        Builds the Signature
        :param data: The Request data
        :type data: dict

        :param saml_type: The target URL the user should be redirected to
        :type saml_type: string  SAMLRequest | SAMLResponse

        :param sign_algorithm: Signature algorithm method
        :type sign_algorithm: string
        """
        assert saml_type in ('SAMLRequest', 'SAMLResponse')
        key = self.get_settings().get_sp_key()

        if not key:
            raise OneLogin_Saml2_Error(
                "Trying to sign the %s but can't load the SP private key." % saml_type,
                OneLogin_Saml2_Error.PRIVATE_KEY_NOT_FOUND
            )

        msg = self.__build_sign_query(data[saml_type],
                                      data.get('RelayState', None),
                                      sign_algorithm,
                                      saml_type)

        sign_algorithm_transform_map = {
            OneLogin_Saml2_Constants.DSA_SHA1: xmlsec.Transform.DSA_SHA1,
            OneLogin_Saml2_Constants.RSA_SHA1: xmlsec.Transform.RSA_SHA1,
            OneLogin_Saml2_Constants.RSA_SHA256: xmlsec.Transform.RSA_SHA256,
            OneLogin_Saml2_Constants.RSA_SHA384: xmlsec.Transform.RSA_SHA384,
            OneLogin_Saml2_Constants.RSA_SHA512: xmlsec.Transform.RSA_SHA512
        }
        sign_algorithm_transform = sign_algorithm_transform_map.get(sign_algorithm, xmlsec.Transform.RSA_SHA1)

        signature = OneLogin_Saml2_Utils.sign_binary(msg, key, sign_algorithm_transform, self.__settings.is_debug_active())
        data['Signature'] = OneLogin_Saml2_Utils.b64encode(signature)
        data['SigAlg'] = sign_algorithm

    def validate_request_signature(self, request_data):
        """
        Validate Request Signature

        :param request_data: The Request data
        :type request_data: dict

        """

        return self.__validate_signature(request_data, 'SAMLRequest')

    def validate_response_signature(self, request_data):
        """
        Validate Response Signature

        :param request_data: The Request data
        :type request_data: dict

        """

        return self.__validate_signature(request_data, 'SAMLResponse')

    def __validate_signature(self, data, saml_type, raise_exceptions=False):
        """
        Validate Signature

        :param data: The Request data
        :type data: dict

        :param cert: The certificate to check signature
        :type cert: str

        :param saml_type: The target URL the user should be redirected to
        :type saml_type: string  SAMLRequest | SAMLResponse

        :param raise_exceptions: Whether to return false on failure or raise an exception
        :type raise_exceptions: Boolean
        """
        try:
            signature = data.get('Signature', None)
            if signature is None:
                if self.__settings.is_strict() and self.__settings.get_security_data().get('wantMessagesSigned', False):
                    raise OneLogin_Saml2_ValidationError(
                        'The %s is not signed. Rejected.' % saml_type,
                        OneLogin_Saml2_ValidationError.NO_SIGNED_MESSAGE
                    )
                return True

            idp_data = self.get_settings().get_idp_data()

            exists_x509cert = 'x509cert' in idp_data and idp_data['x509cert']
            exists_multix509sign = 'x509certMulti' in idp_data and \
                'signing' in idp_data['x509certMulti'] and \
                idp_data['x509certMulti']['signing']

            if not (exists_x509cert or exists_multix509sign):
                error_msg = 'In order to validate the sign on the %s, the x509cert of the IdP is required' % saml_type
                self.__errors.append(error_msg)
                raise OneLogin_Saml2_Error(
                    error_msg,
                    OneLogin_Saml2_Error.CERT_NOT_FOUND
                )

            sign_alg = data.get('SigAlg', OneLogin_Saml2_Constants.RSA_SHA1)
            if isinstance(sign_alg, bytes):
                sign_alg = sign_alg.decode('utf8')

            lowercase_urlencoding = False
            if 'lowercase_urlencoding' in self.__request_data.keys():
                lowercase_urlencoding = self.__request_data['lowercase_urlencoding']

            signed_query = self.__build_sign_query(data[saml_type],
                                                   data.get('RelayState', None),
                                                   sign_alg,
                                                   saml_type,
                                                   lowercase_urlencoding
                                                   )

            if exists_multix509sign:
                for cert in idp_data['x509certMulti']['signing']:
                    if OneLogin_Saml2_Utils.validate_binary_sign(signed_query,
                                                                 OneLogin_Saml2_Utils.b64decode(signature),
                                                                 cert,
                                                                 sign_alg):
                        return True
                raise OneLogin_Saml2_ValidationError(
                    'Signature validation failed. %s rejected' % saml_type,
                    OneLogin_Saml2_ValidationError.INVALID_SIGNATURE
                )
            else:
                cert = idp_data['x509cert']

                if not OneLogin_Saml2_Utils.validate_binary_sign(signed_query,
                                                                 OneLogin_Saml2_Utils.b64decode(signature),
                                                                 cert,
                                                                 sign_alg,
                                                                 self.__settings.is_debug_active()):
                    raise OneLogin_Saml2_ValidationError(
                        'Signature validation failed. %s rejected' % saml_type,
                        OneLogin_Saml2_ValidationError.INVALID_SIGNATURE
                    )
            return True
        except Exception as e:
            self.__error_reason = str(e)
            if raise_exceptions:
                raise e
            return False

    def get_last_response_xml(self, pretty_print_if_possible=False):
        """
        Retrieves the raw XML (decrypted) of the last SAML response,
        or the last Logout Response generated or processed
        :returns: SAML response XML
        :rtype: string|None
        """
        response = None
        if self.__last_response is not None:
            if isinstance(self.__last_response, compat.str_type):
                response = self.__last_response
            else:
                response = tostring(self.__last_response, encoding='unicode', pretty_print=pretty_print_if_possible)
        return response

    def get_last_request_xml(self):
        """
        Retrieves the raw XML sent in the last SAML request
        :returns: SAML request XML
        :rtype: string|None
        """
        return self.__last_request or None
