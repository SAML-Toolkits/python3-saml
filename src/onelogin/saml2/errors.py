# -*- coding: utf-8 -*-

""" OneLogin_Saml2_Error class

Copyright (c) 2014, OneLogin, Inc.
All rights reserved.

Error class of OneLogin's Python Toolkit.

Defines common Error codes and has a custom initializator.

"""


class OneLogin_Saml2_Error(Exception):
    """

    This class implements a custom Exception handler.
    Defines custom error codes.

    """

    # Errors
    SETTINGS_FILE_NOT_FOUND = 0
    SETTINGS_INVALID_SYNTAX = 1
    SETTINGS_INVALID = 2
    METADATA_SP_INVALID = 3
    SP_CERTS_NOT_FOUND = 4
    REDIRECT_INVALID_URL = 5
    PUBLIC_CERT_FILE_NOT_FOUND = 6
    PRIVATE_KEY_FILE_NOT_FOUND = 7
    SAML_RESPONSE_NOT_FOUND = 8
    SAML_LOGOUTMESSAGE_NOT_FOUND = 9
    SAML_LOGOUTREQUEST_INVALID = 10
    SAML_LOGOUTRESPONSE_INVALID = 11
    SAML_SINGLE_LOGOUT_NOT_SUPPORTED = 12

    def __init__(self, message, code=0, errors=None):
        """
        Initializes the Exception instance.

        Arguments are:
            * (str)   message.   Describes the error.
            * (int)   code.      The code error (defined in the error class).
        """
        assert isinstance(message, basestring)
        assert isinstance(code, int)

        if errors is not None:
            message = message % errors

        Exception.__init__(self, message)
        self.code = code
