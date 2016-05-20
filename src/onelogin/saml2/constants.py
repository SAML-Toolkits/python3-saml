# -*- coding: utf-8 -*-

""" OneLogin_Saml2_Constants class

Copyright (c) 2014, OneLogin, Inc.
All rights reserved.

Constants class of OneLogin's Python Toolkit.

"""


class OneLogin_Saml2_Constants(object):
    """

    This class defines all the constants that will be used
    in the OneLogin's Python Toolkit.

    """

    # Value added to the current time in time condition validations
    ALLOWED_CLOCK_DRIFT = 300

    # NameID Formats
    NAMEID_EMAIL_ADDRESS = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
    NAMEID_X509_SUBJECT_NAME = 'urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName'
    NAMEID_WINDOWS_DOMAIN_QUALIFIED_NAME = 'urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName'
    NAMEID_UNSPECIFIED = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'
    NAMEID_KERBEROS = 'urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos'
    NAMEID_ENTITY = 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity'
    NAMEID_TRANSIENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'
    NAMEID_PERSISTENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'
    NAMEID_ENCRYPTED = 'urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted'

    # Attribute Name Formats
    ATTRNAME_FORMAT_UNSPECIFIED = 'urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified'
    ATTRNAME_FORMAT_URI = 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri'
    ATTRNAME_FORMAT_BASIC = 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic'

    # Namespaces
    NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion'
    NS_SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol'
    NS_SOAP = 'http://schemas.xmlsoap.org/soap/envelope/'
    NS_MD = 'urn:oasis:names:tc:SAML:2.0:metadata'
    NS_XS = 'http://www.w3.org/2001/XMLSchema'
    NS_XSI = 'http://www.w3.org/2001/XMLSchema-instance'
    NS_XENC = 'http://www.w3.org/2001/04/xmlenc#'
    NS_DS = 'http://www.w3.org/2000/09/xmldsig#'

    # Bindings
    BINDING_HTTP_POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
    BINDING_HTTP_REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
    BINDING_HTTP_ARTIFACT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact'
    BINDING_SOAP = 'urn:oasis:names:tc:SAML:2.0:bindings:SOAP'
    BINDING_DEFLATE = 'urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE'

    # Auth Context Class
    AC_UNSPECIFIED = 'urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified'
    AC_PASSWORD = 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password'
    AC_PASSWORD_PROTECTED = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
    AC_X509 = 'urn:oasis:names:tc:SAML:2.0:ac:classes:X509'
    AC_SMARTCARD = 'urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard'
    AC_KERBEROS = 'urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos'

    # Subject Confirmation
    CM_BEARER = 'urn:oasis:names:tc:SAML:2.0:cm:bearer'
    CM_HOLDER_KEY = 'urn:oasis:names:tc:SAML:2.0:cm:holder-of-key'
    CM_SENDER_VOUCHES = 'urn:oasis:names:tc:SAML:2.0:cm:sender-vouches'

    # Status Codes
    STATUS_SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success'
    STATUS_REQUESTER = 'urn:oasis:names:tc:SAML:2.0:status:Requester'
    STATUS_RESPONDER = 'urn:oasis:names:tc:SAML:2.0:status:Responder'
    STATUS_VERSION_MISMATCH = 'urn:oasis:names:tc:SAML:2.0:status:VersionMismatch'
    STATUS_NO_PASSIVE = 'urn:oasis:names:tc:SAML:2.0:status:NoPassive'
    STATUS_PARTIAL_LOGOUT = 'urn:oasis:names:tc:SAML:2.0:status:PartialLogout'
    STATUS_PROXY_COUNT_EXCEEDED = 'urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded'

    # Namespaces
    NSMAP = {
        'samlp': NS_SAMLP,
        'saml': NS_SAML,
        'ds': NS_DS,
        'xenc': NS_XENC,
        'md': NS_MD
    }

    # Sign & Crypto
    SHA1 = 'http://www.w3.org/2000/09/xmldsig#sha1'
    SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256'
    SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#sha384'
    SHA512 = 'http://www.w3.org/2001/04/xmlenc#sha512'

    DSA_SHA1 = 'http://www.w3.org/2000/09/xmld/sig#dsa-sha1'
    RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
    RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
    RSA_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384'
    RSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512'

    # Enc
    TRIPLEDES_CBC = 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc'
    AES128_CBC = 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
    AES192_CBC = 'http://www.w3.org/2001/04/xmlenc#aes192-cbc'
    AES256_CBC = 'http://www.w3.org/2001/04/xmlenc#aes256-cbc'
    RSA_1_5 = 'http://www.w3.org/2001/04/xmlenc#rsa-1_5'
    RSA_OAEP_MGF1P = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'
