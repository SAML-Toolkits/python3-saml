import zlib
import base64
import uuid
import urllib

from datetime import datetime
from lxml import etree
from lxml.builder import ElementMaker

def create(
    _clock=None,
    _uuid=None,
    _zlib=None,
    _base64=None,
    _urllib=None,
    **kwargs
    ):
    """Create a URL string which can be used to redirect a samlp:AuthnRequest to the identity provider.
    Return a URL string containing the idp_sso_target_url and a deflated, base64-encoded, url-encoded (in that order) samlp:AuthnRequest XML element as the value of the SAMLRequest parameter.

    Keyword arguments:
    assertion_consumer_service_url -- The URL at which the SAML assertion should be received.
    issuer -- The name of your application. Some identity providers might need this to establish the identity of the service provider requesting the login.
    name_identifier_format -- The format of the username required by this application. If you need the email address, use "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress". See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf section 8.3 for other options. Note that the identity provider might not support all options.
    idp_sso_target_url -- The URL to which the authentication request should be sent. This would be on the identity
"""
    if _clock is None:
        _clock = datetime.utcnow
    if _uuid is None:
        _uuid = uuid.uuid4
    if _zlib is None:
        _zlib = zlib
    if _base64 is None:
        _base64 = base64
    if _urllib is None:
        _urllib = urllib

    assertion_consumer_service_url = kwargs.pop(
        'assertion_consumer_service_url',
        )
    issuer = kwargs.pop('issuer')
    name_identifier_format = kwargs.pop('name_identifier_format')
    idp_sso_target_url = kwargs.pop('idp_sso_target_url')

    now = _clock()
    # Resolution finer than milliseconds not allowed
    # http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf Section
    # 1.3.3
    now = now.replace(microsecond=0)
    now_iso = now.isoformat()

    unique_id = _uuid()
    unique_id = unique_id.hex

    samlp_maker = ElementMaker(
        namespace='urn:oasis:names:tc:SAML:2.0:protocol',
        nsmap=dict(samlp='urn:oasis:names:tc:SAML:2.0:protocol'),
        )
    saml_maker = ElementMaker(
        namespace='urn:oasis:names:tc:SAML:2.0:assertion',
        nsmap=dict(saml='urn:oasis:names:tc:SAML:2.0:assertion'),
        )

    authn_request = samlp_maker.AuthRequest(
        ProtocolBinding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        Version='2.0',
        IssueInstant=now_iso,
        ID=unique_id,
        AssertionConsumerServiceURL=assertion_consumer_service_url,
        )

    saml_issuer = saml_maker.Issuer()
    saml_issuer.text = issuer
    authn_request.append(saml_issuer)

    name_id_policy = samlp_maker.NameIDPolicy(
        Format=name_identifier_format,
        AllowCreate='true',
        )
    authn_request.append(name_id_policy)

    request_authn_context = samlp_maker.RequestedAuthnContext(
        Comparison='exact',
        )
    authn_request.append(request_authn_context)

    authn_context_class_ref = saml_maker.AuthnContextClassRef()
    authn_context_class_ref.text = ('urn:oasis:names:tc:SAML:2.0:ac:classes:'
                                    + 'PasswordProtectedTransport'
                                    )
    request_authn_context.append(authn_context_class_ref)

    compressed_request = _zlib.compress(etree.tostring(authn_request))
    # Strip the first 2 bytes (header) and the last 4 bytes (checksum) to get the raw deflate
    deflated_request = compressed_request[2:-4]
    encoded_request = _base64.b64encode(deflated_request)
    urlencoded_request = _urllib.urlencode(
        [('SAMLRequest', encoded_request)],
        )

    return '{url}?{query}'.format(
        url=idp_sso_target_url,
        query=urlencoded_request,
        )
