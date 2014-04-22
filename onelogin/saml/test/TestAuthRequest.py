import fudge

from datetime import datetime
from nose.tools import eq_ as eq

from onelogin.saml import AuthRequest

class TestAuthRequest(object):
    def setUp(self):
        fudge.clear_expectations()

    @fudge.with_fakes
    def test_create(self):
        fake_uuid_func = fudge.Fake('uuid', callable=True)
        fake_uuid_func.with_arg_count(0)
        fake_uuid = fudge.Fake('foo_uuid')
        fake_uuid.has_attr(hex='hex_uuid')
        fake_uuid = fake_uuid_func.returns(fake_uuid)

        def fake_clock():
            return datetime(2011, 7, 9, 19, 24, 52, 325405)

        fake_zlib = fudge.Fake('zlib')
        fake_zlib.remember_order()
        fake_compress = fake_zlib.expects('compress')
        fake_compress.with_args(
"""<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0" IssueInstant="2011-07-09T19:24:52" ID="hex_uuid" AssertionConsumerServiceURL="http://foo.bar/consume"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">foo_issuer</saml:Issuer><samlp:NameIDPolicy AllowCreate="true" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"/><samlp:RequestedAuthnContext Comparison="exact"><saml:AuthnContextClassRef xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></samlp:RequestedAuthnContext></samlp:AuthnRequest>"""
)
        fake_compress.returns('HDfoo_compressedCHCK')

        fake_base64 = fudge.Fake('base64')
        fake_base64.remember_order()
        fake_encode = fake_base64.expects('b64encode')
        fake_encode.with_args('foo_compressed')
        fake_encode.returns('foo_encoded')

        fake_urllib = fudge.Fake('urllib')
        fake_urllib.remember_order()
        fake_urlencode = fake_urllib.expects('urlencode')
        fake_urlencode.with_args(
            [('SAMLRequest', 'foo_encoded')],
            )
        fake_urlencode.returns('foo_urlencoded')

        req = AuthRequest.create(
            _clock=fake_clock,
            _uuid=fake_uuid_func,
            _zlib=fake_zlib,
            _base64=fake_base64,
            _urllib=fake_urllib,
            assertion_consumer_service_url='http://foo.bar/consume',
            issuer='foo_issuer',
            name_identifier_format=('urn:oasis:names:tc:SAML:1.1:nameid-format:'
                                    + 'emailAddress'
                                    ),
            idp_sso_target_url='http://foo.idp.bar',
            )

        eq(req, 'http://foo.idp.bar?foo_urlencoded')
