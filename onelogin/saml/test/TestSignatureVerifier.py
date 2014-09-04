import fudge

from lxml import etree
from nose.tools import eq_ as eq
from StringIO import StringIO

from onelogin.saml import SignatureVerifier

from onelogin.saml.test.util import assert_raises


class TestSignatureVerifier(object):
    def setUp(self):
        fudge.clear_expectations()

    @fudge.with_fakes
    def test_get_xmlsec_bin_default(self):
        fake_platform = fudge.Fake('platform')
        fake_platform.remember_order()
        system_fn = fake_platform.expects('system')
        system_fn.with_arg_count(0)
        system_fn.returns('Linux')

        xmlsec_bin = SignatureVerifier._get_xmlsec_bin(_platform=fake_platform)

        eq('xmlsec1', xmlsec_bin)

    @fudge.with_fakes
    def test_get_xmlsec_bin_windows(self):
        fake_platform = fudge.Fake('platform')
        fake_platform.remember_order()
        system_fn = fake_platform.expects('system')
        system_fn.with_arg_count(0)
        system_fn.returns('Windows')

        xmlsec_bin = SignatureVerifier._get_xmlsec_bin(_platform=fake_platform)

        eq('xmlsec.exe', xmlsec_bin)

    @fudge.with_fakes
    def test_get_parse_stderr_fail(self):
        msg = """func=xmlSecOpenSSLX509StoreVerify:file=x509vfy.c:line=360:obj=x509-store:subj=X509_verify_cert:error=4:crypto library function failed:subj=/C=US/ST=California/L=Santa Monica/O=OneLogin/CN=app.onelogin.com;err=18;msg=self signed certificate
func=xmlSecOpenSSLX509StoreVerify:file=x509vfy.c:line=408:obj=x509-store:subj=unknown:error=71:certificate verification failed:err=18;msg=self signed certificate
func=xmlSecOpenSSLEvpSignatureVerify:file=signatures.c:line=346:obj=rsa-sha1:subj=EVP_VerifyFinal:error=18:data do not match:signature do not match
FAIL
SignedInfo References (ok/all): 1/1
Manifests References (ok/all): 0/0
Error: failed to verify file "/tmp/tmpYjEjq5"
"""
        fake_proc = fudge.Fake('proc')
        stderr = StringIO(msg)
        fake_proc.has_attr(stderr=stderr)

        res = SignatureVerifier._parse_stderr(fake_proc)

        eq(res, False)

    @fudge.with_fakes
    def test_get_parse_stderr_ok(self):
        msg = """func=xmlSecOpenSSLX509StoreVerify:file=x509vfy.c:line=360:obj=x509-store:subj=X509_verify_cert:error=4:crypto library function failed:subj=/C=US/ST=California/L=Santa Monica/O=OneLogin/CN=app.onelogin.com;err=18;msg=self signed certificate
func=xmlSecOpenSSLX509StoreVerify:file=x509vfy.c:line=408:obj=x509-store:subj=unknown:error=71:certificate verification failed:err=18;msg=self signed certificate
func=xmlSecOpenSSLEvpSignatureVerify:file=signatures.c:line=346:obj=rsa-sha1:subj=EVP_VerifyFinal:error=18:data do not match:signature do not match
OK
SignedInfo References (ok/all): 1/1
Manifests References (ok/all): 0/0
Error: failed to verify file "/tmp/tmpYjEjq5"
"""
        fake_proc = fudge.Fake('proc')
        stderr = StringIO(msg)
        fake_proc.has_attr(stderr=stderr)

        res = SignatureVerifier._parse_stderr(fake_proc)

        eq(res, True)

    @fudge.with_fakes
    def test_get_parse_stderr_error(self):
        msg = 'FAILURE'
        fake_proc = fudge.Fake('proc')
        stderr = StringIO(msg)
        fake_proc.has_attr(stderr=stderr)
        fake_proc.has_attr(returncode=1)

        msg = assert_raises(
            SignatureVerifier.SignatureVerifierError,
            SignatureVerifier._parse_stderr,
            fake_proc
        )

        eq(
            str(msg),
            ('There was a problem validating the response: XMLSec returned error ' +
             'code 1. Please check your certficate.'),
        )

    @fudge.with_fakes
    def test_get_parse_stderr_error_should_not_happen(self):
        msg = 'FAILURE'
        fake_proc = fudge.Fake('proc')
        stderr = StringIO(msg)
        fake_proc.has_attr(stderr=stderr)
        fake_proc.has_attr(returncode=0)

        msg = assert_raises(
            SignatureVerifier.SignatureVerifierError,
            SignatureVerifier._parse_stderr,
            fake_proc
        )

        eq(
            str(msg),
            ('There was a problem validating the response: XMLSec exited with ' +
             'code 0 but did not return OK when verifying the  SAML response.')
        )

    @fudge.with_fakes
    def test_get_parse_stderr_ok_windows(self):
        msg = """func=xmlSecOpenSSLX509StoreVerify:file=x509vfy.c:line=360:obj=x509-store:subj=X509_verify_cert:error=4:crypto library function failed:subj=/C=US/ST=California/L=Santa Monica/O=OneLogin/CN=app.onelogin.com;err=18;msg=self signed certificate\r
func=xmlSecOpenSSLX509StoreVerify:file=x509vfy.c:line=408:obj=x509-store:subj=unknown:error=71:certificate verification failed:err=18;msg=self signed certificate\r
func=xmlSecOpenSSLEvpSignatureVerify:file=signatures.c:line=346:obj=rsa-sha1:subj=EVP_VerifyFinal:error=18:data do not match:signature do not match\r
OK\r
SignedInfo References (ok/all): 1/1\r
Manifests References (ok/all): 0/0\r
Error: failed to verify file "/tmp/tmpYjEjq5"\r
"""
        fake_proc = fudge.Fake('proc')
        stderr = StringIO(msg)
        fake_proc.has_attr(stderr=stderr)

        res = SignatureVerifier._parse_stderr(fake_proc)

        eq(res, True)
