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
    def test_verify_simple(self):
        document = etree.XML('<Response>foo doc</Response>')

        fake_etree = fudge.Fake('etree')
        fake_etree.remember_order()
        to_string = fake_etree.expects('tostring')
        to_string.with_args(document)
        to_string.returns('<Response>foo doc</Response>')

        fake_tempfile = fudge.Fake('tempfile')
        fake_tempfile.remember_order()
        named_xmlfile = fake_tempfile.expects(
            'NamedTemporaryFile'
            )
        named_xmlfile.with_args(delete=False)
        xmlfile = named_xmlfile.returns_fake()
        xmlfile.remember_order()

        enter = xmlfile.expects('__enter__')
        enter.with_arg_count(0)
        enter.returns(xmlfile)

        write = xmlfile.expects('write')
        write.with_args('<Response>foo doc</Response>')
        seek = xmlfile.expects('seek')
        seek.with_args(0)

        exit = xmlfile.expects('__exit__')
        exit.with_args(None, None,None)

        xmlfile.has_attr(name='xmlfile')

        named_certfile = fake_tempfile.next_call(
            'NamedTemporaryFile'
            )
        named_certfile.with_args(delete=False)
        certfile = named_certfile.returns_fake()
        certfile.remember_order()

        enter = certfile.expects('__enter__')
        enter.with_arg_count(0)
        enter.returns(certfile)

        write = certfile.expects('write')
        write.with_args(
            ('-----BEGIN CERTIFICATE-----\nfoo signature\n'
             + '-----END CERTIFICATE-----'
             )
            )
        seek = certfile.expects('seek')
        seek.with_args(0)

        exit = certfile.expects('__exit__')
        exit.with_args(None, None,None)

        certfile.has_attr(name='certfile')


        fake_subprocess = fudge.Fake('subprocess')
        fake_subprocess.remember_order()
        popen = fake_subprocess.expects('Popen')
        fake_subprocess.has_attr(PIPE=1)
        popen.with_args(
            [
                'xmlsec1',
                '--verify',
                '--pubkey-cert-pem',
                'certfile',
                '--id-attr:ID',
                'urn:oasis:names:tc:SAML:2.0:assertion:Assertion',
                'xmlfile',
                ],
            stderr=1,
            stdout=1,
            )
        proc = popen.returns_fake()
        proc.remember_order()
        wait = proc.expects('wait')
        wait.with_arg_count(0)
        stderr = StringIO('OK')
        proc.has_attr(stderr=stderr)

        fake_os = fudge.Fake('os')
        fake_os.remember_order()
        remove = fake_os.expects('remove')
        remove.with_args('certfile')
        remove = fake_os.next_call('remove')
        remove.with_args('xmlfile')

        SignatureVerifier.verify(
            document,
            'foo signature',
            _etree=fake_etree,
            _tempfile=fake_tempfile,
            _subprocess=fake_subprocess,
            _os=fake_os,
            )

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

        eq(str(msg),
           ('There was a problem validating the response: XMLSec returned error '
            + 'code 1. Please check your certficate.'
            ),
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

        eq(str(msg),
           ('There was a problem validating the response: XMLSec exited with '
            + 'code 0 but did not return OK when verifying the  SAML response.'
            )
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
