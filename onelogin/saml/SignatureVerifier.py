import os
import subprocess
import platform
import tempfile
import logging

from lxml import etree

log = logging.getLogger(__name__)

class SignatureVerifierError(Exception):
    """There was a problem validating the response"""
    def __init__(self, msg):
        self._msg = msg

    def __str__(self):
        return '%s: %s' % (self.__doc__, self._msg)

def _parse_stderr(proc):
    output = proc.stderr.read()
    for line in output.split('\n'):
        line = line.strip()
        if line == 'OK':
            return True
        elif line == 'FAIL':
            [log.info('XMLSec: %s' % line)
             for line in output.split('\n')
             if line
             ]
            return False

    # If neither success nor failure
    if proc.returncode is not 0:
        msg = ('XMLSec returned error code %s. Please check your '
               + 'certficate.'
               )
        raise SignatureVerifierError(msg % proc.returncode)

    # Should not happen
    raise SignatureVerifierError(
        ('XMLSec exited with code 0 but did not return OK when verifying the '
         + ' SAML response.'
         )
        )

def _get_xmlsec_bin(_platform=None):
    if _platform is None:
        _platform = platform

    xmlsec_bin = 'xmlsec1'
    if _platform.system() == 'Windows':
        xmlsec_bin = 'xmlsec.exe'

    return xmlsec_bin

def verify(
    document,
    signature,
    _etree=None,
    _tempfile=None,
    _subprocess=None,
    _os=None,
    ):
    """
    Verify that signature contained in the samlp:Response is valid when checked against the provided signature.
    Return True if valid, otherwise False
    Arguments:
    document -- lxml.etree.XML object containing the samlp:Response
    signature -- The fingerprint to check the samlp:Response against
    """
    if _etree is None:
        _etree = etree
    if _tempfile is None:
        _tempfile = tempfile
    if _subprocess is None:
        _subprocess = subprocess
    if _os is None:
        _os = os

    xmlsec_bin = _get_xmlsec_bin()

    verified = False
    cert_filename = None
    xml_filename = None
    # Windows hack: Without the delete=False parameter in NamedTemporaryFile
    # xmlsec.exe will get an IO Permission Denied error.
    try:
        with _tempfile.NamedTemporaryFile(delete=False) as xml_fp:
            doc_str = _etree.tostring(document)
            xml_fp.write(doc_str)
            xml_fp.seek(0)
            with _tempfile.NamedTemporaryFile(delete=False) as cert_fp:
                if signature.startswith(
                    '-----BEGIN CERTIFICATE-----'
                    ):
                    # If there's no matching 'END CERTIFICATE'
                    # cryptpAppKeyLoad will fail
                    cert_fp.write(signature)
                else:
                    cert_fp.write(
                        '{begin}\n{signature}\n{end}'.format(
                            begin='-----BEGIN CERTIFICATE-----',
                            signature=signature,
                            end='-----END CERTIFICATE-----',
                            )
                        )
                cert_fp.seek(0)

                cert_filename = cert_fp.name
                xml_filename = xml_fp.name

                # We cannot use xmlsec python bindings to verify here because
                # that would require a call to libxml2.xmlAddID. The libxml2 python
                # bindings do not yet provide this function.
                # http://www.aleksey.com/xmlsec/faq.html Section 3.2
                cmds = [
                    xmlsec_bin,
                    '--verify',
                    '--pubkey-cert-pem',
                    cert_filename,
                    '--id-attr:ID',
                    'urn:oasis:names:tc:SAML:2.0:assertion:Assertion',
                    xml_filename,
                    ]

                proc = _subprocess.Popen(
                    cmds,
                    stderr=_subprocess.PIPE,
                    stdout=_subprocess.PIPE,
                    )
                proc.wait()
                verified = _parse_stderr(proc)
    finally:
        if cert_filename is not None:
            _os.remove(cert_filename)
        if xml_filename is not None:
            _os.remove(xml_filename)

    return verified
