import base64
from hashlib import sha1
from textwrap import wrap


def format_finger_print(fingerprint):
    """
    Formates a fingerprint.

    :param fingerprint: fingerprint
    :type: string

    :returns: Formated fingerprint
    :rtype: string
    """
    formated_fingerprint = fingerprint.replace(':', '')
    return formated_fingerprint.lower()


def calculate_x509_fingerprint(x509_cert):
        """
        Calculates the fingerprint of a x509cert.

        :param x509_cert: x509 cert
        :type: string

        :returns: Formated fingerprint
        :rtype: string
        """
        assert isinstance(x509_cert, basestring)

        lines = x509_cert.split('\n')
        data = ''

        for line in lines:
            # Remove '\r' from end of line if present.
            line = line.rstrip()
            if line == '-----BEGIN CERTIFICATE-----':
                # Delete junk from before the certificate.
                data = ''
            elif line == '-----END CERTIFICATE-----':
                # Ignore data after the certificate.
                break
            elif line == '-----BEGIN PUBLIC KEY-----' or line == '-----BEGIN RSA PRIVATE KEY-----':
                # This isn't an X509 certificate.
                return None
            else:
                # Append the current line to the certificate data.
                data += line
        # "data" now contains the certificate as a base64-encoded string. The
        # fingerprint of the certificate is the sha1-hash of the certificate.
        return sha1(base64.b64decode(data)).hexdigest().lower()


def format_cert(cert, heads=True):
    """
    Returns a x509 cert (adding header & footer if required).

    :param cert: A x509 unformated cert
    :type: string

    :param heads: True if we want to include head and footer
    :type: boolean

    :returns: Formated cert
    :rtype: string
    """
    x509_cert = cert.replace('\x0D', '')
    x509_cert = x509_cert.replace('\r', '')
    x509_cert = x509_cert.replace('\n', '')
    if len(x509_cert) > 0:
        x509_cert = x509_cert.replace('-----BEGIN CERTIFICATE-----', '')
        x509_cert = x509_cert.replace('-----END CERTIFICATE-----', '')
        x509_cert = x509_cert.replace(' ', '')

        if heads:
            x509_cert = '-----BEGIN CERTIFICATE-----\n' + '\n'.join(wrap(x509_cert, 64)) + '\n-----END CERTIFICATE-----\n'

    return x509_cert
