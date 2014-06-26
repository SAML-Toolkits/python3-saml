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


def get_self_url_no_query(request_data):
    """
    Returns the URL of the current host + current view.

    :param request_data: The request as a dict
    :type: dict

    :return: The url of current host + current view
    :rtype: string
    """
    self_url_host = get_self_url_host(request_data)
    script_name = request_data['script_name']
    if script_name and script_name[0] != '/':
        script_name = '/' + script_name
    self_url_host += script_name
    if 'path_info' in request_data:
        self_url_host += request_data['path_info']

    return self_url_host


def get_self_url_host(request_data):
    """
    Returns the protocol + the current host + the port (if different than
    common ports).

    :param request_data: The request as a dict
    :type: dict

    :return: Url
    :rtype: string
    """
    current_host = get_self_host(request_data)
    port = ''
    if is_https(request_data):
        protocol = 'https'
    else:
        protocol = 'http'

    if 'server_port' in request_data:
        port_number = request_data['server_port']
        port = ':' + port_number

        if protocol == 'http' and port_number == '80':
            port = ''
        elif protocol == 'https' and port_number == '443':
            port = ''

    return '%s://%s%s' % (protocol, current_host, port)


def get_self_host(request_data):
    """
    Returns the current host.

    :param request_data: The request as a dict
    :type: dict

    :return: The current host
    :rtype: string
    """
    if 'http_host' in request_data:
        current_host = request_data['http_host']
    elif 'server_name' in request_data:
        current_host = request_data['server_name']
    else:
        raise Exception('No hostname defined')

    if ':' in current_host:
        current_host_data = current_host.split(':')
        possible_port = current_host_data[-1]
        try:
            possible_port = float(possible_port)
            current_host = current_host_data[0]
        except ValueError:
            current_host = ':'.join(current_host_data)

    return current_host


def is_https(request_data):
    """
    Checks if https or http.

    :param request_data: The request as a dict
    :type: dict

    :return: False if https is not active
    :rtype: boolean
    """
    is_https = 'https' in request_data and request_data['https'] != 'off'
    is_https = is_https or ('server_port' in request_data and request_data['server_port'] == '443')
    return is_https
