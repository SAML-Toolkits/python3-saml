# -*- coding: utf-8 -*-

""" OneLogin_Saml2_Utils class

Copyright (c) 2014, OneLogin, Inc.
All rights reserved.

Auxiliary class of OneLogin's Python Toolkit.

"""

import base64
from datetime import datetime
import calendar
from hashlib import sha1
from isodate import parse_duration as duration_parser
from lxml import etree
from defusedxml.lxml import tostring, fromstring
from os.path import basename, dirname, join
import re
from sys import stderr
from tempfile import NamedTemporaryFile
from textwrap import wrap
from urllib import quote_plus
from uuid import uuid4
from xml.dom.minidom import Document, Element
from defusedxml.minidom import parseString

import zlib

import dm.xmlsec.binding as xmlsec
from dm.xmlsec.binding.tmpl import EncData, Signature

from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.errors import OneLogin_Saml2_Error


def print_xmlsec_errors(filename, line, func, error_object, error_subject, reason, msg):
    """
    Auxiliary method. It override the default xmlsec debug message.
    """

    info = []
    if error_object != "unknown":
        info.append("obj=" + error_object)
    if error_subject != "unknown":
        info.append("subject=" + error_subject)
    if msg.strip():
        info.append("msg=" + msg)
    if reason != 1:
        info.append("errno=%d" % reason)
    if info:
        print "%s:%d(%s)" % (filename, line, func), " ".join(info)


class OneLogin_Saml2_Utils(object):
    """

    Auxiliary class that contains several utility methods to parse time,
    urls, add sign, encrypt, decrypt, sign validation, handle xml ...

    """

    @staticmethod
    def decode_base64_and_inflate(value):
        """
        base64 decodes and then inflates according to RFC1951
        :param value: a deflated and encoded string
        :type value: string
        :returns: the string after decoding and inflating
        :rtype: string
        """

        return zlib.decompress(base64.b64decode(value), -15)

    @staticmethod
    def deflate_and_base64_encode(value):
        """
        Deflates and the base64 encodes a string
        :param value: The string to deflate and encode
        :type value: string
        :returns: The deflated and encoded string
        :rtype: string
        """
        return base64.b64encode(zlib.compress(value)[2:-4])

    @staticmethod
    def validate_xml(xml, schema, debug=False):
        """
        Validates a xml against a schema
        :param xml: The xml that will be validated
        :type: string|DomDocument
        :param schema: The schema
        :type: string
        :param debug: If debug is active, the parse-errors will be showed
        :type: bool
        :returns: Error code or the DomDocument of the xml
        :rtype: string
        """
        assert isinstance(xml, basestring) or isinstance(xml, Document) or isinstance(xml, etree._Element)
        assert isinstance(schema, basestring)

        if isinstance(xml, Document):
            xml = xml.toxml()
        elif isinstance(xml, etree._Element):
            xml = tostring(xml)

        # Switch to lxml for schema validation
        try:
            dom = fromstring(str(xml))
        except Exception:
            return 'unloaded_xml'

        schema_file = join(dirname(__file__), 'schemas', schema)
        f_schema = open(schema_file, 'r')
        schema_doc = etree.parse(f_schema)
        f_schema.close()
        xmlschema = etree.XMLSchema(schema_doc)

        if not xmlschema.validate(dom):
            if debug:
                stderr.write('Errors validating the metadata')
                stderr.write(':\n\n')
                for error in xmlschema.error_log:
                    stderr.write('%s\n' % error.message)

            return 'invalid_xml'

        return parseString(etree.tostring(dom))

    @staticmethod
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
                x509_cert = "-----BEGIN CERTIFICATE-----\n" + "\n".join(wrap(x509_cert, 64)) + "\n-----END CERTIFICATE-----\n"

        return x509_cert

    @staticmethod
    def format_private_key(key, heads=True):
        """
        Returns a private key (adding header & footer if required).

        :param key A private key
        :type: string

        :param heads: True if we want to include head and footer
        :type: boolean

        :returns: Formated private key
        :rtype: string
        """
        private_key = key.replace('\x0D', '')
        private_key = private_key.replace('\r', '')
        private_key = private_key.replace('\n', '')
        if len(private_key) > 0:
            if private_key.find('-----BEGIN PRIVATE KEY-----') != -1:
                private_key = private_key.replace('-----BEGIN PRIVATE KEY-----', '')
                private_key = private_key.replace('-----END PRIVATE KEY-----', '')
                private_key = private_key.replace(' ', '')
                if heads:
                    private_key = "-----BEGIN PRIVATE KEY-----\n" + "\n".join(wrap(private_key, 64)) + "\n-----END PRIVATE KEY-----\n"
            else:
                private_key = private_key.replace('-----BEGIN RSA PRIVATE KEY-----', '')
                private_key = private_key.replace('-----END RSA PRIVATE KEY-----', '')
                private_key = private_key.replace(' ', '')
                if heads:
                    private_key = "-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(wrap(private_key, 64)) + "\n-----END RSA PRIVATE KEY-----\n"
        return private_key

    @staticmethod
    def redirect(url, parameters={}, request_data={}):
        """
        Executes a redirection to the provided url (or return the target url).

        :param url: The target url
        :type: string

        :param parameters: Extra parameters to be passed as part of the url
        :type: dict

        :param request_data: The request as a dict
        :type: dict

        :returns: Url
        :rtype: string
        """
        assert isinstance(url, basestring)
        assert isinstance(parameters, dict)

        if url.startswith('/'):
            url = '%s%s' % (OneLogin_Saml2_Utils.get_self_url_host(request_data), url)

        # Verify that the URL is to a http or https site.
        if re.search('^https?://', url) is None:
            raise OneLogin_Saml2_Error(
                'Redirect to invalid URL: ' + url,
                OneLogin_Saml2_Error.REDIRECT_INVALID_URL
            )

        # Add encoded parameters
        if url.find('?') < 0:
            param_prefix = '?'
        else:
            param_prefix = '&'

        for name, value in parameters.items():

            if value is None:
                param = quote_plus(name)
            elif isinstance(value, list):
                param = ''
                for val in value:
                    param += quote_plus(name) + '[]=' + quote_plus(val) + '&'
                if len(param) > 0:
                    param = param[0:-1]
            else:
                param = quote_plus(name) + '=' + quote_plus(value)

            if param:
                url += param_prefix + param
                param_prefix = '&'

        return url

    @staticmethod
    def get_self_url_host(request_data):
        """
        Returns the protocol + the current host + the port (if different than
        common ports).

        :param request_data: The request as a dict
        :type: dict

        :return: Url
        :rtype: string
        """
        current_host = OneLogin_Saml2_Utils.get_self_host(request_data)
        port = ''
        if OneLogin_Saml2_Utils.is_https(request_data):
            protocol = 'https'
        else:
            protocol = 'http'

        if 'server_port' in request_data:
            port_number = str(request_data['server_port'])
            port = ':' + port_number

            if protocol == 'http' and port_number == '80':
                port = ''
            elif protocol == 'https' and port_number == '443':
                port = ''

        return '%s://%s%s' % (protocol, current_host, port)

    @staticmethod
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

    @staticmethod
    def is_https(request_data):
        """
        Checks if https or http.

        :param request_data: The request as a dict
        :type: dict

        :return: False if https is not active
        :rtype: boolean
        """
        is_https = 'https' in request_data and request_data['https'] != 'off'
        is_https = is_https or ('server_port' in request_data and str(request_data['server_port']) == '443')
        return is_https

    @staticmethod
    def get_self_url_no_query(request_data):
        """
        Returns the URL of the current host + current view.

        :param request_data: The request as a dict
        :type: dict

        :return: The url of current host + current view
        :rtype: string
        """
        self_url_host = OneLogin_Saml2_Utils.get_self_url_host(request_data)
        script_name = request_data['script_name']
        if script_name:
            if script_name[0] != '/':
                script_name = '/' + script_name
        else:
            script_name = ''
        self_url_no_query = self_url_host + script_name
        if 'path_info' in request_data:
            self_url_no_query += request_data['path_info']

        return self_url_no_query

    @staticmethod
    def get_self_routed_url_no_query(request_data):
        """
        Returns the routed URL of the current host + current view.

        :param request_data: The request as a dict
        :type: dict

        :return: The url of current host + current view
        :rtype: string
        """
        self_url_host = OneLogin_Saml2_Utils.get_self_url_host(request_data)
        route = ''
        if 'request_uri' in request_data.keys() and request_data['request_uri']:
            route = request_data['request_uri']
            if 'query_string' in request_data.keys() and request_data['query_string']:
                route = route.replace(request_data['query_string'], '')

        return self_url_host + route

    @staticmethod
    def get_self_url(request_data):
        """
        Returns the URL of the current host + current view + query.

        :param request_data: The request as a dict
        :type: dict

        :return: The url of current host + current view + query
        :rtype: string
        """
        self_url_host = OneLogin_Saml2_Utils.get_self_url_host(request_data)

        request_uri = ''
        if 'request_uri' in request_data:
            request_uri = request_data['request_uri']
            if not request_uri.startswith('/'):
                match = re.search('^https?://[^/]*(/.*)', request_uri)
                if match is not None:
                    request_uri = match.groups()[0]

        return self_url_host + request_uri

    @staticmethod
    def generate_unique_id():
        """
        Generates an unique string (used for example as ID for assertions).

        :return: A unique string
        :rtype: string
        """
        return 'ONELOGIN_%s' % sha1(uuid4().hex).hexdigest()

    @staticmethod
    def parse_time_to_SAML(time):
        """
        Converts a UNIX timestamp to SAML2 timestamp on the form
        yyyy-mm-ddThh:mm:ss(\.s+)?Z.

        :param time: The time we should convert (DateTime).
        :type: string

        :return: SAML2 timestamp.
        :rtype: string
        """
        data = datetime.utcfromtimestamp(float(time))
        return data.strftime('%Y-%m-%dT%H:%M:%SZ')

    @staticmethod
    def parse_SAML_to_time(timestr):
        """
        Converts a SAML2 timestamp on the form yyyy-mm-ddThh:mm:ss(\.s+)?Z
        to a UNIX timestamp. The sub-second part is ignored.

        :param time: The time we should convert (SAML Timestamp).
        :type: string

        :return: Converted to a unix timestamp.
        :rtype: int
        """
        try:
            data = datetime.strptime(timestr, '%Y-%m-%dT%H:%M:%SZ')
        except ValueError:
            data = datetime.strptime(timestr, '%Y-%m-%dT%H:%M:%S.%fZ')
        return calendar.timegm(data.utctimetuple())

    @staticmethod
    def now():
        """
        :return: unix timestamp of actual time.
        :rtype: int
        """
        return calendar.timegm(datetime.utcnow().utctimetuple())

    @staticmethod
    def parse_duration(duration, timestamp=None):
        """
        Interprets a ISO8601 duration value relative to a given timestamp.

        :param duration: The duration, as a string.
        :type: string

        :param timestamp: The unix timestamp we should apply the duration to.
                          Optional, default to the current time.
        :type: string

        :return: The new timestamp, after the duration is applied.
        :rtype: int
        """
        assert isinstance(duration, basestring)
        assert timestamp is None or isinstance(timestamp, int)

        timedelta = duration_parser(duration)
        if timestamp is None:
            data = datetime.utcnow() + timedelta
        else:
            data = datetime.utcfromtimestamp(timestamp) + timedelta
        return calendar.timegm(data.utctimetuple())

    @staticmethod
    def get_expire_time(cache_duration=None, valid_until=None):
        """
        Compares 2 dates and returns the earliest.

        :param cache_duration: The duration, as a string.
        :type: string

        :param valid_until: The valid until date, as a string or as a timestamp
        :type: string

        :return: The expiration time.
        :rtype: int
        """
        expire_time = None

        if cache_duration is not None:
            expire_time = OneLogin_Saml2_Utils.parse_duration(cache_duration)

        if valid_until is not None:
            if isinstance(valid_until, int):
                valid_until_time = valid_until
            else:
                valid_until_time = OneLogin_Saml2_Utils.parse_SAML_to_time(valid_until)
            if expire_time is None or expire_time > valid_until_time:
                expire_time = valid_until_time

        if expire_time is not None:
            return '%d' % expire_time
        return None

    @staticmethod
    def query(dom, query, context=None):
        """
        Extracts nodes that match the query from the Element

        :param dom: The root of the lxml objet
        :type: Element

        :param query: Xpath Expresion
        :type: string

        :param context: Context Node
        :type: DOMElement

        :returns: The queried nodes
        :rtype: list
        """
        if context is None:
            return dom.xpath(query, namespaces=OneLogin_Saml2_Constants.NSMAP)
        else:
            return context.xpath(query, namespaces=OneLogin_Saml2_Constants.NSMAP)

    @staticmethod
    def delete_local_session(callback=None):
        """
        Deletes the local session.
        """

        if callback is not None:
            callback()

    @staticmethod
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

    @staticmethod
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

    @staticmethod
    def generate_name_id(value, sp_nq, sp_format, cert=None, debug=False):
        """
        Generates a nameID.

        :param value: fingerprint
        :type: string

        :param sp_nq: SP Name Qualifier
        :type: string

        :param sp_format: SP Format
        :type: string

        :param cert: IdP Public Cert to encrypt the nameID
        :type: string

        :param debug: Activate the xmlsec debug
        :type: bool

        :returns: DOMElement | XMLSec nameID
        :rtype: string
        """
        doc = Document()
        name_id_container = doc.createElementNS(OneLogin_Saml2_Constants.NS_SAML, 'container')
        name_id_container.setAttribute("xmlns:saml", OneLogin_Saml2_Constants.NS_SAML)

        name_id = doc.createElement('saml:NameID')
        name_id.setAttribute('SPNameQualifier', sp_nq)
        name_id.setAttribute('Format', sp_format)
        name_id.appendChild(doc.createTextNode(value))
        name_id_container.appendChild(name_id)

        if cert is not None:
            xml = name_id_container.toxml()
            elem = fromstring(xml)

            xmlsec.initialize()

            if debug:
                xmlsec.set_error_callback(print_xmlsec_errors)

            # Load the public cert
            mngr = xmlsec.KeysMngr()
            file_cert = OneLogin_Saml2_Utils.write_temp_file(cert)
            key_data = xmlsec.Key.load(file_cert.name, xmlsec.KeyDataFormatCertPem, None)
            key_data.name = basename(file_cert.name)
            mngr.addKey(key_data)
            file_cert.close()

            # Prepare for encryption
            enc_data = EncData(xmlsec.TransformAes128Cbc, type=xmlsec.TypeEncElement)
            enc_data.ensureCipherValue()
            key_info = enc_data.ensureKeyInfo()
            # enc_key = key_info.addEncryptedKey(xmlsec.TransformRsaPkcs1)
            enc_key = key_info.addEncryptedKey(xmlsec.TransformRsaOaep)
            enc_key.ensureCipherValue()

            # Encrypt!
            enc_ctx = xmlsec.EncCtx(mngr)
            enc_ctx.encKey = xmlsec.Key.generate(xmlsec.KeyDataAes, 128, xmlsec.KeyDataTypeSession)

            edata = enc_ctx.encryptXml(enc_data, elem[0])

            newdoc = parseString(etree.tostring(edata))

            if newdoc.hasChildNodes():
                child = newdoc.firstChild
                child.removeAttribute('xmlns')
                child.removeAttribute('xmlns:saml')
                child.setAttribute('xmlns:xenc', OneLogin_Saml2_Constants.NS_XENC)
                child.setAttribute('xmlns:dsig', OneLogin_Saml2_Constants.NS_DS)

            nodes = newdoc.getElementsByTagName("*")
            for node in nodes:
                if node.tagName == 'ns0:KeyInfo':
                    node.tagName = 'dsig:KeyInfo'
                    node.removeAttribute('xmlns:ns0')
                    node.setAttribute('xmlns:dsig', OneLogin_Saml2_Constants.NS_DS)
                else:
                    node.tagName = 'xenc:' + node.tagName

            encrypted_id = newdoc.createElement('saml:EncryptedID')
            encrypted_data = newdoc.replaceChild(encrypted_id, newdoc.firstChild)
            encrypted_id.appendChild(encrypted_data)
            return newdoc.saveXML(encrypted_id)
        else:
            return doc.saveXML(name_id)

    @staticmethod
    def get_status(dom):
        """
        Gets Status from a Response.

        :param dom: The Response as XML
        :type: Document

        :returns: The Status, an array with the code and a message.
        :rtype: dict
        """
        status = {}

        status_entry = OneLogin_Saml2_Utils.query(dom, '/samlp:Response/samlp:Status')
        if len(status_entry) == 0:
            raise Exception('Missing Status on response')

        code_entry = OneLogin_Saml2_Utils.query(dom, '/samlp:Response/samlp:Status/samlp:StatusCode', status_entry[0])
        if len(code_entry) == 0:
            raise Exception('Missing Status Code on response')
        code = code_entry[0].values()[0]
        status['code'] = code

        message_entry = OneLogin_Saml2_Utils.query(dom, '/samlp:Response/samlp:Status/samlp:StatusMessage', status_entry[0])
        if len(message_entry) == 0:
            subcode_entry = OneLogin_Saml2_Utils.query(dom, '/samlp:Response/samlp:Status/samlp:StatusCode/samlp:StatusCode', status_entry[0])
            if len(subcode_entry) > 0:
                status['msg'] = subcode_entry[0].values()[0]
            else:
                status['msg'] = ''
        else:
            status['msg'] = message_entry[0].text

        return status

    @staticmethod
    def decrypt_element(encrypted_data, key, debug=False):
        """
        Decrypts an encrypted element.

        :param encrypted_data: The encrypted data.
        :type: lxml.etree.Element | DOMElement | basestring

        :param key: The key.
        :type: string

        :param debug: Activate the xmlsec debug
        :type: bool

        :returns: The decrypted element.
        :rtype: lxml.etree.Element
        """
        if isinstance(encrypted_data, Element):
            encrypted_data = fromstring(str(encrypted_data.toxml()))
        elif isinstance(encrypted_data, basestring):
            encrypted_data = fromstring(str(encrypted_data))

        xmlsec.initialize()

        if debug:
            xmlsec.set_error_callback(print_xmlsec_errors)

        mngr = xmlsec.KeysMngr()

        key = xmlsec.Key.loadMemory(key, xmlsec.KeyDataFormatPem, None)
        mngr.addKey(key)
        enc_ctx = xmlsec.EncCtx(mngr)

        return enc_ctx.decrypt(encrypted_data)

    @staticmethod
    def write_temp_file(content):
        """
        Writes some content into a temporary file and returns it.

        :param content: The file content
        :type: string

        :returns: The temporary file
        :rtype: file-like object
        """
        f_temp = NamedTemporaryFile(delete=True)
        f_temp.file.write(content)
        f_temp.file.flush()
        return f_temp

    @staticmethod
    def add_sign(xml, key, cert, debug=False):
        """
        Adds signature key and senders certificate to an element (Message or
        Assertion).

        :param xml: The element we should sign
        :type: string | Document

        :param key: The private key
        :type: string

        :param debug: Activate the xmlsec debug
        :type: bool

        :param cert: The public
        :type: string
        """
        if xml is None or xml == '':
            raise Exception('Empty string supplied as input')
        elif isinstance(xml, etree._Element):
            elem = xml
        elif isinstance(xml, Document):
            xml = xml.toxml()
            elem = fromstring(str(xml))
        elif isinstance(xml, Element):
            xml.setAttributeNS(
                unicode(OneLogin_Saml2_Constants.NS_SAMLP),
                'xmlns:samlp',
                unicode(OneLogin_Saml2_Constants.NS_SAMLP)
            )
            xml.setAttributeNS(
                unicode(OneLogin_Saml2_Constants.NS_SAML),
                'xmlns:saml',
                unicode(OneLogin_Saml2_Constants.NS_SAML)
            )
            xml = xml.toxml()
            elem = fromstring(str(xml))
        elif isinstance(xml, basestring):
            elem = fromstring(str(xml))
        else:
            raise Exception('Error parsing xml string')

        xmlsec.initialize()

        if debug:
            xmlsec.set_error_callback(print_xmlsec_errors)

        # Sign the metadacta with our private key.
        signature = Signature(xmlsec.TransformExclC14N, xmlsec.TransformRsaSha1)

        issuer = OneLogin_Saml2_Utils.query(elem, '//saml:Issuer')
        if len(issuer) > 0:
            issuer = issuer[0]
            issuer.addnext(signature)
        else:
            elem[0].insert(0, signature)

        ref = signature.addReference(xmlsec.TransformSha1)
        ref.addTransform(xmlsec.TransformEnveloped)
        ref.addTransform(xmlsec.TransformExclC14N)

        key_info = signature.ensureKeyInfo()
        key_info.addX509Data()

        dsig_ctx = xmlsec.DSigCtx()
        sign_key = xmlsec.Key.loadMemory(key, xmlsec.KeyDataFormatPem, None)

        file_cert = OneLogin_Saml2_Utils.write_temp_file(cert)
        sign_key.loadCert(file_cert.name, xmlsec.KeyDataFormatCertPem)
        file_cert.close()

        dsig_ctx.signKey = sign_key
        dsig_ctx.sign(signature)

        newdoc = parseString(etree.tostring(elem))

        signature_nodes = newdoc.getElementsByTagName("Signature")

        for signature in signature_nodes:
            signature.removeAttribute('xmlns')
            signature.setAttribute('xmlns:ds', OneLogin_Saml2_Constants.NS_DS)
            if not signature.tagName.startswith('ds:'):
                signature.tagName = 'ds:' + signature.tagName
            nodes = signature.getElementsByTagName("*")
            for node in nodes:
                if not node.tagName.startswith('ds:'):
                    node.tagName = 'ds:' + node.tagName

        return newdoc.saveXML(newdoc.firstChild)

    @staticmethod
    def validate_sign(xml, cert=None, fingerprint=None, validatecert=False, debug=False):
        """
        Validates a signature (Message or Assertion).

        :param xml: The element we should validate
        :type: string | Document

        :param cert: The pubic cert
        :type: string

        :param fingerprint: The fingerprint of the public cert
        :type: string

        :param validatecert: If true, will verify the signature and if the cert is valid.
        :type: bool

        :param debug: Activate the xmlsec debug
        :type: bool
        """
        try:
            if xml is None or xml == '':
                raise Exception('Empty string supplied as input')
            elif isinstance(xml, etree._Element):
                elem = xml
            elif isinstance(xml, Document):
                xml = xml.toxml()
                elem = fromstring(str(xml))
            elif isinstance(xml, Element):
                xml.setAttributeNS(
                    unicode(OneLogin_Saml2_Constants.NS_SAMLP),
                    'xmlns:samlp',
                    unicode(OneLogin_Saml2_Constants.NS_SAMLP)
                )
                xml.setAttributeNS(
                    unicode(OneLogin_Saml2_Constants.NS_SAML),
                    'xmlns:saml',
                    unicode(OneLogin_Saml2_Constants.NS_SAML)
                )
                xml = xml.toxml()
                elem = fromstring(str(xml))
            elif isinstance(xml, basestring):
                elem = fromstring(str(xml))
            else:
                raise Exception('Error parsing xml string')

            xmlsec.initialize()

            if debug:
                xmlsec.set_error_callback(print_xmlsec_errors)

            xmlsec.addIDs(elem, ["ID"])

            signature_nodes = OneLogin_Saml2_Utils.query(elem, '//ds:Signature')

            if len(signature_nodes) > 0:
                signature_node = signature_nodes[0]

                if (cert is None or cert == '') and fingerprint:
                    x509_certificate_nodes = OneLogin_Saml2_Utils.query(signature_node, '//ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate')
                    if len(x509_certificate_nodes) > 0:
                        x509_certificate_node = x509_certificate_nodes[0]
                        x509_cert_value = x509_certificate_node.text
                        x509_fingerprint_value = OneLogin_Saml2_Utils.calculate_x509_fingerprint(x509_cert_value)
                        if fingerprint == x509_fingerprint_value:
                            cert = OneLogin_Saml2_Utils.format_cert(x509_cert_value)

                if cert is None or cert == '':
                    return False

                dsig_ctx = xmlsec.DSigCtx()

                file_cert = OneLogin_Saml2_Utils.write_temp_file(cert)

                if validatecert:
                    mngr = xmlsec.KeysMngr()
                    mngr.loadCert(file_cert.name, xmlsec.KeyDataFormatCertPem, xmlsec.KeyDataTypeTrusted)
                    dsig_ctx = xmlsec.DSigCtx(mngr)
                else:
                    dsig_ctx = xmlsec.DSigCtx()
                    dsig_ctx.signKey = xmlsec.Key.load(file_cert.name, xmlsec.KeyDataFormatCertPem, None)

                file_cert.close()

                dsig_ctx.setEnabledKeyData([xmlsec.KeyDataX509])
                dsig_ctx.verify(signature_node)
                return True
            else:
                return False
        except Exception:
            return False

    @staticmethod
    def validate_binary_sign(signed_query, signature, cert=None, algorithm=xmlsec.TransformRsaSha1, debug=False):
        """
        Validates signed bynary data (Used to validate GET Signature).

        :param signed_query: The element we should validate
        :type: string


        :param signature: The signature that will be validate
        :type: string

        :param cert: The pubic cert
        :type: string

        :param algorithm: Signature algorithm
        :type: string

        :param debug: Activate the xmlsec debug
        :type: bool
        """
        try:
            xmlsec.initialize()

            if debug:
                xmlsec.set_error_callback(print_xmlsec_errors)

            dsig_ctx = xmlsec.DSigCtx()

            file_cert = OneLogin_Saml2_Utils.write_temp_file(cert)
            dsig_ctx.signKey = xmlsec.Key.load(file_cert.name, xmlsec.KeyDataFormatCertPem, None)
            file_cert.close()

            dsig_ctx.verifyBinary(signed_query, algorithm, signature)
            return True
        except Exception:
            return False
