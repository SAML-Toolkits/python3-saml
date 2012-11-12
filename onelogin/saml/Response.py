import base64

from lxml import etree
from datetime import datetime, timedelta

from onelogin.saml import SignatureVerifier

namespaces=dict(
    samlp='urn:oasis:names:tc:SAML:2.0:protocol',
    saml='urn:oasis:names:tc:SAML:2.0:assertion',
    )

class ResponseValidationError(Exception):
    """There was a problem validating the response"""
    def __init__(self, msg):
        self._msg = msg

    def __str__(self):
        return '%s: %s' % (self.__doc__, self._msg)

class ResponseNameIDError(Exception):
    """There was a problem getting the name ID"""
    def __init__(self, msg):
        self._msg = msg

    def __str__(self):
        return '%s: %s' % (self.__doc__, self._msg)

class ResponseConditionError(Exception):
    """There was a problem validating a condition"""
    def __init__(self, msg):
        self._msg = msg

    def __str__(self):
        return '%s: %s' % (self.__doc__, self._msg)

class Response(object):
    def __init__(
        self,
        response,
        signature,
        _base64=None,
        _etree=None,
        ):
        """
        Extract information from an samlp:Response
        Arguments:
        response -- The base64 encoded, XML string containing the samlp:Response
        signature -- The fingerprint to check the samlp:Response against
        """
        if _base64 is None:
            _base64 = base64
        if _etree is None:
            _etree = etree

        decoded_response = _base64.b64decode(response)
        self._document = _etree.fromstring(decoded_response)
        self._signature = signature

    def _parse_datetime(self, dt):
        return datetime.strptime(dt, '%Y-%m-%dT%H:%M:%SZ')

    def _get_name_id(self):
        result = self._document.xpath(
            '/samlp:Response/saml:Assertion/saml:Subject/saml:NameID',
            namespaces=namespaces,
            )
        length = len(result)
        if length > 1:
            raise ResponseNameIDError(
                'Found more than one name ID'
                )
        if length == 0:
            raise ResponseNameIDError(
                'Did not find a name ID'
                )

        node = result.pop()

        return node.text.strip()

    name_id = property(
        fget=_get_name_id,
        doc="The value requested in the name_identifier_format, e.g., the user's email address",
        )

    def get_assertion_attribute_value(self,attribute_name):
        """
        Get the value of an AssertionAttribute, located in an Assertion/AttributeStatement/Attribute[@Name=attribute_name/AttributeValue tag
        """
        result = self._document.xpath('/samlp:Response/saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name="%s"]/saml:AttributeValue'%attribute_name,namespaces=namespaces)
        return [n.text.strip() for n in result]

    def is_valid(
        self,
        _clock=None,
        _verifier=None,
        ):
        """
        Verify that the samlp:Response is valid.
        Return True if valid, otherwise False.
        """
        if _clock is None:
            _clock = datetime.utcnow
        if _verifier is None:
            _verifier = SignatureVerifier.verify

        conditions = self._document.xpath(
            '/samlp:Response/saml:Assertion/saml:Conditions',
            namespaces=namespaces,
            )

        now = _clock()

        not_before = None
        not_on_or_after = None
        for condition in conditions:
            not_on_or_after = condition.attrib.get('NotOnOrAfter', None)
            not_before = condition.attrib.get('NotBefore', None)

        if not_before is None:
            #notbefore condition is not mandatory. If it is not specified, use yesterday as not_before condition
            not_before = (now-timedelta(1,0,0)).strftime('%Y-%m-%dT%H:%M:%SZ')
        if not_on_or_after is None:
            raise ResponseConditionError('Did not find NotOnOrAfter condition')

        not_before = self._parse_datetime(not_before)
        not_on_or_after = self._parse_datetime(not_on_or_after)

        if now < not_before:
            raise ResponseValidationError(
                'Current time is earlier than NotBefore condition'
                )
        if now >= not_on_or_after:
            raise ResponseValidationError(
                'Current time is on or after NotOnOrAfter condition'
                )

        return _verifier(
            self._document,
            self._signature,
            )
