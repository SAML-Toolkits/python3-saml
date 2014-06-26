import base64

from lxml import etree
from datetime import datetime, timedelta

from onelogin.saml import SignatureVerifier
from onelogin.saml.Utils import get_self_url_no_query


namespaces = dict(
    samlp='urn:oasis:names:tc:SAML:2.0:protocol',
    saml='urn:oasis:names:tc:SAML:2.0:assertion',
    ds='http://www.w3.org/2000/09/xmldsig#',
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


class ResponseFormatError(Exception):
    """There was a problem validating the format"""
    def __init__(self, msg):
        self._msg = msg

    def __str__(self):
        return '%s: %s' % (self.__doc__, self._msg)


class ResponseDestinationError(Exception):
    """There was a problem validating a destination"""
    def __init__(self, msg):
        self._msg = msg

    def __str__(self):
        return '%s: %s' % (self.__doc__, self._msg)


class ResponseSubjectConfirmationError(Exception):
    """There was a problem validating the response, no valid SubjectConfirmation found"""
    def __init__(self, msg):
        self._msg = msg

    def __str__(self):
        return '%s: %s' % (self.__doc__, self._msg)


class Response(object):
    def __init__(self, request_data, response, signature, _base64=None, _etree=None, issuer=None):
        """
        Extract information from an samlp:Response
        Arguments:
        response -- The base64 encoded, XML string containing a samlp:Response
        signature -- The fingerprint to check the samlp:Response against
        """
        if _base64 is None:
            _base64 = base64
        if _etree is None:
            _etree = etree

        self._request_data = request_data
        decoded_response = _base64.b64decode(response)
        self._document = _etree.fromstring(decoded_response, parser=_etree.XMLParser())
        self._signature = signature
        self._issuer = issuer

    def _parse_datetime(self, dt):
        try:
            return datetime.strptime(dt, '%Y-%m-%dT%H:%M:%SZ')
        except ValueError:
            return datetime.strptime(dt, '%Y-%m-%dT%H:%M:%S.%fZ')

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

    def get_assertion_attribute_value(self, attribute_name):
        """
        Get the value of an AssertionAttribute, located in an Assertion/AttributeStatement/Attribute[@Name=attribute_name/AttributeValue tag
        """
        result = self._document.xpath('/samlp:Response/saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name="%s"]/saml:AttributeValue' % attribute_name, namespaces=namespaces)
        return [n.text.strip() for n in result]

    def get_audiences(self):
        """
        Gets the audiences

        :returns: The valid audiences for the SAML Response
        :rtype: list
        """
        audiences = []

        audience_nodes = self._document.xpath(
            '/samlp:Response/saml:Assertion/saml:Conditions/saml:AudienceRestriction/saml:Audience',
            namespaces=namespaces,
        )
        for audience_node in audience_nodes:
            audiences.append(audience_node.text)
        return audiences

    def validate_num_assertions(self):
        """
        Verifies that the document only contains a single Assertion (encrypted or not)

        :returns: True if only 1 assertion encrypted or not
        :rtype: bool
        """
        #Not encrypted assertion supported yet
        #encrypted_assertion_nodes = self._document.xpath('//saml:EncryptedAssertion')
        assertion_nodes = self._document.xpath(
            '//saml:Assertion',
            namespaces=namespaces,
        )
        return len(assertion_nodes) == 1

    def is_valid(self, _clock=None, _verifier=None):
        """
        Verify that the samlp:Response is valid.
        Return True if valid, otherwise False.
        """

        # Checks SAML version
        if self._document.get('Version', None) != '2.0':
            raise ResponseFormatError('Unsupported SAML version')

        # Checks that ID exists
        if self._document.get('ID', None) is None:
            raise ResponseFormatError('Missing ID attribute on SAML Response')

        # Checks that the response only has one assertion
        if not self.validate_num_assertions():
            raise ResponseFormatError('Only 1 Assertion in the SAMLResponse is supported')



        if _clock is None:
            _clock = datetime.utcnow
        if _verifier is None:
            _verifier = SignatureVerifier.verify

        conditions = self._document.xpath(
            '/samlp:Response/saml:Assertion/saml:Conditions',
            namespaces=namespaces,
        )

        now = _clock()

        for condition in conditions:
            
            not_before = condition.attrib.get('NotBefore', None)
            not_on_or_after = condition.attrib.get('NotOnOrAfter', None)
            
            if not_before is None:
                not_before = (now - timedelta(0, 5, 0)).strftime('%Y-%m-%dT%H:%M:%SZ')
            if not_on_or_after is None:
                not_on_or_after = (now + timedelta(0, 5, 0)).strftime('%Y-%m-%dT%H:%M:%SZ')

            not_before = self._parse_datetime(not_before)
            not_on_or_after = self._parse_datetime(not_on_or_after)

            if now < not_before:
                raise ResponseConditionError('Timmig issue')
            if now >= not_on_or_after:
                raise ResponseConditionError('Timmig issue')

        current_url = get_self_url_no_query(self._request_data)

        # Checks destination
        destination = self._document.get('Destination', None)
        if destination and destination not in current_url:
            raise ResponseDestinationError('The response was received at %s instead of %s' % (current_url, destination))

        # Checks audience
        valid_audiences = self.get_audiences()
        if valid_audiences and self._issuer not in valid_audiences:
            raise ResponseConditionError('%s is not a valid audience for this Response' % self._issuer)

        # Checks the SubjectConfirmation, at least one SubjectConfirmation must be valid
        any_subject_confirmation = False
        subject_confirmation_nodes = self._document.xpath(
            '//saml:Subject/saml:SubjectConfirmation',
            namespaces=namespaces
        )

        in_response_to = self._document.get('InResponseTo', None)
        for scn in subject_confirmation_nodes:
            method = scn.get('Method', None)
            if method and method != 'urn:oasis:names:tc:SAML:2.0:cm:bearer':
                continue
            scData = scn.find('saml:SubjectConfirmationData', namespaces=namespaces)
            if scData is None:
                continue
            else:
                irt = scData.get('InResponseTo', None)
                if irt != in_response_to:
                    continue
                recipient = scData.get('Recipient', None)
                if recipient not in current_url:
                    continue
                nooa = scData.get('NotOnOrAfter', None)
                if nooa:
                    parsed_nooa = self._parse_datetime(nooa)
                    if parsed_nooa <= now:
                        continue
                nb = scData.get('NotBefore', None)
                if nb:
                    parsed_nb = self._parse_datetime(nb)
                    if parsed_nb > now:
                        continue
                any_subject_confirmation = True
                break

        if not any_subject_confirmation:
            raise ResponseSubjectConfirmationError('A valid SubjectConfirmation was not found on this Response')


        return _verifier(
            self._document,
            self._signature,
        )
