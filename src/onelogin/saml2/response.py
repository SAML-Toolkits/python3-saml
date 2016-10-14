# -*- coding: utf-8 -*-

""" OneLogin_Saml2_Response class

Copyright (c) 2014, OneLogin, Inc.
All rights reserved.

SAML Response class of OneLogin's Python Toolkit.

"""

from copy import deepcopy
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from onelogin.saml2.xml_utils import OneLogin_Saml2_XML


class OneLogin_Saml2_Response(object):
    """

    This class handles a SAML Response. It parses or validates
    a Logout Response object.

    """

    def __init__(self, settings, response):
        """
        Constructs the response object.

        :param settings: The setting info
        :type settings: OneLogin_Saml2_Setting object

        :param response: The base64 encoded, XML string containing the samlp:Response
        :type response: string
        """
        self.__settings = settings
        self.__error = None
        self.response = OneLogin_Saml2_Utils.b64decode(response)
        self.document = OneLogin_Saml2_XML.to_etree(self.response)
        self.decrypted_document = None
        self.encrypted = None

        # Quick check for the presence of EncryptedAssertion
        encrypted_assertion_nodes = self.__query('/samlp:Response/saml:EncryptedAssertion')
        if encrypted_assertion_nodes:
            decrypted_document = deepcopy(self.document)
            self.encrypted = True
            self.decrypted_document = self.__decrypt_assertion(decrypted_document)

    def is_valid(self, request_data, request_id=None):
        """
        Validates the response object.

        :param request_data: Request Data
        :type request_data: dict

        :param request_id: Optional argument. The ID of the AuthNRequest sent by this SP to the IdP
        :type request_id: string

        :returns: True if the SAML Response is valid, False if not
        :rtype: bool
        """
        self.__error = None
        try:
            # Checks SAML version
            if self.document.get('Version', None) != '2.0':
                raise Exception('Unsupported SAML version')

            # Checks that ID exists
            if self.document.get('ID', None) is None:
                raise Exception('Missing ID attribute on SAML Response')

            # Checks that the response only has one assertion
            if not self.validate_num_assertions():
                raise Exception('SAML Response must contain 1 assertion')

            # Checks that the response has the SUCCESS status
            self.check_status()

            idp_data = self.__settings.get_idp_data()
            idp_entity_id = idp_data['entityId']
            sp_data = self.__settings.get_sp_data()
            sp_entity_id = sp_data['entityId']

            signed_elements = self.process_signed_elements()

            has_signed_response = '{%s}Response' % OneLogin_Saml2_Constants.NS_SAMLP in signed_elements
            has_signed_assertion = '{%s}Assertion' % OneLogin_Saml2_Constants.NS_SAML in signed_elements

            if self.__settings.is_strict():
                no_valid_xml_msg = 'Invalid SAML Response. Not match the saml-schema-protocol-2.0.xsd'
                res = OneLogin_Saml2_XML.validate_xml(self.document, 'saml-schema-protocol-2.0.xsd', self.__settings.is_debug_active())
                if isinstance(res, str):
                    raise Exception(no_valid_xml_msg)

                # If encrypted, check also the decrypted document
                if self.encrypted:
                    res = OneLogin_Saml2_XML.validate_xml(self.decrypted_document, 'saml-schema-protocol-2.0.xsd', self.__settings.is_debug_active())
                    if isinstance(res, str):
                        raise Exception(no_valid_xml_msg)

                security = self.__settings.get_security_data()
                current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)

                # Check if the InResponseTo of the Response matchs the ID of the AuthNRequest (requestId) if provided
                in_response_to = self.document.get('InResponseTo', None)
                if in_response_to and request_id:
                    if in_response_to != request_id:
                        raise Exception('The InResponseTo of the Response: %s, does not match the ID of the AuthNRequest sent by the SP: %s' % (in_response_to, request_id))

                if not self.encrypted and security['wantAssertionsEncrypted']:
                    raise Exception('The assertion of the Response is not encrypted and the SP require it')

                if security['wantNameIdEncrypted']:
                    encrypted_nameid_nodes = self.__query_assertion('/saml:Subject/saml:EncryptedID/xenc:EncryptedData')
                    if len(encrypted_nameid_nodes) != 1:
                        raise Exception('The NameID of the Response is not encrypted and the SP require it')

                # Checks that a Conditions element exists
                if not self.check_one_condition():
                    raise Exception('The Assertion must include a Conditions element')

                # Validates Assertion timestamps
                if not self.validate_timestamps():
                    raise Exception('Timing issues (please check your clock settings)')

                # Checks that an AuthnStatement element exists and is unique
                if not self.check_one_authnstatement():
                    raise Exception('The Assertion must include an AuthnStatement element')

                # Checks that there is at least one AttributeStatement if required
                attribute_statement_nodes = self.__query_assertion('/saml:AttributeStatement')
                if security.get('wantAttributeStatement', True) and not attribute_statement_nodes:
                    raise Exception('There is no AttributeStatement on the Response')

                encrypted_attributes_nodes = self.__query_assertion('/saml:AttributeStatement/saml:EncryptedAttribute')
                if encrypted_attributes_nodes:
                    raise Exception('There is an EncryptedAttribute in the Response and this SP not support them')

                # Checks destination
                destination = self.document.get('Destination', None)
                if destination:
                    if not destination.startswith(current_url):
                        # TODO: Review if following lines are required, since we can control the
                        # request_data
                        #  current_url_routed = OneLogin_Saml2_Utils.get_self_routed_url_no_query(request_data)
                        #  if not destination.startswith(current_url_routed):
                        raise Exception('The response was received at %s instead of %s' % (current_url, destination))
                elif destination == '':
                    raise Exception('The response has an empty Destination value')

                # Checks audience
                valid_audiences = self.get_audiences()
                if valid_audiences and sp_entity_id not in valid_audiences:
                    raise Exception('%s is not a valid audience for this Response' % sp_entity_id)

                # Checks the issuers
                issuers = self.get_issuers()
                for issuer in issuers:
                    if issuer is None or issuer != idp_entity_id:
                        raise Exception('Invalid issuer in the Assertion/Response')

                # Checks the session Expiration
                session_expiration = self.get_session_not_on_or_after()
                if session_expiration and session_expiration <= OneLogin_Saml2_Utils.now():
                    raise Exception('The attributes have expired, based on the SessionNotOnOrAfter of the AttributeStatement of this Response')

                # Checks the SubjectConfirmation, at least one SubjectConfirmation must be valid
                any_subject_confirmation = False
                subject_confirmation_nodes = self.__query_assertion('/saml:Subject/saml:SubjectConfirmation')

                for scn in subject_confirmation_nodes:
                    method = scn.get('Method', None)
                    if method and method != OneLogin_Saml2_Constants.CM_BEARER:
                        continue
                    sc_data = scn.find('saml:SubjectConfirmationData', namespaces=OneLogin_Saml2_Constants.NSMAP)
                    if sc_data is None:
                        continue
                    else:
                        irt = sc_data.get('InResponseTo', None)
                        if in_response_to and irt and irt != in_response_to:
                            continue
                        recipient = sc_data.get('Recipient', None)
                        if recipient and current_url not in recipient:
                            continue
                        nooa = sc_data.get('NotOnOrAfter', None)
                        if nooa:
                            parsed_nooa = OneLogin_Saml2_Utils.parse_SAML_to_time(nooa)
                            if parsed_nooa <= OneLogin_Saml2_Utils.now():
                                continue
                        nb = sc_data.get('NotBefore', None)
                        if nb:
                            parsed_nb = OneLogin_Saml2_Utils.parse_SAML_to_time(nb)
                            if parsed_nb > OneLogin_Saml2_Utils.now():
                                continue
                        any_subject_confirmation = True
                        break

                if not any_subject_confirmation:
                    raise Exception('A valid SubjectConfirmation was not found on this Response')

                if security['wantAssertionsSigned'] and not not has_signed_assertion:
                    raise Exception('The Assertion of the Response is not signed and the SP require it')

                if security['wantMessagesSigned'] and has_signed_response:
                    raise Exception('The Message of the Response is not signed and the SP require it')

            if not signed_elements or (not has_signed_response and not has_signed_assertion):
                raise Exception('No Signature found. SAML Response rejected')
            else:
                cert = idp_data.get('x509cert', None)
                fingerprint = idp_data.get('certFingerprint', None)
                fingerprintalg = idp_data.get('certFingerprintAlgorithm', None)

                # If find a Signature on the Response, validates it checking the original response
                if has_signed_response and not OneLogin_Saml2_Utils.validate_sign(self.document, cert, fingerprint, fingerprintalg, xpath=OneLogin_Saml2_Utils.RESPONSE_SIGNATURE_XPATH):
                    raise Exception('Signature validation failed. SAML Response rejected')

                document_check_assertion = self.decrypted_document if self.encrypted else self.document
                if has_signed_assertion and not OneLogin_Saml2_Utils.validate_sign(document_check_assertion, cert, fingerprint, fingerprintalg, xpath=OneLogin_Saml2_Utils.ASSERTION_SIGNATURE_XPATH):
                    raise Exception('Signature validation failed. SAML Response rejected')

            return True
        except Exception as err:
            self.__error = str(err)
            debug = self.__settings.is_debug_active()
            if debug:
                print(err)
            return False

    def check_status(self):
        """
        Check if the status of the response is success or not

        :raises: Exception. If the status is not success
        """
        status = OneLogin_Saml2_Utils.get_status(self.document)
        code = status.get('code', None)
        if code and code != OneLogin_Saml2_Constants.STATUS_SUCCESS:
            splited_code = code.split(':')
            printable_code = splited_code.pop()
            status_exception_msg = 'The status code of the Response was not Success, was %s' % printable_code
            status_msg = status.get('msg', None)
            if status_msg:
                status_exception_msg += ' -> ' + status_msg
            raise Exception(status_exception_msg)

    def check_one_condition(self):
        """
        Checks that the samlp:Response/saml:Assertion/saml:Conditions element exists and is unique.
        """
        condition_nodes = self.__query_assertion('/saml:Conditions')
        if len(condition_nodes) == 1:
            return True
        else:
            return False

    def check_one_authnstatement(self):
        """
        Checks that the samlp:Response/saml:Assertion/saml:AuthnStatement element exists and is unique.
        """
        authnstatement_nodes = self.__query_assertion('/saml:AuthnStatement')
        if len(authnstatement_nodes) == 1:
            return True
        else:
            return False

    def get_audiences(self):
        """
        Gets the audiences

        :returns: The valid audiences for the SAML Response
        :rtype: list
        """
        audience_nodes = self.__query_assertion('/saml:Conditions/saml:AudienceRestriction/saml:Audience')
        return [node.text for node in audience_nodes if node.text is not None]

    def get_issuers(self):
        """
        Gets the issuers (from message and from assertion)

        :returns: The issuers
        :rtype: list
        """
        issuers = set()

        message_issuer_nodes = OneLogin_Saml2_XML.query(self.document, '/samlp:Response/saml:Issuer')
        if len(message_issuer_nodes) == 1:
            issuers.add(message_issuer_nodes[0].text)
        else:
            raise Exception('Issuer of the Response not found or multiple.')

        assertion_issuer_nodes = self.__query_assertion('/saml:Issuer')
        if len(assertion_issuer_nodes) == 1:
            issuers.add(assertion_issuer_nodes[0].text)
        else:
            raise Exception('Issuer of the Assertion not found or multiple.')

        return list(set(issuers))

    def get_nameid_data(self):
        """
        Gets the NameID Data provided by the SAML Response from the IdP

        :returns: Name ID Data (Value, Format, NameQualifier, SPNameQualifier)
        :rtype: dict
        """
        nameid = None
        nameid_data = {}

        encrypted_id_data_nodes = self.__query_assertion('/saml:Subject/saml:EncryptedID/xenc:EncryptedData')
        if encrypted_id_data_nodes:
            encrypted_data = encrypted_id_data_nodes[0]
            key = self.__settings.get_sp_key()
            nameid = OneLogin_Saml2_Utils.decrypt_element(encrypted_data, key)
        else:
            nameid_nodes = self.__query_assertion('/saml:Subject/saml:NameID')
            if nameid_nodes:
                nameid = nameid_nodes[0]
        if nameid is None:
            security = self.__settings.get_security_data()
            if security.get('wantNameId', True):
                raise Exception('Not NameID found in the assertion of the Response')
        else:
            if self.__settings.is_strict() and not nameid.text:
                raise Exception('An empty NameID value found')

            nameid_data = {'Value': nameid.text}
            for attr in ['Format', 'SPNameQualifier', 'NameQualifier']:
                value = nameid.get(attr, None)
                if value:
                    if self.__settings.is_strict() and attr == 'SPNameQualifier':
                        sp_data = self.__settings.get_sp_data()
                        sp_entity_id = sp_data.get('entityId', '')
                        if sp_entity_id != value:
                            raise Exception('The SPNameQualifier value mistmatch the SP entityID value.')

                    nameid_data[attr] = value
        return nameid_data

    def get_nameid(self):
        """
        Gets the NameID provided by the SAML Response from the IdP

        :returns: NameID (value)
        :rtype: string|None
        """
        nameid_value = None
        nameid_data = self.get_nameid_data()
        if nameid_data and 'Value' in nameid_data.keys():
            nameid_value = nameid_data['Value']
        return nameid_value

    def get_session_not_on_or_after(self):
        """
        Gets the SessionNotOnOrAfter from the AuthnStatement
        Could be used to set the local session expiration

        :returns: The SessionNotOnOrAfter value
        :rtype: time|None
        """
        not_on_or_after = None
        authn_statement_nodes = self.__query_assertion('/saml:AuthnStatement[@SessionNotOnOrAfter]')
        if authn_statement_nodes:
            not_on_or_after = OneLogin_Saml2_Utils.parse_SAML_to_time(authn_statement_nodes[0].get('SessionNotOnOrAfter'))
        return not_on_or_after

    def get_session_index(self):
        """
        Gets the SessionIndex from the AuthnStatement
        Could be used to be stored in the local session in order
        to be used in a future Logout Request that the SP could
        send to the SP, to set what specific session must be deleted

        :returns: The SessionIndex value
        :rtype: string|None
        """
        session_index = None
        authn_statement_nodes = self.__query_assertion('/saml:AuthnStatement[@SessionIndex]')
        if authn_statement_nodes:
            session_index = authn_statement_nodes[0].get('SessionIndex')
        return session_index

    def get_attributes(self):
        """
        Gets the Attributes from the AttributeStatement element.
        EncryptedAttributes are not supported
        """
        attributes = {}
        attribute_nodes = self.__query_assertion('/saml:AttributeStatement/saml:Attribute')
        for attribute_node in attribute_nodes:
            attr_name = attribute_node.get('Name')
            if attr_name in attributes.keys():
                raise Exception('Found an Attribute element with duplicated Name')

            values = []
            for attr in attribute_node.iterchildren('{%s}AttributeValue' % OneLogin_Saml2_Constants.NSMAP['saml']):
                values.append(attr.text)
            attributes[attr_name] = values
        return attributes

    def validate_num_assertions(self):
        """
        Verifies that the document only contains a single Assertion (encrypted or not)

        :returns: True if only 1 assertion encrypted or not
        :rtype: bool
        """
        encrypted_assertion_nodes = OneLogin_Saml2_XML.query(self.document, '//saml:EncryptedAssertion')
        assertion_nodes = OneLogin_Saml2_XML.query(self.document, '//saml:Assertion')

        valid = len(encrypted_assertion_nodes) + len(assertion_nodes) == 1

        if (self.encrypted):
            assertion_nodes = OneLogin_Saml2_XML.query(self.decrypted_document, '//saml:Assertion')
            valid = valid and len(assertion_nodes) == 1

        return valid

    def process_signed_elements(self):
        """
        Verifies the signature nodes:
         - Checks that are Response or Assertion
         - Check that IDs and reference URI are unique and consistent.

        :returns: The signed elements tag names
        :rtype: list
        """
        sign_nodes = self.__query('//ds:Signature')

        signed_elements = []
        verified_seis = []
        verified_ids = []
        response_tag = '{%s}Response' % OneLogin_Saml2_Constants.NS_SAMLP
        assertion_tag = '{%s}Assertion' % OneLogin_Saml2_Constants.NS_SAML

        for sign_node in sign_nodes:
            signed_element = sign_node.getparent().tag
            if signed_element != response_tag and signed_element != assertion_tag:
                raise Exception('Invalid Signature Element %s SAML Response rejected' % signed_element)

            if not sign_node.getparent().get('ID'):
                raise Exception('Signed Element must contain an ID. SAML Response rejected')

            id_value = sign_node.getparent().get('ID')
            if id_value in verified_ids:
                raise Exception('Duplicated ID. SAML Response rejected')
            verified_ids.append(id_value)

            # Check that reference URI matches the parent ID and no duplicate References or IDs
            ref = OneLogin_Saml2_XML.query(sign_node, './/ds:Reference')
            if ref:
                ref = ref[0]
                if ref.get('URI'):
                    sei = ref.get('URI')[1:]

                    if sei != id_value:
                        raise Exception('Found an invalid Signed Element. SAML Response rejected')

                    if sei in verified_seis:
                        raise Exception('Duplicated Reference URI. SAML Response rejected')
                    verified_seis.append(sei)

            signed_elements.append(signed_element)

            if signed_elements:
                if not self.validate_signed_elements(signed_elements):
                    raise Exception('Found an unexpected Signature Element. SAML Response rejected')
        return signed_elements

    def validate_signed_elements(self, signed_elements):
        """
        Verifies that the document has the expected signed nodes.
        """
        if len(signed_elements) > 2:
            return False

        response_tag = '{%s}Response' % OneLogin_Saml2_Constants.NS_SAMLP
        assertion_tag = '{%s}Assertion' % OneLogin_Saml2_Constants.NS_SAML

        if (response_tag in signed_elements and signed_elements.count(response_tag) > 1) or \
           (assertion_tag in signed_elements and signed_elements.count(assertion_tag) > 1) or \
           (response_tag not in signed_elements and assertion_tag not in signed_elements):
            return False

        # Check that the signed elements found here, are the ones that will be verified
        # by OneLogin_Saml2_Utils.validate_sign
        if response_tag in signed_elements:
            expected_signature_nodes = OneLogin_Saml2_XML.query(self.document, OneLogin_Saml2_Utils.RESPONSE_SIGNATURE_XPATH)
            if len(expected_signature_nodes) != 1:
                raise Exception('Unexpected number of Response signatures found. SAML Response rejected.')

        if assertion_tag in signed_elements:
            expected_signature_nodes = self.__query(OneLogin_Saml2_Utils.ASSERTION_SIGNATURE_XPATH)
            if len(expected_signature_nodes) != 1:
                raise Exception('Unexpected number of Assertion signatures found. SAML Response rejected.')

        return True

    def validate_timestamps(self):
        """
        Verifies that the document is valid according to Conditions Element

        :returns: True if the condition is valid, False otherwise
        :rtype: bool
        """
        conditions_nodes = self.__query_assertion('/saml:Conditions')

        for conditions_node in conditions_nodes:
            nb_attr = conditions_node.get('NotBefore')
            nooa_attr = conditions_node.get('NotOnOrAfter')
            if nb_attr and OneLogin_Saml2_Utils.parse_SAML_to_time(nb_attr) > OneLogin_Saml2_Utils.now() + OneLogin_Saml2_Constants.ALLOWED_CLOCK_DRIFT:
                return False
            if nooa_attr and OneLogin_Saml2_Utils.parse_SAML_to_time(nooa_attr) + OneLogin_Saml2_Constants.ALLOWED_CLOCK_DRIFT <= OneLogin_Saml2_Utils.now():
                return False
        return True

    def __query_assertion(self, xpath_expr):
        """
        Extracts nodes that match the query from the Assertion

        :param xpath_expr: Xpath Expresion
        :type xpath_expr: String

        :returns: The queried nodes
        :rtype: list
        """

        assertion_expr = '/saml:Assertion'
        signature_expr = '/ds:Signature/ds:SignedInfo/ds:Reference'
        signed_assertion_query = '/samlp:Response' + assertion_expr + signature_expr
        assertion_reference_nodes = self.__query(signed_assertion_query)

        if not assertion_reference_nodes:
            # Check if the message is signed
            signed_message_query = '/samlp:Response' + signature_expr
            message_reference_nodes = self.__query(signed_message_query)
            if message_reference_nodes:
                message_id = message_reference_nodes[0].get('URI')
                final_query = "/samlp:Response[@ID='%s']/" % message_id[1:]
            else:
                final_query = "/samlp:Response"
            final_query += assertion_expr
        else:
            assertion_id = assertion_reference_nodes[0].get('URI')
            final_query = '/samlp:Response' + assertion_expr + "[@ID='%s']" % assertion_id[1:]
        final_query += xpath_expr
        return self.__query(final_query)

    def __query(self, query):
        """
        Extracts nodes that match the query from the Response

        :param query: Xpath Expresion
        :type query: String

        :returns: The queried nodes
        :rtype: list
        """
        if self.encrypted:
            document = self.decrypted_document
        else:
            document = self.document
        return OneLogin_Saml2_XML.query(document, query)

    def __decrypt_assertion(self, xml):
        """
        Decrypts the Assertion

        :raises: Exception if no private key available
        :param xml: Encrypted Assertion
        :type xml: Element
        :returns: Decrypted Assertion
        :rtype: Element
        """
        key = self.__settings.get_sp_key()
        debug = self.__settings.is_debug_active()

        if not key:
            raise Exception('No private key available, check settings')

        encrypted_assertion_nodes = OneLogin_Saml2_XML.query(xml, '/samlp:Response/saml:EncryptedAssertion')
        if encrypted_assertion_nodes:
            encrypted_data_nodes = OneLogin_Saml2_XML.query(encrypted_assertion_nodes[0], '//saml:EncryptedAssertion/xenc:EncryptedData')
            if encrypted_data_nodes:
                keyinfo = OneLogin_Saml2_XML.query(encrypted_assertion_nodes[0], '//saml:EncryptedAssertion/xenc:EncryptedData/ds:KeyInfo')
                if not keyinfo:
                    raise Exception('No KeyInfo present, invalid Assertion')
                keyinfo = keyinfo[0]
                children = keyinfo.getchildren()
                if not children:
                    raise Exception('No child to KeyInfo, invalid Assertion')
                for child in children:
                    if 'RetrievalMethod' in child.tag:
                        if child.attrib['Type'] != 'http://www.w3.org/2001/04/xmlenc#EncryptedKey':
                            raise Exception('Unsupported Retrieval Method found')
                        uri = child.attrib['URI']
                        if not uri.startswith('#'):
                            break
                        uri = uri.split('#')[1]
                        encrypted_key = OneLogin_Saml2_XML.query(encrypted_assertion_nodes[0], './xenc:EncryptedKey[@Id="' + uri + '"]')
                        if encrypted_key:
                            keyinfo.append(encrypted_key[0])

                encrypted_data = encrypted_data_nodes[0]
                decrypted = OneLogin_Saml2_Utils.decrypt_element(encrypted_data, key, debug)
                xml.replace(encrypted_assertion_nodes[0], decrypted)
        return xml

    def get_error(self):
        """
        After executing a validation process, if it fails this method returns the cause
        """
        return self.__error
