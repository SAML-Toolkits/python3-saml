from base64 import b64encode

from onelogin.saml2.utils import (OneLogin_Saml2_Utils,
                                  OneLogin_Saml2_ValidationError)
from onelogin.saml2.xml_utils import OneLogin_Saml2_XML


class Artifact_Response:
    def __init__(self, settings, response):
        self.__settings = settings
        self.__error = None
        self.id = None

        self.__artifact_response = response

        soap_envelope = OneLogin_Saml2_XML.to_etree(self.__artifact_response)

        self.document = OneLogin_Saml2_XML.query(
            soap_envelope, '/soap:Envelope/soap:Body'
        )[0].getchildren()[0]

        self.id = self.document.get('ID', None)

    def get_issuer(self):
        """
        Gets the Issuer of the Logout Response Message
        :return: The Issuer
        :rtype: string
        """
        issuer = None
        issuer_nodes = self.__query('/samlp:ArtifactResponse/saml:Issuer')
        if len(issuer_nodes) == 1:
            issuer = OneLogin_Saml2_XML.element_text(issuer_nodes[0])
        return issuer

    def get_status(self):
        """
        Gets the Status
        :return: The Status
        :rtype: string
        """
        entries = self.__query('/samlp:ArtifactResponse/samlp:Status/samlp:StatusCode')
        if len(entries) == 0:
            return None
        status = entries[0].attrib['Value']
        return status

    def is_valid(self, request_id, raise_exceptions=False):
        """
        Determines if the SAML ArtifactResponse is valid
        :param request_id: The ID of the ArtifactResolve sent by this SP to the IdP
        :type request_id: string

        :param raise_exceptions: Whether to return false on failure or raise an exception
        :type raise_exceptions: Boolean

        :return: Returns if the SAML ArtifactResponse is or not valid
        :rtype: boolean
        """
        self.__error = None
        try:
            idp_data = self.__settings.get_idp_data()
            idp_entity_id = idp_data['entityId']

            if self.__settings.is_strict():
                res = OneLogin_Saml2_XML.validate_xml(self.document, 'saml-schema-protocol-2.0.xsd', self.__settings.is_debug_active())
                if isinstance(res, str):
                    raise OneLogin_Saml2_ValidationError(
                        'Invalid SAML ArtifactResponse. Not match the saml-schema-protocol-2.0.xsd',
                        OneLogin_Saml2_ValidationError.INVALID_XML_FORMAT
                    )

                security = self.__settings.get_security_data()

                # Check if the InResponseTo of the Artifact Response matches the ID of the Artifact Resolve Request (requestId) if provided
                in_response_to = self.get_in_response_to()
                if in_response_to and in_response_to != request_id:
                    raise OneLogin_Saml2_ValidationError(
                        'The InResponseTo of the Logout Response: %s, does not match the ID of the Logout request sent by the SP: %s' % (in_response_to, request_id),
                        OneLogin_Saml2_ValidationError.WRONG_INRESPONSETO
                    )

                # Check issuer
                issuer = self.get_issuer()
                if issuer is not None and issuer != idp_entity_id:
                    raise OneLogin_Saml2_ValidationError(
                        'Invalid issuer in the Logout Response (expected %(idpEntityId)s, got %(issuer)s)' %
                        {
                            'idpEntityId': idp_entity_id,
                            'issuer': issuer
                        },
                        OneLogin_Saml2_ValidationError.WRONG_ISSUER
                    )

            return True
        # pylint: disable=R0801
        except Exception as err:
            self.__error = str(err)
            debug = self.__settings.is_debug_active()
            if debug:
                print(err)
            if raise_exceptions:
                raise
            return False

    def __query(self, query):
        """
        Extracts a node from the Etree (Logout Response Message)
        :param query: Xpath Expression
        :type query: string
        :return: The queried node
        :rtype: Element
        """
        return OneLogin_Saml2_XML.query(self.document, query)

    def get_in_response_to(self):
        """
        Gets the ID of the LogoutRequest which this response is in response to
        :returns: ID of LogoutRequest this LogoutResponse is in response to or None if it is not present
        :rtype: str
        """
        return self.document.get('InResponseTo')

    def get_error(self):
        """
        After executing a validation process, if it fails this method returns the cause
        """
        return self.__error

    def get_xml(self):
        """
        Returns the XML that will be sent as part of the response
        or that was received at the SP
        :return: XML response body
        :rtype: string
        """
        return self.__artifact_response

    def get_response_xml(self):
        return b64encode(
            OneLogin_Saml2_XML.to_string(
                self.__query('//samlp:ArtifactResponse/samlp:Response')[0]
            )
        )
