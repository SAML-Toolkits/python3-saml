from base64 import b64decode
from binascii import hexlify
from hashlib import sha1

import requests
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from onelogin.saml2.xml_templates import OneLogin_Saml2_Templates

from .errors import OneLogin_Saml2_ValidationError


def parse_saml2_artifact(artifact):
    #
    # SAMLBind - See 3.6.4 Artifact Format, for SAMLart format.
    #
    decoded = b64decode(artifact)
    type_code = b'\x00\x04'

    if decoded[:2] != type_code:
        raise OneLogin_Saml2_ValidationError()

    index = str(int.from_bytes(decoded[2:4], byteorder="big"))
    sha1_entity_id = decoded[4:24]
    message_handle = decoded[24:44]

    return index, sha1_entity_id, message_handle


class Artifact_Resolve_Request:
    def __init__(self, settings, saml_art):
        self.__settings = settings
        self.validate_saml2_artifact(saml_art)
        self.saml_art = saml_art

        sp_data = self.__settings.get_sp_data()

        uid = OneLogin_Saml2_Utils.generate_unique_id()
        self.__id = uid

        issue_instant = OneLogin_Saml2_Utils.parse_time_to_SAML(OneLogin_Saml2_Utils.now())

        request = OneLogin_Saml2_Templates.ARTIFACT_RESOLVE_REQUEST % \
            {
                'id': uid,
                'issue_instant': issue_instant,
                'entity_id': sp_data['entityId'],
                'artifact': saml_art
            }

        self.__artifact_resolve_request = request

    def validate_saml2_artifact(self, saml_art):
        index, sha1_entity_id, message_handle = parse_saml2_artifact(saml_art)

        idp = self.__settings.get_idp_data()
        if idp['artifactResolutionService']['index'] != index:
            raise OneLogin_Saml2_ValidationError(
                "The SourceID given in the SAML artifact ({}) does not correspond with a "
                "configured ACS index ({})".format(
                    index, idp['artifactResolutionService']['index']
                )
            )

        if sha1_entity_id != sha1(idp['entityId'].encode('utf-8')).digest():
            raise OneLogin_Saml2_ValidationError()

    def get_soap_request(self):
        request = OneLogin_Saml2_Templates.SOAP_ENVELOPE % \
            {
                'soap_body': self.__artifact_resolve_request
            }
        return request

    def send(self):
        idp = self.__settings.get_idp_data()
        headers = {"content-type": "application/soap+xml"}
        return requests.post(
            url=idp['artifactResolutionService']['url'],
            cert=(
                idp['artifactResolutionService']['clientKey'],
                idp['artifactResolutionService']['clientCert'],
            ),
            data=self.get_soap_request(),
            headers=headers,
        )

    def get_id(self):
        """
        Returns the AuthNRequest ID.
        :return: AuthNRequest ID
        :rtype: string
        """
        return self.__id
