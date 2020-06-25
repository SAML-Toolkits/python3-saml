import logging
import requests

from base64 import b64decode
from hashlib import sha1

from onelogin.saml2.utils import OneLogin_Saml2_Utils
from onelogin.saml2.xml_templates import OneLogin_Saml2_Templates
from onelogin.saml2.constants import OneLogin_Saml2_Constants

from .errors import OneLogin_Saml2_ValidationError


logger = logging.getLogger(__name__)


def parse_saml2_artifact(artifact):
    #
    # SAMLBind - See 3.6.4 Artifact Format, for SAMLart format.
    #
    decoded = b64decode(artifact)
    type_code = b'\x00\x04'

    if decoded[:2] != type_code:
        raise OneLogin_Saml2_ValidationError(
            "The received Artifact does not have the correct header.",
            OneLogin_Saml2_ValidationError.WRONG_ARTIFACT_FORMAT
        )

    index = str(int.from_bytes(decoded[2:4], byteorder="big"))
    sha1_entity_id = decoded[4:24]
    message_handle = decoded[24:44]

    return index, sha1_entity_id, message_handle


class Artifact_Resolve_Request:
    def __init__(self, settings, saml_art):
        self.__settings = settings
        self.soap_endpoint = self.find_soap_endpoint(saml_art)
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

    def find_soap_endpoint(self, saml_art):
        idp = self.__settings.get_idp_data()
        index, sha1_entity_id, message_handle = parse_saml2_artifact(saml_art)

        if sha1_entity_id != sha1(idp['entityId'].encode('utf-8')).digest():
            raise OneLogin_Saml2_ValidationError(
                f"The sha1 hash of the entityId returned in the SAML Artifact ({sha1_entity_id})"
                f"does not match the sha1 hash of the configured entityId ({idp['entityId']})"
            )

        for ars_node in idp['artifactResolutionService']:
            if ars_node['binding'] != "urn:oasis:names:tc:SAML:2.0:bindings:SOAP":
                continue
            if ars_node['index'] == index:
                return ars_node

        return None

    def get_soap_request(self):
        request = OneLogin_Saml2_Templates.SOAP_ENVELOPE % \
            {
                'soap_body': self.__artifact_resolve_request
            }

        return OneLogin_Saml2_Utils.add_sign(
            request,
            self.__settings.get_sp_key(), self.__settings.get_sp_cert(),
            sign_algorithm=OneLogin_Saml2_Constants.RSA_SHA256,
            digest_algorithm=OneLogin_Saml2_Constants.SHA256,
        )

    def send(self):
        security_data = self.__settings.get_security_data()
        headers = {"content-type": "application/soap+xml"}
        url = self.soap_endpoint['url']
        data = self.get_soap_request()

        logger.debug(
            "Doing a ArtifactResolve (POST) request to %s with data %s",
            url, data
        )
        return requests.post(
            url=url,
            cert=(
                security_data['soapClientCert'],
                security_data['soapClientKey'],
            ),
            data=data,
            headers=headers,
        )

    def get_id(self):
        """
        Returns the ArtifactResolve ID.
        :return: ArtifactResolve ID
        :rtype: string
        """
        return self.__id
