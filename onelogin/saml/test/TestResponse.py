from datetime import datetime

import base64
import fudge

from nose.tools import eq_ as eq

from onelogin.saml.test.util import assert_raises
from onelogin.saml import (
    Response,
    ResponseValidationError,
    ResponseNameIDError,
    ResponseConditionError,
    )

test_response = """<samlp:Response
   xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
   xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
   ID="identifier_2"
   InResponseTo="identifier_1"
   Version="2.0"
   IssueInstant="2004-12-05T09:22:05Z"
   Destination="https://sp.example.com/SAML2/SSO/POST">
   <saml:Issuer>https://idp.example.org/SAML2</saml:Issuer>
   <samlp:Status>
     <samlp:StatusCode
       Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
   </samlp:Status>
   <saml:Assertion
     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
     ID="identifier_3"
     Version="2.0"
     IssueInstant="2004-12-05T09:22:05Z">
     <saml:Issuer>https://idp.example.org/SAML2</saml:Issuer>
     <ds:Signature
       xmlns:ds="http://www.w3.org/2000/09/xmldsig#">foo signature</ds:Signature>
     <saml:Subject>
       <saml:NameID
         Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">
         3f7b3dcf-1674-4ecd-92c8-1544f346baf8
       </saml:NameID>
       <saml:SubjectConfirmation
         Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
         <saml:SubjectConfirmationData
           InResponseTo="identifier_1"
           Recipient="https://sp.example.com/SAML2/SSO/POST"
           NotOnOrAfter="2004-12-05T09:27:05Z"/>
       </saml:SubjectConfirmation>
     </saml:Subject>
     <saml:Conditions
       NotBefore="2004-12-05T09:17:05Z"
       NotOnOrAfter="2004-12-05T09:27:05Z">
       <saml:AudienceRestriction>
         <saml:Audience>https://sp.example.com/SAML2</saml:Audience>
       </saml:AudienceRestriction>
     </saml:Conditions>
     <saml:AuthnStatement
       AuthnInstant="2004-12-05T09:22:00Z"
       SessionIndex="identifier_3">
       <saml:AuthnContext>
         <saml:AuthnContextClassRef>
           urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
        </saml:AuthnContextClassRef>
       </saml:AuthnContext>
     </saml:AuthnStatement>
   </saml:Assertion>
 </samlp:Response>
"""

class TestResponse(object):
    def setUp(self):
        fudge.clear_expectations()

    @fudge.with_fakes
    def test__init__(self):
        fake_base64 = fudge.Fake('base64')
        fake_base64.remember_order()
        decode = fake_base64.expects('b64decode')
        decode.with_args('foo response')
        decode.returns('foo decoded response')

        fake_etree = fudge.Fake('etree')
        fake_etree.remember_order()
        from_string = fake_etree.expects('fromstring')
        from_string.with_args('foo decoded response')
        from_string.returns('foo document')

        res = Response(
            response='foo response',
            signature='foo signature',
            _base64=fake_base64,
            _etree=fake_etree,
            )

        eq(res._document, 'foo document')
        eq(res._signature, 'foo signature')

    @fudge.with_fakes
    def test_get_name_id_simple(self):
        encoded_response = base64.b64encode(test_response)
        res = Response(
            response=encoded_response,
            signature=None,
            )
        name_id = res.name_id

        eq('3f7b3dcf-1674-4ecd-92c8-1544f346baf8', name_id)

    @fudge.with_fakes
    def test_get_name_id_multiple(self):
        response = """<samlp:Response
   xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
   xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
   ID="identifier_2"
   InResponseTo="identifier_1"
   Version="2.0"
   IssueInstant="2004-12-05T09:22:05Z"
   Destination="https://sp.example.com/SAML2/SSO/POST">
   <saml:Issuer>https://idp.example.org/SAML2</saml:Issuer>
   <samlp:Status>
     <samlp:StatusCode
       Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
   </samlp:Status>
   <saml:Assertion
     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
     ID="identifier_3"
     Version="2.0"
     IssueInstant="2004-12-05T09:22:05Z">
     <saml:Issuer>https://idp.example.org/SAML2</saml:Issuer>
     <ds:Signature
       xmlns:ds="http://www.w3.org/2000/09/xmldsig#">...</ds:Signature>
     <saml:Subject>
       <saml:NameID
         Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">
         3f7b3dcf-1674-4ecd-92c8-1544f346baf8
       </saml:NameID>
       <saml:NameID
         Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">
         foo-copy
       </saml:NameID>
       <saml:SubjectConfirmation
         Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
         <saml:SubjectConfirmationData
           InResponseTo="identifier_1"
           Recipient="https://sp.example.com/SAML2/SSO/POST"
           NotOnOrAfter="2004-12-05T09:27:05Z"/>
       </saml:SubjectConfirmation>
     </saml:Subject>
     <saml:Conditions
       NotBefore="2004-12-05T09:17:05Z"
       NotOnOrAfter="2004-12-05T09:27:05Z">
       <saml:AudienceRestriction>
         <saml:Audience>https://sp.example.com/SAML2</saml:Audience>
       </saml:AudienceRestriction>
     </saml:Conditions>
     <saml:AuthnStatement
       AuthnInstant="2004-12-05T09:22:00Z"
       SessionIndex="identifier_3">
       <saml:AuthnContext>
         <saml:AuthnContextClassRef>
           urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
        </saml:AuthnContextClassRef>
       </saml:AuthnContext>
     </saml:AuthnStatement>
   </saml:Assertion>
 </samlp:Response>
"""
        encoded_response = base64.b64encode(response)
        res = Response(
            response=encoded_response,
            signature=None,
            )
        msg = assert_raises(
            ResponseNameIDError,
            res._get_name_id,
            )

        eq(
            str(msg),
            ('There was a problem getting the name ID: Found more than one '
             + 'name ID'
             ),
            )

    @fudge.with_fakes
    def test_get_name_id_none(self):
        response = """<samlp:Response
   xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
   xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
   ID="identifier_2"
   InResponseTo="identifier_1"
   Version="2.0"
   IssueInstant="2004-12-05T09:22:05Z"
   Destination="https://sp.example.com/SAML2/SSO/POST">
   <saml:Issuer>https://idp.example.org/SAML2</saml:Issuer>
   <samlp:Status>
     <samlp:StatusCode
       Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
   </samlp:Status>
   <saml:Assertion
     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
     ID="identifier_3"
     Version="2.0"
     IssueInstant="2004-12-05T09:22:05Z">
     <saml:Issuer>https://idp.example.org/SAML2</saml:Issuer>
     <ds:Signature
       xmlns:ds="http://www.w3.org/2000/09/xmldsig#">...</ds:Signature>
     <saml:Subject>
       <saml:SubjectConfirmation
         Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
         <saml:SubjectConfirmationData
           InResponseTo="identifier_1"
           Recipient="https://sp.example.com/SAML2/SSO/POST"
           NotOnOrAfter="2004-12-05T09:27:05Z"/>
       </saml:SubjectConfirmation>
     </saml:Subject>
     <saml:Conditions
       NotBefore="2004-12-05T09:17:05Z"
       NotOnOrAfter="2004-12-05T09:27:05Z">
       <saml:AudienceRestriction>
         <saml:Audience>https://sp.example.com/SAML2</saml:Audience>
       </saml:AudienceRestriction>
     </saml:Conditions>
     <saml:AuthnStatement
       AuthnInstant="2004-12-05T09:22:00Z"
       SessionIndex="identifier_3">
       <saml:AuthnContext>
         <saml:AuthnContextClassRef>
           urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
        </saml:AuthnContextClassRef>
       </saml:AuthnContext>
     </saml:AuthnStatement>
   </saml:Assertion>
 </samlp:Response>
"""
        encoded_response = base64.b64encode(response)
        res = Response(
            response=encoded_response,
            signature=None,
            )
        msg = assert_raises(
            ResponseNameIDError,
            res._get_name_id,
            )

        eq(
            str(msg),
            ('There was a problem getting the name ID: Did not find a name '
             + 'ID'
             ),
            )

    @fudge.with_fakes
    def test_is_valid_not_before_missing(self):
        response = """<samlp:Response
   xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
   xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
   ID="identifier_2"
   InResponseTo="identifier_1"
   Version="2.0"
   IssueInstant="2004-12-05T09:22:05Z"
   Destination="https://sp.example.com/SAML2/SSO/POST">
   <saml:Issuer>https://idp.example.org/SAML2</saml:Issuer>
   <samlp:Status>
     <samlp:StatusCode
       Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
   </samlp:Status>
   <saml:Assertion
     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
     ID="identifier_3"
     Version="2.0"
     IssueInstant="2004-12-05T09:22:05Z">
     <saml:Issuer>https://idp.example.org/SAML2</saml:Issuer>
     <ds:Signature
       xmlns:ds="http://www.w3.org/2000/09/xmldsig#">foo signature</ds:Signature>
     <saml:Subject>
       <saml:NameID
         Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">
         3f7b3dcf-1674-4ecd-92c8-1544f346baf8
       </saml:NameID>
       <saml:SubjectConfirmation
         Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
         <saml:SubjectConfirmationData
           InResponseTo="identifier_1"
           Recipient="https://sp.example.com/SAML2/SSO/POST"
           NotOnOrAfter="2004-12-05T09:27:05Z"/>
       </saml:SubjectConfirmation>
     </saml:Subject>
     <saml:Conditions
       NotOnOrAfter="2004-12-05T09:27:05Z">
       <saml:AudienceRestriction>
         <saml:Audience>https://sp.example.com/SAML2</saml:Audience>
       </saml:AudienceRestriction>
     </saml:Conditions>
     <saml:AuthnStatement
       AuthnInstant="2004-12-05T09:22:00Z"
       SessionIndex="identifier_3">
       <saml:AuthnContext>
         <saml:AuthnContextClassRef>
           urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
        </saml:AuthnContextClassRef>
       </saml:AuthnContext>
     </saml:AuthnStatement>
   </saml:Assertion>
 </samlp:Response>
"""
        encoded_response = base64.b64encode(response)
        res = Response(
            response=encoded_response,
            signature=None,
            )
        msg = assert_raises(
            ResponseConditionError,
            res.is_valid,
            )

        eq(str(msg),
           ('There was a problem validating a condition: Did not find NotBefore '
            + 'condition'
            ),
           )

    @fudge.with_fakes
    def test_is_valid_not_on_or_after_missing(self):
        response = """<samlp:Response
   xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
   xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
   ID="identifier_2"
   InResponseTo="identifier_1"
   Version="2.0"
   IssueInstant="2004-12-05T09:22:05Z"
   Destination="https://sp.example.com/SAML2/SSO/POST">
   <saml:Issuer>https://idp.example.org/SAML2</saml:Issuer>
   <samlp:Status>
     <samlp:StatusCode
       Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
   </samlp:Status>
   <saml:Assertion
     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
     ID="identifier_3"
     Version="2.0"
     IssueInstant="2004-12-05T09:22:05Z">
     <saml:Issuer>https://idp.example.org/SAML2</saml:Issuer>
     <ds:Signature
       xmlns:ds="http://www.w3.org/2000/09/xmldsig#">foo signature</ds:Signature>
     <saml:Subject>
       <saml:NameID
         Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">
         3f7b3dcf-1674-4ecd-92c8-1544f346baf8
       </saml:NameID>
       <saml:SubjectConfirmation
         Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
         <saml:SubjectConfirmationData
           InResponseTo="identifier_1"
           Recipient="https://sp.example.com/SAML2/SSO/POST"
           NotOnOrAfter="2004-12-05T09:27:05Z"/>
       </saml:SubjectConfirmation>
     </saml:Subject>
     <saml:Conditions
       NotBefore="2004-12-05T09:27:05Z">
       <saml:AudienceRestriction>
         <saml:Audience>https://sp.example.com/SAML2</saml:Audience>
       </saml:AudienceRestriction>
     </saml:Conditions>
     <saml:AuthnStatement
       AuthnInstant="2004-12-05T09:22:00Z"
       SessionIndex="identifier_3">
       <saml:AuthnContext>
         <saml:AuthnContextClassRef>
           urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
        </saml:AuthnContextClassRef>
       </saml:AuthnContext>
     </saml:AuthnStatement>
   </saml:Assertion>
 </samlp:Response>
"""
        encoded_response = base64.b64encode(response)
        res = Response(
            response=encoded_response,
            signature=None,
            )
        msg = assert_raises(
            ResponseConditionError,
            res.is_valid,
            )

        eq(str(msg),
           ('There was a problem validating a condition: Did not find '
            + 'NotOnOrAfter condition'
            ),
           )

    @fudge.with_fakes
    def test_is_valid_current_time_earlier(self):
        encoded_response = base64.b64encode(test_response)
        res = Response(
            response=encoded_response,
            signature=None,
            )

        def fake_clock():
            return datetime(2004, 12, 05, 9, 16, 45, 462796)
        msg = assert_raises(
            ResponseValidationError,
            res.is_valid,
            _clock=fake_clock,
            )

        eq(str(msg),
           ('There was a problem validating the response: Current time is '
            + 'earlier than NotBefore condition'
            ),
           )

    @fudge.with_fakes
    def test_is_valid_current_time_on_or_after(self):
        encoded_response = base64.b64encode(test_response)
        res = Response(
            response=encoded_response,
            signature=None,
            )

        def fake_clock():
            return datetime(2004, 12, 05, 9, 30, 45, 462796)
        msg = assert_raises(
            ResponseValidationError,
            res.is_valid,
            _clock=fake_clock,
            )

        eq(str(msg),
           ('There was a problem validating the response: Current time is '
            + 'on or after NotOnOrAfter condition'
            ),
           )

    @fudge.with_fakes
    def test_is_valid_simple(self):
        encoded_response = base64.b64encode(test_response)
        res = Response(
            response=encoded_response,
            signature='foo signature',
            )

        def fake_clock():
            return datetime(2004, 12, 05, 9, 18, 45, 462796)

        fake_verifier = fudge.Fake(
            'verifier',
            callable=True,
            )
        fake_verifier.times_called(1)
        fake_verifier.with_args(res._document, 'foo signature')

        fake_verifier.returns(True)

        msg = res.is_valid(
            _clock=fake_clock,
            _verifier=fake_verifier,
            )

        eq(msg, True)
