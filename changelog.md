# python3-saml changelog

### 1.2.3 (January 15, 2017)
 * Fix p3 compatibility

### 1.2.2 (January 11, 2017)
 * [#37](https://github.com/onelogin/python3-saml/pull/37) Add option to raise response validation exceptions
 * [#42](https://github.com/onelogin/python3-saml/pull/42) Optionally raise detailed exceptions vs. returning False. Implement a more specific exception class for handling some validation errors. Improve/Fix tests. Add support for retrieving the last ID of the generated AuthNRequest / LogoutRequest. Add hooks to retrieve last-sent and last-received requests and responses
 * Improved inResponse validation on Responses
 * Add the ability to extract the specific certificate from IdP metadata when several defined
 * Fix Invalid True attribute value in Metadata XML
 * [#35](https://github.com/onelogin/python3-saml/pull/35) Fix typos and json sample code in documentation

### 1.2.1 (October 18, 2016)
 * [#30](https://github.com/onelogin/python3-saml/pull/30) Bug on signature checks

### 1.2.0 (October 14, 2016)
* Several security improvements:
  * Conditions element required and unique.
  * AuthnStatement element required and unique.
  * SPNameQualifier must math the SP EntityID
  * Reject saml:Attribute element with same “Name” attribute
  * Reject empty nameID
  * Require Issuer element. (Must match IdP EntityID).
  * Destination value can't be blank (if present must match ACS URL).
  * Check that the EncryptedAssertion element only contains 1 Assertion element.
* Improve Signature validation process
* Document the wantAssertionsEncrypted parameter
* Support multiple attributeValues on RequestedAttribute
* Fix AttributeConsumingService

### 1.1.4 (Jun 27, 2016)
* Change the decrypt assertion process.
* Add 2 extra validations to prevent Signature wrapping attacks.

### 1.1.3 (Jun 02, 2016)
* Fix Metadata XML (RequestedAttribute)
* Fix Windows specific Unix date formatting bug.
* Fix SHA384 Constant URI
* Refactor of settings.py to make it a little more readable.
* Bugfix for ADFS lowercase signatures
* READMEs suggested wrong cert name

### 1.1.2 (May 14, 2016)

* Allow AuthnRequest with no NameIDPolicy.
* Remove NameId requirement on SAMLResponse, now requirement depends on setting
* Use python-xmlsec 0.6.0
* Make idp settings optional
* Fix Organization element on SP metadata. Minor style code fix
* Add debug parameter to decrypt method
* Support AttributeConsumingService
* Improve AuthNRequest format
* Fix unspecified NameID
* Make deflate process when retrieving built SAML messages optional
* Not compare Assertion InResponseTo if not found
* [#15](https://github.com/onelogin/python3-saml/pull/15) Passing NameQualifier through to logout request
* Improve documentation
* [#12](https://github.com/onelogin/python3-saml/pull/12) Add information about getting the demos up and running on Heroku

### 1.1.1 (Mar 17, 2016)
* Make AttributeStatements requirement optional
