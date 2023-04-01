# python3-saml changelog
### 1.15.0 (Dec 27, 2022)
- [#317](https://github.com/SAML-Toolkits/python3-saml/pull/317) Handle unicode characters gracefully in python 2
- [#338](https://github.com/SAML-Toolkits/python3-saml/pull/338) Fix WantAuthnRequestsSigned parser
- [#339](https://github.com/SAML-Toolkits/python3-saml/pull/339) Add Poetry support
- Remove version restriction on lxml dependency
- Updated Django demo to 4.X (only py3 compatible)
- Updated Travis file. Forced lxml to be installed using no-validate_binary
- Removed references to OneLogin from documentation

### 1.14.0 (Feb 18, 2022)
- [#297](https://github.com/onelogin/python3-saml/pull/297) Don't require yanked version of lxml.
- [#298](https://github.com/onelogin/python3-saml/pull/298) Add support for python 3.10 and cleanup the GHA.
- [#299](https://github.com/onelogin/python3-saml/pull/299) Remove stats from coveralls removed as they are no longer maintained.

### 1.13.0 (Jan 28, 2022)
- [#296](https://github.com/onelogin/python3-saml/pull/296) Add rejectDeprecatedAlgorithm settings in order to be able reject messages signed with deprecated algorithms.
- Set sha256 and rsa-sha256 as default algorithms
- [#288](https://github.com/onelogin/python3-saml/pull/288) Support building a LogoutResponse with non-success status
- Added warning about Open Redirect and Reply attacks
- [##274](https://github.com/onelogin/python3-saml/pull/274) Replace double-underscored names with single underscores
- Add at OneLogin_Saml2_Auth get_last_assertion_issue_instant() and get_last_response_in_response_to() methods
- Upgrade dependencies

### 1.12.0 (Aug 13, 2021)
* [#276](https://github.com/onelogin/python3-saml/pull/276) Deprecate server_port from request data dictionary

### 1.11.0 (Jul 23, 2021)
* [#261](https://github.com/onelogin/python3-saml/pull/261) Allow duplicate named attributes, controlled by a new setting
* [#268](https://github.com/onelogin/python3-saml/pull/268) Make the redirect scheme matcher case-insensitive
* [#256](https://github.com/onelogin/python3-saml/pull/256) Improve signature validation process. Add an option to use query string for validation
* [#259](https://github.com/onelogin/python3-saml/pull/259) Add get metadata timeout
* [#246](https://github.com/onelogin/python3-saml/pull/246) Add the ability to change the ProtocolBinding in the authn request.
* [#248](https://github.com/onelogin/python3-saml/pull/248) Move storing the response data into its own method in the Auth class
* Remove the dependency on defusedxml
* [#241](https://github.com/onelogin/python3-saml/pull/241) Improve AttributeConsumingService support
* Update expired dates from test responses
* Migrate from Travis to Github Actions

### 1.10.1 (Jan 27, 2021)
* Fix bug on LogoutRequest class, get_idp_slo_response_url was used instead get_idp_slo_url

### 1.10.0 (Jan 14, 2021)
* Added custom lxml parser based on the one defined at xmldefused. Parser will ignore comments and processing instructions and by default have deactivated huge_tree, DTD and access to external documents
* Destination URL Comparison is now case-insensitive for netloc
* Support single-label-domains as valid. New security parameter allowSingleLabelDomains
* Added get_idp_sso_url, get_idp_slo_url and get_idp_slo_response_url methods to the Settings class and use it in the toolkit
* [#212](https://github.com/onelogin/python3-saml/pull/212) Overridability enhancements. Made classes overridable by subclassing. Use of classmethods instead staticmethods
* Add get_friendlyname_attributes support
* Remove external lib method get_ext_lib_path. Add set_cert_path in order to allow set the cert path in a different folder than the toolkit
* Add sha256 instead sha1 algorithm for sign/digest as recommended value on documentation and settings
* [#178](https://github.com/onelogin/python3-saml/pull/178) Support for adding idp.crt from filesystem
* Add samlUserdata to demo-flask session
* Fix autoreloading in demo-tornado

### 1.9.0 (Nov 20, 2019)
* Allow any number of decimal places for seconds on SAML datetimes
* Fix failOnAuthnContextMismatch code
* Improve signature validation when no reference uri
* Update demo versions. Improve them and add Tornado demo.

### 1.8.0 (Sep 11, 2019)
* Set true as the default value for strict setting
* [#152](https://github.com/onelogin/python3-saml/pull/152/files) Don't clean xsd and xsi namespaces
* Drop python3.4 support due lxml. See lxml 4.4.0 (2019-07-27)

### 1.7.0 (Jul 02, 2019)
* Adjusted acs endpoint to extract NameQualifier and SPNameQualifier from SAMLResponse. Adjusted single logout service to provide NameQualifier and SPNameQualifier to logout method. Add getNameIdNameQualifier to Auth and SamlResponse. Extend logout method from Auth and LogoutRequest constructor to support SPNameQualifier parameter. Align LogoutRequest constructor with SAML specs
* Added get_in_response_to method to Response and LogoutResponse classes
* Update defusexml dependency

### 1.6.0 (Apr 10, 2019)
* Add support for Subjects on AuthNRequests by the new name_id_value_req parameter
* [#127](https://github.com/onelogin/python3-saml/pull/127) Fix for SLO when XML specifies encoding
* [#126](https://github.com/onelogin/python3-saml/pull/126) Fixed setting NameFormat attribute for AttributeValue tags

### 1.5.0 (Jan 29, 2019)
* Security improvements. Use of tagid to prevent XPath injection. Disable DTD on fromstring defusedxml method
* [#97](https://github.com/onelogin/python3-saml/pull/97) Check that the response has all of the AuthnContexts that we provided
* Adapt renders from Django demo for Django 1.11 version
* Update pylint dependency to 1.9.1
* If debug enable, print reason for the SAMLResponse invalidation
* Fix DSA constant
* [#106](https://github.com/onelogin/python3-saml/pull/106) Support NameID children inside of AttributeValue elements
* Start using flake8 for code quality

### 1.4.1 (Apr 25, 2018)
* Add ID to EntityDescriptor before sign it on add_sign method.
* Update defusedxml, coveralls and coverage dependencies
* Update copyright and license reference

### 1.4.0 (Feb 27, 2018)
* Fix vulnerability [CVE-2017-11427](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-11427). Process text of nodes properly, ignoring comments
* Improve how fingerprint is calcultated
* Fix issue with LogoutRequest rejected by ADFS due NameID with unspecified format instead no format attribute
* Fix signature position in the SP metadata
* [#80](https://github.com/onelogin/python3-saml/pull/80) Preserve xmlns:xs namespace when signing and serializing responses
* Redefine NSMAP constant
* Updated Django demo (Django 1.11).

### 1.3.0 (Sep 15, 2017)
* Improve decrypt method, Add an option to decrypt an element in place or copy it before decryption.
* [#63](https://github.com/onelogin/python3-saml/pull/63) Be able to get at the auth object the last processed ID (response/assertion) and the last generated ID, as well as the NotOnOrAfter value of the valid SubjectConfirmationData in the processed SAMLResponse
* On a LogoutRequest if the NameIdFormat is entity, NameQualifier and SPNameQualifier will be omitted. If the NameIdFormat is not entity and a NameQualifier is provided, then the SPNameQualifier will be also added.
* Reset errorReason attribute of the auth object before each Process method
* [#65](https://github.com/onelogin/python3-saml/pull/65) Fix issue on getting multiple certs when only sign or encryption certs

### 1.2.6 (Jun 15, 2017)
* Use defusedxml that will prevent XEE and other attacks based on the abuse on XMLs. (CVE-2017-9672)

### 1.2.5 (Jun 2, 2017)
* Fix issue related with multicers (multicerts were not used on response validation)
### 1.2.4 (May 18, 2017)
* Publish KeyDescriptor[use=encryption] only when required
* [#57](https://github.com/onelogin/python3-saml/pull/57) Be able to register future SP x509cert on the settings and publish it on SP metadata
* [#57](https://github.com/onelogin/python3-saml/pull/57) Be able to register more than 1 Identity Provider x509cert, linked with an specific use (signing or encryption
* [#57](https://github.com/onelogin/python3-saml/pull/57) Allow metadata to be retrieved from source containing data of multiple entities
* [#57](https://github.com/onelogin/python3-saml/pull/57) Adapt IdP XML metadata parser to take care of multiple IdP certtificates and be able to inject the data obtained on the settings.
* Be able to relax SSL Certificate verification when retrieving idp metadata
* Checking the status of response before assertion count
* Allows underscores in URL hosts
* Add a Pyramid demo
* Be able to provide a NameIDFormat to LogoutRequest
* Add DigestMethod support. Add sign_algorithm and digest_algorithm par
ameters to sign_metadata and add_sign.
* Validate serial number as string to work around libxml2 limitation
* Make the Issuer on the Response Optional
* Fixed bug with formated cert fingerprints

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
