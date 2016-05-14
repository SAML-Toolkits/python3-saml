# python3-saml changelog

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