# OneLogin's SAML Python Toolkit

[![Build Status](https://api.travis-ci.org/onelogin/python-saml.png?branch=master)](http://travis-ci.org/onelogin/python-saml)
[![Coverage Status](https://coveralls.io/repos/onelogin/python-saml/badge.png)](https://coveralls.io/r/onelogin/python-saml)

Add SAML support to your Python softwares using this library.
Forget those complicated libraries and use that open source library provided
and supported by OneLogin Inc.


Why add SAML support to my software?
------------------------------------

SAML is an XML-based standard for web browser single sign-on and is defined by
the OASIS Security Services Technical Committee. The standard has been around 
since 2002, but lately it is becoming popular due its advantages:

 * **Usability** - One-click access from portals or intranets, deep linking, 
   password elimination and automatically renewing sessions make life
   easier for the user.
 * **Security** - Based on strong digital signatures for authentication and
   integrity, SAML is a secure single sign-on protocol that the largest
   and most security conscious enterprises in the world rely on.
 * **Speed** - SAML is fast. One browser redirect is all it takes to securely
   sign a user into an application.
 * **Phishing Prevention** - If you don’t have a password for an app, you
   can’t be tricked into entering it on a fake login page.
 * **IT Friendly** - SAML simplifies life for IT because it centralizes
   authentication, provides greater visibility and makes directory
   integration easier.
 * **Opportunity** - B2B cloud vendor should support SAML to facilitate the 
   integration of their product.

General description
-------------------

OneLogin's SAML Python toolkit let you build a SP (Service Provider) over
your Python application and connect it to any IdP (Identity Provider).

Supports:

 * SSO and SLO (SP-Initiated and IdP-Initiated).
 * Assertion and nameId encryption.
 * Assertion signature.
 * Message signature: AuthNRequest, LogoutRequest, LogoutResponses.
 * Enable an Assertion Consumer Service endpoint.
 * Enable a Single Logout Service endpoint.
 * Publish the SP metadata (which can be signed).

Key features:

 * **saml2int** - Implements the SAML 2.0 Web Browser SSO Profile.
 * **Session-less** - Forget those common conflicts between the SP and
   the final app, the toolkit delegate session in the final app.
 * **Easy to use** - Programmer will be allowed to code high-level and 
   low-level programming, 2 easy to use APIs are available.
 * **Tested** - Thoroughly tested.
 * **Popular** - OneLogin's customers use it. Add easy support to your django/flask web projects.


Installation
------------

### Dependences ###

 * python 2.7
 * M2Crypto  A Python crypto and SSL toolkit (depends on swig)
 * dm.xmlsec.binding  Cython/lxml based binding for the XML security library (depends on libxmlsec1-dev)
 * isodate  An ISO 8601 date/time/duration parser and formater
 * defusedxml  XML bomb protection for Python stdlib modules

Review the setup.py file to know the version of the library that python-saml is using

### Code ###

#### Option 1. Download from github ####

The toolkit is hosted on github. You can download it from:

 * Lastest release: https://github.com/onelogin/python-saml/releases/latest
 * Master repo: https://github.com/onelogin/python-saml/tree/master

Copy the core of the library (src/onelogin/saml2 folder) and merge the setup.py inside the python application. (each application has its structure so take your time to locate the Python SAML toolkit in the best place). 

#### Option 2. Download from pypi ####

The toolkit is hosted in pypi, you can find the python-sam package at https://pypi.python.org/pypi/python-saml

You can install it executing:
```
 pip install python-saml
```

If you want to know how a project can handle python packages review this [guide](https://packaging.python.org/en/latest/tutorial.html) and review this [sampleproject](https://github.com/pypa/sampleproject)


Getting started
---------------

### Knowing the toolkit ###

The new OneLogin SAML Toolkit contains different folders (certs, lib, demo-django, demo-flask and tests) and some files.

Let's start describing them:

#### src ####

This folder contains the heart of the toolkit, **onelogin/saml2** folder contains the new version of
the classes and methods that are described in a later section.

#### demo-django ####

This folder contains a Django project that will be used as demo to show how to add SAML support to the Django Framework. 'demo' is the main folder of the django project (with its settings.py, views.py, urls.py), 'templates' is the django templates of the project and 'saml' is a folder that contains the 'certs' folder with the x509 public and private key, and the saml toolkit settings (settings.json and advanced_settings.json).

***Notice about certs***

SAML requires a x.509 cert to sign and encrypt elements like NameID, Message, Assertion, Metadata.

If our environment requires sign or encrypt support, the certs folder may contain the x509 cert and the private key that the SP will use:

* sp.crt The public cert of the SP
* sp.key The privake key of the SP

Or also we can provide those data in the setting file at the 'x509cert' and the privateKey' json parameters of the 'sp' element.

Sometimes we could need a signature on the metadata published by the SP, in this case we could use the x.509 cert previously mentioned or use a new x.509 cert: metadata.crt and metadata.key.

#### demo-flask ####

This folder contains a Flask project that will be used as demo to show how to add SAML support to the Flask Framework. 'index.py' is the main flask file that has all the code, this file uses the templates stored at the 'templates' folder. In the 'saml' folder we found the 'certs' folder to store the x509 public and private key, and the saml toolkit settings (settings.json and advanced_settings.json).

#### setup.py ####

Setup script is the centre of all activity in building, distributing, and installing modules.
Read more at https://pythonhosted.org/an_example_pypi_project/setuptools.html

#### tests ####

Contains the unit test of the toolkit.

In order to execute the test you only need to load the virtualenv with the toolkit installed on it and execute:
```
python setup.py test
```
The previous line will run the tests for the whole toolkit. You can also run the tests for a specific module. To do so for the auth module you would have to execute this:
```
python setup.py test --test-suite tests.src.OneLogin.saml2_tests.auth_test.OneLogin_Saml2_Auth_Test
```

With the --test-suite parameter you can specify the module to test. You'll find all the module available and their class names at tests/src/OneLogin/saml2_tests/

### How it works ###

#### Settings ####

First of all we need to configure the toolkit. The SP's info, the IdP's info, and in some cases, configure advanced security issues like signatures and encryption.

There are two ways to provide the settings information:

* Use a settings.json file that we should locate in any folder, but indicates its path with the 'custom_base_path' parameter.

* Use a json object with the setting data and provide it directly to the constructor of the class (if your toolkit integation requires certs, remember to provide the 'custom_base_path' as part of the settings or as a parameter in the constructor.

In the demo-django and in the demo-flask folders you will find a 'saml' folder, inside there is a 'certs' folder and a settings.json and a advanced_settings.json files. Those files contain the settings for the saml toolkit. Copy them in your project and set the correct values.

This is the settings.json file:

```javascript
{
    // If strict is True, then the PHP Toolkit will reject unsigned 
    // or unencrypted messages if it expects them to be signed or encrypted.
    // Also it will reject the messages if the SAML standard is not strictly
    // followed. Destination, NameId, Conditions ... are validated too.
    "strict": true,

    // Enable debug mode (outputs errors).
    "debug": true,

    // Service Provider Data that we are deploying.
    "sp": {
        // Identifier of the SP entity  (must be a URI)
        "entityId": "https://<sp_domain>/metadata/",
        // Specifies info about where and how the <AuthnResponse> message MUST be
        // returned to the requester, in this case our SP.
        "assertionConsumerService": {
            // URL Location where the <Response> from the IdP will be returned
            "url": "https://<sp_domain>/?acs",
            // SAML protocol binding to be used when returning the <Response>
            // message. OneLogin Toolkit supports this endpoint for the 
            // HTTP-POST binding only.
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        },
        // Specifies info about where and how the <Logout Response> message MUST be
        // returned to the requester, in this case our SP. 
        "singleLogoutService": {
            // URL Location where the <Response> from the IdP will be returned
            "url": "https://<sp_domain>/?sls",
            // SAML protocol binding to be used when returning the <Response>
            // message. OneLogin Toolkit supports the HTTP-Redirect binding
            // only for this endpoint.
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        // Specifies the constraints on the name identifier to be used to
        // represent the requested subject.
        // Take a look on lib/Saml2/Constants.php to see the NameIdFormat supported.
        "NameIDFormat": "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified",
        // Usually x509cert and privateKey of the SP are provided by files placed at
        // the certs folder. But we can also provide them with the following parameters
        'x509cert' => '',
        'privateKey' > ''
    },

    // Identity Provider Data that we want connected with our SP.
    "idp": {
        // Identifier of the IdP entity  (must be a URI)
        "entityId": "https://app.onelogin.com/saml/metadata/<onelogin_connector_id>",
        // SSO endpoint info of the IdP. (Authentication Request protocol)
        "singleSignOnService": {
            // URL Target of the IdP where the Authentication Request Message 
            // will be sent.
            "url": "https://app.onelogin.com/trust/saml2/http-post/sso/<onelogin_connector_id>",
            // SAML protocol binding to be used when returning the <Response>
            // message. OneLogin Toolkit supports the HTTP-Redirect binding
            // only for this endpoint.
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        // SLO endpoint info of the IdP.
        "singleLogoutService": {
            // URL Location of the IdP where SLO Request will be sent.
            "url": "https://app.onelogin.com/trust/saml2/http-redirect/slo/<onelogin_connector_id>",
            // SAML protocol binding to be used when returning the <Response>
            // message. OneLogin Toolkit supports the HTTP-Redirect binding
            // only for this endpoint.
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        // Public x509 certificate of the IdP
        "x509cert": "<onelogin_connector_cert>"
        /* 
         *  Instead of use the whole x509cert you can use a fingerprint
         *  (openssl x509 -noout -fingerprint -in "idp.crt" to generate it)
         */
        // "certFingerprint": ""

    }
}
```

In addition to the required settings data (idp, sp), there is extra information that could be defined at advanced_settings.json

```javascript
{
    // Security settings
    "security": {

        /** signatures and encryptions offered **/

        // Indicates that the nameID of the <samlp:logoutRequest> sent by this SP
        // will be encrypted.
        "nameIdEncrypted": false,

        // Indicates whether the <samlp:AuthnRequest> messages sent by this SP 
        // will be signed.  [Metadata of the SP will offer this info]
        "authnRequestsSigned": false,

        // Indicates whether the <samlp:logoutRequest> messages sent by this SP 
        // will be signed.
        "logoutRequestSigned": false,

        // Indicates whether the <samlp:logoutResponse> messages sent by this SP 
        // will be signed.
        "logoutResponseSigned": false,

        /* Sign the Metadata
         false || true (use sp certs) || {
                                            "keyFileName": "metadata.key",
                                            "certFileName": "metadata.crt"
                                         }
        */
        "signMetadata": false,

        /** signatures and encryptions required **/

        // Indicates a requirement for the <samlp:Response>, <samlp:LogoutRequest>
        // and <samlp:LogoutResponse> elements received by this SP to be signed.
        "wantMessagesSigned": false,

        // Indicates a requirement for the <saml:Assertion> elements received by
        // this SP to be signed. [Metadata of the SP will offer this info]
        "wantAssertionsSigned": false,

        // Indicates a requirement for the NameID received by
        // this SP to be encrypted.
        "wantNameIdEncrypted": false
    },

    // Contact information template, it is recommended to suply a
    // technical and support contacts.
    "contactPerson": {
        "technical": {
            "givenName": "technical_name",
            "emailAddress": "technical@example.com"
        },
        "support": {
            "givenName": "support_name",
            "emailAddress": "support@example.com"
        }
    },

    // Organization information template, the info in en_US lang is
    // recomended, add more if required.
    "organization": {
        "en-US": {
            "name": "sp_test",
            "displayname": "SP test",
            "url": "http://sp.example.com"
        }
    }
}
```

In the security section, you can set the way that the SP will handle the messages and assertions. Contact the admin of the IdP and ask him what the IdP expects, and decide what validations will handle the SP and what requirements the SP will have and communicate them to the IdP's admin too.

Once we know what kind of data could be configured, let's talk about the way settings are handled within the toolkit.

The settings files described (settings.json and advanced_settings.json) are loaded by the toolkit if not other dict with settings info is provided in the constructors of the toolkit. Let's see some examples.

```python
# Initializes toolkit with settings.json & advanced_settings.json files.
auth = OneLogin_Saml2_Auth(req)
# or
settings = OneLogin_Saml2_Settings()

# Initializes toolkit with settings.json & advanced_settings.json files from a custom base path.
custom_folder = '/var/www/django-project'
auth = OneLogin_Saml2_Auth(req, custom_base_path=custom_folder)
# or
settings = OneLogin_Saml2_Settings(custom_base_path=custom_folder)

# Initializes toolkit with the dict provided.
auth = OneLogin_Saml2_Auth(req, settings_data)
# or
settings = OneLogin_Saml2_Settings(settings_data)
```

You can declare the settings_data in the file that constains the constructor execution or locate them in any file and load the file in order to get the dict available as we see in the following example:

```python
filename = "/var/www/django-project/custom_settings.json" # The custom_settings.json contains a
json_data_file = open(filename, 'r')                      # settings_data dict.
settings_data = json.load(json_data_file)
json_data_file.close()

auth = OneLogin_Saml2_Auth(req, settings_data)
```

#### How load the library ####

In order to use the toolkit library you need to import the file that contains the class that you will need
on the top of your python file.

``` python
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils
```

#### The Request ####

Building an OneLogin_Saml2_Auth object requires a 'request' parameter.

```python
auth = OneLogin_Saml2_Auth(req)
```

This parameter has the following scheme:

```javascript
req = {
    "http_host": "",
    "script_name": "",
    "server_port": "",
    "get_data": "",
    "post_data": ""
}
```

Each python framework built its own request object, you may map its data to match what the saml toolkit expects.
Let`s see some examples:

```python
def prepare_from_django_request(request):
    return {
        'http_host': request.META['HTTP_HOST'],
        'script_name': request.META['PATH_INFO'],
        'server_port': request.META['SERVER_PORT'],
        'get_data': request.GET.copy(),
        'post_data': request.POST.copy()
    }

def prepare_from_flask_request(request):
    url_data = urlparse(request.url)
    return {
        'http_host': request.host,
        'server_port': url_data.port,
        'script_name': request.path,
        'get_data': request.args.copy(),
        'post_data': request.form.copy()
    }
```


#### Initiate SSO ####

In order to send an AuthNRequest to the IdP:

```python
from onelogin.saml2.auth import OneLogin_Saml2_Auth

req = prepare_request_for_toolkit(request)
auth = OneLogin_Saml2_Auth(req)   # Constructor of the SP, loads settings.json
                                  # and advanced_settings.json

auth.login()      # Method that builds and sends the AuthNRequest
```

The AuthNRequest will be sent signed or unsigned based on the security info of the advanced_settings.json ('authnRequestsSigned').

The IdP will return the SAML Response to the Attribute Consumer Service of the SP.

We can set a 'return_to' url parameter to the login function and that will be converted as a 'RelayState' parameter:

```python
target_url = 'https://example.com'
auth.login(return_to=target_url)
```

#### The SP Endpoints ####

Related to the SP there are 3 important endpoints: The metadata view, the ACS view and the SLS view. 
The toolkit provides examples of those views in the demos, but lets see an example.

***SP Metadata***

This code will provide the XML metadata file of our SP, based on the info that we provided in the settings files.

```python
req = prepare_request_for_toolkit(request)
auth = OneLogin_Saml2_Auth(req)
saml_settings = auth.get_settings()
metadata = saml_settings.get_sp_metadata()
errors = saml_settings.validate_metadata(metadata)
if len(errors) == 0:
    print metadata
else:
    print "Error found on Metadata: %s" % (', '.join(errors))
```

The get_sp_metadata will return the metadata signed or not based on the security info of the advanced_settings.json ('signMetadata').

Before the XML metadata is exposed, a check takes place to ensure that the info to be provided is valid.

***Attribute Consumer Service(ACS)***

This code handles the SAML response that the IdP returns to the SP.

```python
req = prepare_request_for_toolkit(request)
auth = OneLogin_Saml2_Auth(req)
auth.process_response()
errors = auth.get_errors()
if not errors:
    if not auth.is_authenticated():
        request.session['samlUserdata'] = auth.get_attributes()
        if 'RelayState' in req['post_data'] and 
          OneLogin_Saml2_Utils.get_self_url(req) != req['post_data']['RelayState']:
            auth.redirect_to(req['post_data']['RelayState'])
        else:
            for attr_name in request.session['samlUserdata'].keys():
                print '%s ==> %s' % (attr_name, '|| '.join(request.session['samlUserdata'][attr_name]))
    else:
      print 'Not authenticated'
else:
    print "Error when processing SAML Response: %s" % (', '.join(errors))
```

The SAML response is processed and then checked that there are no errors. It also verifies that the user is authenticated and stored the userdata in session.

At that point there are 2 possible alternatives:

* If no RelayState is provided, we could show the user data in this view or however we wanted.
* If RelayState is provided, a rediretion take place.

Notice that we saved the user data in the session before the redirection to have the user data available at the RelayState view.

In order to retrieve attributes we use:

```python
attributes = auth.get_attributes();
```

With this method we get a dict with all the user data provided by the IdP in the Assertion of the SAML Response.

If we execute print attributes we could get:

```python
{
    "cn": ["Jhon"],
    "sn": ["Doe"],
    "mail": ["Doe"],
    "groups": ["users", "members"]
}
``` 

Each attribute name can be used as a key to obtain the value. Every attribute is a list of values. A single-valued attribute is a listy of a single element.

The following code is equivalent:

```python
attributes = auth.get_attributes();
print attributes['cn']

print auth.get_attribute('cn')
```

Before trying to get an attribute, check that the user is authenticated. If the user isn't authenticated, an empty dict will be returned. For example, if we call to get_attributes before a auth.process_response, the get_attributes() will return an empty dict.


***Single Logout Service (SLS)***

This code handles the Logout Request and the Logout Responses.

```python
delete_session_callback = lambda: request.session.flush()
url = auth.process_slo(delete_session_cb=delete_session_callback)
errors = auth.get_errors()
if len(errors) == 0:
    if url is not None:
        return redirect(url)
    else:
        print "Sucessfully Logged out"
else:
    print "Error when processing SLO: %s" % (', '.join(errors))
```

If the SLS endpoints receives a Logout Response, the response is validated and the session could be closed, using the callback.

```python
# Part of the process_slo method
logout_response = OneLogin_Saml2_Logout_Response(self.__settings, self.__request_data['get_data']['SAMLResponse'])
if not logout_response.is_valid(self.__request_data, request_id):
    self.__errors.append('invalid_logout_response')
elif logout_response.get_status() != OneLogin_Saml2_Constants.STATUS_SUCCESS:
    self.__errors.append('logout_not_success')
elif not keep_local_session:
    OneLogin_Saml2_Utils.delete_local_session(delete_session_cb)  
```

If the SLS endpoints receives an Logout Request, the request is validated, the session is closed and a Logout Response is sent to the SLS endpoint of the idP.

```python
# Part of the process_slo method
request = OneLogin_Saml2_Utils.decode_base64_and_inflate(self.__request_data['get_data']['SAMLRequest'])
if not OneLogin_Saml2_Logout_Request.is_valid(self.__settings, request, self.__request_data):
    self.__errors.append('invalid_logout_request')
else:
    if not keep_local_session:
        OneLogin_Saml2_Utils.delete_local_session(delete_session_cb)

    in_response_to = OneLogin_Saml2_Logout_Request.get_id(request)
    response_builder = OneLogin_Saml2_Logout_Response(self.__settings)
    response_builder.build(in_response_to)
    logout_response = response_builder.get_response()

    parameters = {'SAMLResponse': logout_response}
    if 'RelayState' in self.__request_data['get_data']:
        parameters['RelayState'] = self.__request_data['get_data']['RelayState']

    security = self.__settings.get_security_data()
    if 'logoutResponseSigned' in security and security['logoutResponseSigned']:
        parameters['SigAlg'] = OneLogin_Saml2_Constants.RSA_SHA1
        parameters['Signature'] = self.build_response_signature(logout_response, parameters.get('RelayState', None))

    return self.redirect_to(self.get_slo_url(), parameters)
```

If we don't want that process_slo to destroy the session, pass a true parameter to the process_slo method

```python
keepLocalSession = true
auth.process_slo(keep_local_session=keepLocalSession);
```

#### Initiate SLO ####

In order to send a Logout Request to the IdP:

The Logout Request will be sent signed or unsigned based on the security info of the advanced_settings.json ('logoutRequestSigned').

The IdP will return the Logout Response to the Single Logout Service of the SP. 

We can set a 'return_to' url parameter to the logout function and that will be converted as a 'RelayState' parameter:

```python
target_url = 'https://example.com'
auth.logout(return_to=target_url)
```

####Example of a view that initiates the SSO request and handles the response (is the acs target)####

We can code a unique file that initiates the SSO process, handle the response, get the attributes, initiate the slo and processes the logout response.

Note: Review the demos, in a later section we explain the demo use case further in detail.

```python
req = prepare_request_for_toolkit(request)
auth = OneLogin_Saml2_Auth(req)

if 'sso' in request.args:
    return redirect(auth.login())
elif 'sso2' in request.args:
    return_to = '%sattrs/' % request.host_url
    return redirect(auth.login(return_to))
elif 'slo' in request.args:
    return redirect(auth.logout())
elif 'acs' in request.args:
    auth.process_response()
    errors = auth.get_errors()
    if len(errors) == 0:
        if not auth.is_authenticated():
            msg = "Not authenticated"
        else:
            session['samlUserdata'] = auth.get_attributes()
            self_url = OneLogin_Saml2_Utils.get_self_url(req)
            if 'RelayState' in request.form and self_url != request.form['RelayState']:
                return redirect(auth.redirect_to(request.form['RelayState']))
            else:
                msg = ''
                for attr_name in request.session['samlUserdata'].keys():
                    msg += '%s ==> %s' % (attr_name, '|| '.join(request.session['samlUserdata'][attr_name]))
elif 'sls' in request.args:
    delete_session_callback = lambda: session.clear()
    url = auth.process_slo(delete_session_cb=delete_session_callback)
    errors = auth.get_errors()
    if len(errors) == 0:
        if url is not None:
            return redirect(url)
        else:
            msg = "Sucessfully logged out"

if len(errors) == 0:
  print msg
else:
  print ', '.join(errors)
```


### Main classes and methods ###

Described below are the main classes and methods that can be invoked from the SAML2 library.

TODO


Demos and test
--------------

### Getting Started ###

We said that this toolkit includes a django application demo and a flask applicacion demo,
lets see how fast is deploy them.

***Virtualenv***

The use of a [virtualenv](http://virtualenv.readthedocs.org/en/latest/) is
highly recommended.

Virtualenv helps isolating the python enviroment used to run the toolkit. You
can find more details and an installation guide in the
[official documentation](http://virtualenv.readthedocs.org/en/latest/).

Once you have your virtualenv ready and loaded, then you can install the
toolkit on it in development mode executing this:
```
 python setup.py develop
```

Using this method of deployment the toolkit files will be linked instead of
copied, so if you make changes on them you won't need to reinstall the toolkit.

If you want install it in a nomal mode, execute:
```
 python setup.py install
```

#### Demo Flask ####

You'll need a virtualenv with the toolkit installed on it.

To run the demo you need to install the requirements first. Load your
virtualenv and execute:

```
 pip install -r demo-flask/requirements.txt
```

This will install flask and its dependences. Once it has finished, you have to complete the configuration
of the toolkit. You'll find it at `demo-flask/settings.json`

Now, with the virtualenv loaded, you can run the demo like this:
```
 cd demo-flask
 python index.py
```

You'll have the demo running at http://localhost:8000

#### Demo Django ####

You'll need a virtualenv with the toolkit installed on it.

To run the demo you need to install the requirements first. Load your
virtualenv  and execute:
```
 pip install -r demo-django/requirements.txt
``` 
This will install django and its dependences. Once it has finished, you have to complete
the configuration of the toolkit. You'll find it at `demo-django/settings.json`

Now, with the virtualenv loaded, you can run the demo like this:
```
 cd demo-django
 python manage.py runserver 0.0.0.0:8000
```

You'll have the demo running at http://localhost:8000

#### Tests Suite ####

To run the test you only need to load the virtualenv with the toolkit installed
on it and execute:
```
 python setup.py test
```

The previous line will run the tests for the whole toolkit. You can also run
the tests for a specific module. To do so for the `auth` module you would
have to execute this:
```
 python setup.py test --test-suite tests.src.OneLogin.saml2_tests.auth_test.OneLogin_Saml2_Auth_Test
```

With the `--test-suite` parameter you can specify the module to test. You'll
find all the module available and their class names at
`tests/src/OneLogin/saml2_tests/`


### How it works ###

#### Demo Django ####

TODO

#### Demo Django ####

TODO
