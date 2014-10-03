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
 * M2Crypto  A Python crypto and SSL toolkit
 * dm.xmlsec.binding  Cython/lxml based binding for the XML security library
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

#### certs ####

SAML requires a x.509 cert to sign and encrypt elements like NameID, Message,
Assertion, Metadata.

If our environment requires sign or encrypt support, this folder may contain
the x509 cert and the private key that the SP will use:

 * **sp.crt** The public cert of the SP
 * **sp.key** The privake key of the SP

Or also we can provide those data in the setting file at the $settings['sp']['x509cert']
and the $settings['sp']['privateKey'].

Sometimes we could need a signature on the metadata published by the SP, in
this case we could use the x.509 cert previously mentioned or use a new x.509
cert: **metadata.crt** and **metadata.key**.


#### src ####

This folder contains the heart of the toolkit, **onelogin/saml2** folder contains the new version of
the classes and methods that are described in a later section

#### demo-django ####

TODO: Explain structure and how works

#### demo-flask ####

TODO: Explain structure and how works

#### setup.py ####

Setup script is the centre of all activity in building, distributing, and installing modules.
Read more at https://pythonhosted.org/an_example_pypi_project/setuptools.html

### How it works ###

#### Settings ####

TODO

#### How load the library ####

TODO
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils

#### Initiate SSO ####

TODO

#### The SP Endpoints ####

TODO

#### Initiate SLO ####

TODO

### Main classes and methods ###

TODO


Demos and test
--------------

### Getting Started ###

We said that this toolkit includes a django application demo and a flask applicacion demo,
lets see how fast is deploy them.

** Virtualenv **

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
