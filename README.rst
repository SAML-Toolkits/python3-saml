===========
Python SAML
===========

This Python SAML toolkit provides functionality for creating SAML AuthnRequests
which can be sent to an identity provider and for verifying SAML Responses from
an identity provider. OneLogin is an example of an identity provider.

Non-Python Requirements
=======================

- libxml2
- libxslt
- libxmlsec1
- libxml2-dev
- libxslt-dev
- libxmlsec1-dev

This toolkit makes use of the xmlsec binary in order to verify the response
signature. Make sure you add the xmlsec binary to your Windows or Linux PATH.
Unfortunately, the python bindings for libxml2, which xmlsec uses, do not
provide the functionality needed to programmatically verify the signature,
specifically the libxml2.xmlAddID function.
For more information see http://www.aleksey.com/xmlsec/faq.html Section 3.2

Python Requirements
===================

- python-setuptools
- python2.6
- python2.6-dev
- lxml 2.3 or greater

Test Requirements
=================

- fudge 0.9.5 or greater
- nose 0.10.4 or greater

Installing
==========
To install in the default Python library location::

    python setup.py install

To install in a custom Python library location in Linux::

    MY_BASE_DIR=/home/foouser
    export PYTHONPATH=$MY_BASE_DIR/lib/python2.6/site-packages
    python setup.py install --prefix=$MY_BASE_DIR

Testing
=======
To run the unit-tests::

   python setup.py test

Running the example app
=======================
To run with the default configuration file, example.cfg, which needs to be
filled out completely::

    python setup.py example

To run with your own configuration file in Linux::

    python setup.py example --config-file=~/my_config.cfg

Example app breakdown
=====================
The example app subclasses the BaseHTTPRequestHandler in order to process
GET and POST HTTP requests. It is by no means a secure application and should
not be used for anything other than exploring and testing.

Creating and sending the AuthnRequest to the identity provider
--------------------------------------------------------------
The identification flow starts when a user requests a resource from the service
provider which, in this case, is implemented in our example app. In our example
the user requests a resource by going to the root path of our app, i.e,::

    http://localhost:7070/

Our example app receives this request and in turn creates a SAML AuthnRequest
in the form of URL string which we use to redirect the user to our identity
provider--OneLogin::

        from BaseHTTPServer import BaseHTTPRequestHandler
        from onelogin.saml import AuthnRequest
        ...
        class SampleAppHTTPRequestHandler(BaseHTTPRequestHandler):
          ...
          def do_GET(self):
            ...
            url = AuthnRequest.create(**self.settings)
            self.send_response(301)
            self.send_header("Location", url)
            self.end_headers()

The self.settings variable is a dictionary with the following entries. These
entries are originally retrieved from the configuration file passed in as a
command line option to the example app::

    settings = dict(
      assertion_consumer_service_url='http://localhost:7070/example/saml/consume',
      issuer='python-saml',
      name_identifier_format='urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
      idp_sso_target_url='https://app.onelogin.com/saml/signon/<id>',
    )

The idp_sso_target_url is the SAML Login URL from the SAML Test (IdP) app. You
must register with OneLogin and add the SAML Test (IdP) app to your apps in
order to get the idp_sso_target_url. You must also register the
assertion_consumer_service_url with the SAML Test (IdP) app by entering it in
the SAML Consumer URL field.

Receiving and verifying the response
------------------------------------
The user will then be redirected to the OneLogin login page where they will
enter their credentials in order to verify their identity. After OneLogin has
verified their identity it will redirect the user to the
assertion_consumer_service_url--http://localhost:7070/example/saml/consume.

Our example app then verifies the SAML Response from OneLogin using the fingerprint
of the public certificate originally obtained from OneLogin::

          def do_POST(self):
            ...
            length = int(self.headers['Content-Length'])
            data = self.rfile.read(length)
            query = urlparse.parse_qs(data)
            res = Response(
                query['SAMLResponse'].pop(),
                self.settings['idp_cert_fingerprint'],
                )
            valid = res.is_valid()
            name_id = res.name_id
            if valid:
                msg = 'The identity of {name_id} has been verified'.format(
                    name_id=name_id,
                    )
                self._serve_msg(200, msg)
            else:
                msg = '{name_id} is not authorized to use this resource'.format(
                    name_id=name_id,
                    )
                self._serve_msg(401, msg)

Once again, the self.settings variable is populated from an entry in
the configuration file. You can find the public certificate under Security->SAML
after you login to OneLogin.

For full details see **example.py** and **example.cfg**.
