import os
import ConfigParser
import optparse
import logging
import shutil
import urlparse

from StringIO import StringIO
from BaseHTTPServer import BaseHTTPRequestHandler
from BaseHTTPServer import HTTPServer

from onelogin.saml import AuthRequest, Response

__version__ = '0.1'

log = logging.getLogger(__name__)

class SampleAppHTTPRequestHandler(BaseHTTPRequestHandler):
    server_version = 'SampleAppHTTPRequestHandler/%s' % __version__

    def _serve_msg(self, code, msg):
        f = StringIO()
        f.write('<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">')
        f.write("<html>\n<body>\n%s</body>\n</html>\n" % msg)
        length = f.tell()
        f.seek(0)

        if code == 200:
            self.send_response(code)
        else:
            self.send_error(code, message=msg)

        self.send_header('Content-type', 'text/html')
        self.send_header('Content-Length', str(length))
        self.end_headers()

        shutil.copyfileobj(f, self.wfile)

    def _bad_request(self):
        """Serve Bad Request (400)."""
        self._serve_msg(400, 'Bad Request')

    def log_message(self, format, *args):
        log.info(format % args)

    def do_HEAD(self):
        """Serve a HEAD request."""
        self._bad_request()

    def do_DEL(self):
        """Serve a DEL request."""
        self._bad_request()

    def do_GET(self):
        """Serve a GET request."""
        if not self.path == '/':
            self._bad_request()
            return

        url = AuthRequest.create(**self.settings)
        self.send_response(301)
        self.send_header("Location", url)
        self.end_headers()

    def do_POST(self):
        """Serve a POST request."""
        if not self.path == self.saml_post_path:
            self._bad_request()
            return

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
            msg = 'The identify of {name_id} has been verified'.format(
                name_id=name_id,
                )
            self._serve_msg(200, msg)
        else:
            msg = '{name_id} is not authorized to use this resource'.format(
                name_id=name_id,
                )
            self._serve_msg(401, msg)

def main(config_file):
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s.%(msecs)03d example: %(levelname)s: %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S',
        )

    config = ConfigParser.RawConfigParser()
    config_path = os.path.expanduser(config_file)
    config_path = os.path.abspath(config_path)
    with open(config_path) as f:
        config.readfp(f)

    host = config.get('app', 'host')
    port = config.get('app', 'port')
    port = int(port)

    settings = dict()
    settings['assertion_consumer_service_url'] = config.get(
        'saml',
        'assertion_consumer_service_url'
        )
    settings['issuer'] = config.get(
        'saml',
        'issuer'
        )
    settings['name_identifier_format'] = config.get(
        'saml',
        'name_identifier_format'
        )
    settings['idp_sso_target_url'] = config.get(
        'saml',
        'idp_sso_target_url'
        )
    settings['idp_cert_file'] = config.get(
        'saml',
        'idp_cert_file'
        )
    settings['idp_cert_fingerprint'] = config.get(
        'saml',
        'idp_cert_fingerprint'
        )

    cert_file = settings.pop('idp_cert_file', None)

    # idp_cert_file has priority over idp_cert_fingerprint
    if cert_file:
        cert_path = os.path.expanduser(cert_file)
        cert_path = os.path.abspath(cert_path)

        with open(cert_path) as f:
            settings['idp_cert_fingerprint'] = f.read()

    parts = urlparse.urlparse(settings['assertion_consumer_service_url'])
    SampleAppHTTPRequestHandler.protocol_version = 'HTTP/1.0'
    SampleAppHTTPRequestHandler.settings = settings
    SampleAppHTTPRequestHandler.saml_post_path = parts.path
    httpd = HTTPServer(
        (host, port),
        SampleAppHTTPRequestHandler,
        )

    socket_name = httpd.socket.getsockname()

    log.info(
        'Serving HTTP on {host} port {port} ...'.format(
            host=socket_name[0],
            port=socket_name[1],
            )
        )

    httpd.serve_forever()

if __name__ == '__main__':
    parser = optparse.OptionParser(
        usage='%prog [OPTS]',
        )
    parser.add_option(
        '--config-file',
        metavar='PATH',
        help='The configuration file containing the app and SAML settings',
        )

    parser.set_defaults(
        config_file='example.cfg'
        )

    options, args = parser.parse_args()
    if args:
        parser.error('Wrong number of arguments')

    main(options.config_file)
