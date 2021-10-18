import tornado.ioloop
import tornado.web
import Settings
import tornado.httpserver
import tornado.httputil

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils

# Global session info
session = {}


class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", IndexHandler),
            (r"/attrs", AttrsHandler),
            (r"/metadata", MetadataHandler),
        ]
        settings = {
            "template_path": Settings.TEMPLATE_PATH,
            "saml_path": Settings.SAML_PATH,
            "autoreload": True,
            "debug": True
        }
        tornado.web.Application.__init__(self, handlers, **settings)


class IndexHandler(tornado.web.RequestHandler):
    def post(self):
        req = prepare_tornado_request(self.request)
        auth = init_saml_auth(req)
        error_reason = None
        attributes = False
        paint_logout = False
        success_slo = False

        auth.process_response()
        errors = auth.get_errors()
        not_auth_warn = not auth.is_authenticated()

        if len(errors) == 0:
            session['samlUserdata'] = auth.get_attributes()
            session['samlNameId'] = auth.get_nameid()
            session['samlSessionIndex'] = auth.get_session_index()
            self_url = OneLogin_Saml2_Utils.get_self_url(req)
            if 'RelayState' in self.request.arguments and self_url != self.request.arguments['RelayState'][0].decode('utf-8'):
                # To avoid 'Open Redirect' attacks, before execute the redirection confirm
                # the value of the self.request.arguments['RelayState'][0] is a trusted URL.
                return self.redirect(self.request.arguments['RelayState'][0].decode('utf-8'))
        elif auth.get_settings().is_debug_active():
            error_reason = auth.get_last_error_reason()

        if 'samlUserdata' in session:
            paint_logout = True
            if len(session['samlUserdata']) > 0:
                attributes = session['samlUserdata'].items()

        self.render('index.html', errors=errors, error_reason=error_reason, not_auth_warn=not_auth_warn, success_slo=success_slo, attributes=attributes, paint_logout=paint_logout)

    def get(self):
        req = prepare_tornado_request(self.request)
        auth = init_saml_auth(req)
        error_reason = None
        errors = []
        not_auth_warn = False
        success_slo = False
        attributes = False
        paint_logout = False

        if 'sso' in req['get_data']:
            print('-sso-')
            return self.redirect(auth.login())
        elif 'sso2' in req['get_data']:
            print('-sso2-')
            return_to = '%s/attrs' % self.request.host
            return self.redirect(auth.login(return_to))
        elif 'slo' in req['get_data']:
            print('-slo-')
            name_id = None
            session_index = None
            if 'samlNameId' in session:
                name_id = session['samlNameId']
            if 'samlSessionIndex' in session:
                session_index = session['samlSessionIndex']
            return self.redirect(auth.logout(name_id=name_id, session_index=session_index))
        elif 'acs' in req['get_data']:
            print('-acs-')
            auth.process_response()
            errors = auth.get_errors()
            not_auth_warn = not auth.is_authenticated()
            if len(errors) == 0:
                session['samlUserdata'] = auth.get_attributes()
                session['samlNameId'] = auth.get_nameid()
                session['samlSessionIndex'] = auth.get_session_index()
                self_url = OneLogin_Saml2_Utils.get_self_url(req)
                if 'RelayState' in self.request.arguments and self_url != self.request.arguments['RelayState'][0].decode('utf-8'):
                    return self.redirect(auth.redirect_to(self.request.arguments['RelayState'][0].decode('utf-8')))
                elif auth.get_settings().is_debug_active():
                    error_reason = auth.get_last_error_reason()
        elif 'sls' in req['get_data']:
            print('-sls-')
            dscb = lambda: session.clear()  # clear out the session
            url = auth.process_slo(delete_session_cb=dscb)
            errors = auth.get_errors()
            if len(errors) == 0:
                if url is not None:
                    # To avoid 'Open Redirect' attacks, before execute the redirection confirm
                    # the value of the url is a trusted URL.
                    return self.redirect(url)
                else:
                    success_slo = True
            elif auth.get_settings().is_debug_active():
                error_reason = auth.get_last_error_reason()
        if 'samlUserdata' in session:
            print('-samlUserdata-')
            paint_logout = True
            if len(session['samlUserdata']) > 0:
                attributes = session['samlUserdata'].items()
                print("ATTRIBUTES", attributes)
        self.render('index.html', errors=errors, error_reason=error_reason, not_auth_warn=not_auth_warn, success_slo=success_slo, attributes=attributes, paint_logout=paint_logout)


class AttrsHandler(tornado.web.RequestHandler):
    def get(self):
        paint_logout = False
        attributes = False

        if 'samlUserdata' in session:
            paint_logout = True
            if len(session['samlUserdata']) > 0:
                attributes = session['samlUserdata'].items()

        self.render('attrs.html', paint_logout=paint_logout, attributes=attributes)


class MetadataHandler(tornado.web.RequestHandler):
    def get(self):
        req = prepare_tornado_request(self.request)
        auth = init_saml_auth(req)
        saml_settings = auth.get_settings()
        metadata = saml_settings.get_sp_metadata()
        errors = saml_settings.validate_metadata(metadata)

        if len(errors) == 0:
            # resp = HttpResponse(content=metadata, content_type='text/xml')
            self.set_header('Content-Type', 'text/xml')
            self.write(metadata)
        else:
            # resp = HttpResponseServerError(content=', '.join(errors))
            self.write(', '.join(errors))
        # return resp


def prepare_tornado_request(request):

    dataDict = {}
    for key in request.arguments:
        dataDict[key] = request.arguments[key][0].decode('utf-8')

    result = {
        'https': 'on' if request == 'https' else 'off',
        'http_host': request.host,
        'script_name': request.path,
        'get_data': dataDict,
        'post_data': dataDict,
        'query_string': request.query
    }
    return result


def init_saml_auth(req):
    auth = OneLogin_Saml2_Auth(req, custom_base_path=Settings.SAML_PATH)
    return auth


if __name__ == "__main__":
    app = Application()
    http_server = tornado.httpserver.HTTPServer(app)
    http_server.listen(8000)
    tornado.ioloop.IOLoop.instance().start()
