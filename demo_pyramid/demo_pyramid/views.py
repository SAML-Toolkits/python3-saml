import os

from pyramid.httpexceptions import (HTTPFound, HTTPInternalServerError, HTTPOk,)
from pyramid.view import view_config

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils

SAML_PATH = os.path.join(os.path.dirname(__file__), 'saml')


def init_saml_auth(req):
    auth = OneLogin_Saml2_Auth(req, custom_base_path=SAML_PATH)
    return auth


def prepare_pyramid_request(request):
    # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
    return {
        'https': 'on' if request.scheme == 'https' else 'off',
        'http_host': request.host,
        'server_port': request.server_port,
        'script_name': request.path,
        'get_data': request.GET.copy(),
        # Uncomment if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
        # 'lowercase_urlencoding': True,
        'post_data': request.POST.copy(),
    }


@view_config(route_name='index', renderer='templates/index.jinja2')
def index(request):
    req = prepare_pyramid_request(request)
    auth = init_saml_auth(req)
    errors = []
    error_reason = ""
    not_auth_warn = False
    success_slo = False
    attributes = False
    paint_logout = False

    session = request.session

    if 'sso' in request.GET:
        return HTTPFound(auth.login())
    elif 'sso2' in request.GET:
        return_to = '%s/attrs/' % request.host_url
        return HTTPFound(auth.login(return_to))
    elif 'slo' in request.GET:
        name_id = None
        session_index = None
        if 'samlNameId' in session:
            name_id = session['samlNameId']
        if 'samlSessionIndex' in session:
            session_index = session['samlSessionIndex']

        return HTTPFound(auth.logout(name_id=name_id, session_index=session_index))
    elif 'acs' in request.GET:
        auth.process_response()
        errors = auth.get_errors()
        not_auth_warn = not auth.is_authenticated()
        if len(errors) == 0:
            session['samlUserdata'] = auth.get_attributes()
            session['samlNameId'] = auth.get_nameid()
            session['samlSessionIndex'] = auth.get_session_index()
            self_url = OneLogin_Saml2_Utils.get_self_url(req)
            if 'RelayState' in request.POST and self_url != request.POST['RelayState']:
                return HTTPFound(auth.redirect_to(request.POST['RelayState']))
        else:
            error_reason = auth.get_last_error_reason()
    elif 'sls' in request.GET:
        dscb = lambda: session.clear()
        url = auth.process_slo(delete_session_cb=dscb)
        errors = auth.get_errors()
        if len(errors) == 0:
            if url is not None:
                return HTTPFound(url)
            else:
                success_slo = True

    if 'samlUserdata' in session:
        paint_logout = True
        if len(session['samlUserdata']) > 0:
            attributes = session['samlUserdata'].items()

    return {
        'errors': errors,
        'error_reason': error_reason,
        'not_auth_warn': not_auth_warn,
        'success_slo': success_slo,
        'attributes': attributes,
        'paint_logout': paint_logout,
    }


@view_config(route_name='attrs', renderer='templates/attrs.jinja2')
def attrs(request):
    paint_logout = False
    attributes = False

    session = request.session

    if 'samlUserdata' in session:
        paint_logout = True
        if len(session['samlUserdata']) > 0:
            attributes = session['samlUserdata'].items()

    return {
        'paint_logout': paint_logout,
        'attributes': attributes,
    }


@view_config(route_name='metadata', renderer='html')
def metadata(request):
    req = prepare_pyramid_request(request)
    auth = init_saml_auth(req)
    settings = auth.get_settings()
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)

    if len(errors) == 0:
        resp = HTTPOk(body=metadata, headers={'Content-Type': 'text/xml'})
    else:
        resp = HTTPInternalServerError(body=', '.join(errors))
    return resp
