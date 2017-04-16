from pyramid.config import Configurator
from pyramid.session import SignedCookieSessionFactory


session_factory = SignedCookieSessionFactory('onelogindemopytoolkit')


def main(global_config, **settings):
    """ This function returns a Pyramid WSGI application.
    """
    config = Configurator(settings=settings)
    config.set_session_factory(session_factory)
    config.include('pyramid_jinja2')
    config.add_static_view('static', 'static', cache_max_age=3600)
    config.add_route('index', '/')
    config.add_route('attrs', '/attrs/')
    config.add_route('metadata', '/metadata/')
    config.scan()
    return config.make_wsgi_app()
