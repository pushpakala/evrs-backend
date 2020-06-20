import os



class BaseConfig(object):
    DEBUG = False
    SECRET_KEY = 'mysecreatkey'
    basedir = os.path.abspath(os.path.dirname(__file__))


class TestConfig(BaseConfig):
    DEBUG = True
    TESTING = True
    WTF_CSRF_ENABLED = False

                                                       
class DevelopmentConfig(BaseConfig):               
    DEBUG = True


class ProductionConfig(BaseConfig):
    DEBUG = False
