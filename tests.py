import unittest
from flask_testing import TestCase
from main import app
from project import  db
import json
import os
from flask_jwt import JWT, jwt_required, current_identity
from json.decoder import JSONDecoder
class BaseTestCase(TestCase):

    def create_app(self):
        app.config.from_object('config.TestConfig')
        return app

    def setUp(self):
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()

        
class TestUsers(BaseTestCase):

    def test_app_is_testing(self):
        '''test app'''
        self.assertFalse(app.config['SECRET_KEY'] is 'mysecretkey')
        self.assertTrue(app.config['DEBUG'])
        basedir = os.path.abspath(os.path.dirname(__file__))
        self.assertFalse(
            app.config['SQLALCHEMY_DATABASE_URI'] == 'sqlite:///'+os.path.join(basedir,'data.sqlite')
        )
   
    
if __name__ == '__main__':
    unittest.main()
