from os import environ, path
from dotenv import load_dotenv
from datetime import timedelta

basedir = path.abspath(path.dirname(__file__))
load_dotenv(path.join(basedir, '.env'))

DEBUG = True


FLASK_ENV = 'development'
MAIL_SERVER ='smtp.gmail.com'
MAIL_PORT = 465
MAIL_USERNAME = environ.get('MAIL_USERNAME')
MAIL_PASSWORD = environ.get('MAIL_PASSWORD')
MAIL_USE_TLS = False
MAIL_USE_SSL = True
SQLALCHEMY_DATABASE_URI = 'sqlite:///Database.db'
SQLALCHEMY_TRACK_MODIFICATIONS = True
SECRET_KEY = environ.get('SECRET_KEY')
JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=1)
JWT_REFRESH_TOKEN_EXPIRES = timedelta(hours=1)