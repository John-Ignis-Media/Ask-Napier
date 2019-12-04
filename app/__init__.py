# Importing of modules and packages
from flask import Flask
import flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

app = flask.Flask(__name__)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

app.secret_key = '38Ig114RmU'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

from app import routes
