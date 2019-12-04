from app import db
from flask_login import UserMixin

# Model for users database
class users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(80))

# Model for admin_users database
class admin_users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(80))

# Model for modules database
class modules(db.Model):
    modulename = db.Column(db.String(200), unique=True, primary_key=True)

# Model for posts database
class posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    modulename = db.Column(db.String(200), unique=True)
    title = db.Column(db.String(200))
    content = db.Column(db.String(9999))
    time = db.Column(db.String(100))

# Model for replies database
class replies(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer)
    content = db.Column(db.String(9999))
    time = db.Column(db.String(100))
