from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from app.models import users, posts
from flask_sqlalchemy import SQLAlchemy

# --------  Registration Form   --------

class RegistrationForm(FlaskForm):

    def napier_email(self, email):

        email = email.data
        domain = email.split("@")

        if "@" in email and "." in email:
            if domain[1] != "live.napier.ac.uk":
                raise ValidationError('Please use a Napier University email address.')
        else:
            raise ValidationError('Please use a valid email address. e.g. example@example.com')

    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])

    email = StringField('Napier Email', validators=[DataRequired(), napier_email])

    password = PasswordField('Password', validators=[DataRequired()])

    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])

    submit = SubmitField('Register')

    def validate_username(self, username):
        user = users.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is already taken. Please choose another.')

    def validate_email(self, email):
        user = users.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is already taken. Please choose another.')

# --------  Login Form  --------

class LoginForm(FlaskForm):

    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])

    password = PasswordField('Password', validators=[DataRequired()])

    remember = BooleanField('Remember Me')

    submit = SubmitField('Sign In')

# --------  Admin Login Form  --------

class AdminLoginForm(FlaskForm):

    username = StringField('Username', validators=[DataRequired()])

    password = PasswordField('Password', validators=[DataRequired()])

    submit = SubmitField('Sign In')

# --------  New Post Form  --------

class PostForm(FlaskForm):

    post_title = StringField('Post Title', validators=[DataRequired()])

    post_content = StringField('Post Content', validators=[DataRequired()])

    submit = SubmitField('Make Post')

# --------  New Reply Form  --------

class ReplyForm(FlaskForm):

    reply_content = StringField('Reply to post', validators=[DataRequired()])

    submit = SubmitField('Post reply')

# --------  Delete Post by ID Form  --------

class DeletePostForm(FlaskForm):

    post_id = StringField('Delete Post by ID', validators=[DataRequired()])

    submit = SubmitField('Delete Post')

# --------  Delete Reply by ID Form  --------

class CreateAdminForm(FlaskForm):

    username = StringField('Username', validators=[DataRequired()])

    password = StringField('Password')

    submit = SubmitField('Create Account')

# --------  Create Admin Account Form  --------

class DeleteReplyForm(FlaskForm):

    reply_id = StringField('Delete Comment by ID', validators=[DataRequired()])

    submit = SubmitField('Delete Comment')


# --------  Filter Post Form  --------

class FilterPostForm(FlaskForm):

    filter = SelectField('Filter Posts By Module', choices=[
    ('Show All', 'Show All'),
    ('Advanced Web Tech', 'Advanced Web Tech'),
    ('Being Digital', 'Being Digital'),
    ('Business Systems Analysis and Design', 'Business Systems Analysis and Design'),
    ('Cyberpsychology', 'Cyberpsychology'),
    ('Database Systems', 'Database Systems'),
    ('Digital Business Environments', 'Digital Business Environments'),
    ('Digital Imaging', 'Digital Imaging'),
    ('Digital Storytelling', 'Digital Storytelling'),
    ('Experiental Design', 'Experiental Design'),
    ('Foundations of Software Design and Development', 'Foundations of Software Design and Development'),
    ('Honours Project', 'Honours Project'),
    ('Information - Society and Security', 'Information - Society and Security'),
    ('Introduction to Human-Computer Interaction (HCI)', 'Introduction to Human-Computer Interaction (HCI)'),
    ('Mobile Applications Development', 'Mobile Applications Development'),
    ('Object Oriented Software Development', 'Object Oriented Software Development'),
    ('Online Marketing', 'Online Marketing'),
    ('Playful Interaction', 'Playful Interaction'),
    ('Practical Interaction Design', 'Practical Interaction Design'),
    ('Programming for Media and Design', 'Programming for Media and Design'),
    ('Starting a new business', 'Starting a new business'),
    ('UBICOM', 'UBICOM'),
    ('User Centred Organizational Systems', 'User Centred Organizational Systems'),
    ('User Experience', 'User Experience'),
    ('Web Technologies', 'Web Technologies')
    ], default="Show All")

    submit = SubmitField('Apply Filter')
