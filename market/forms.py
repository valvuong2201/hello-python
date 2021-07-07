from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, ValidationError
from wtforms.validators import Length, EqualTo, Email, DataRequired
from market.models import User


class RegisterForm(FlaskForm):
    username = StringField(label='User Name:', validators=[Length(min=2, max=30), DataRequired()])
    email_address = StringField(label='Email Address:', validators=[Email(), DataRequired()])
    password1 = PasswordField(label='Password:', validators=[Length(min=6), DataRequired()])
    password2 = PasswordField(label='Confirm Password:', validators=[EqualTo('password1'), DataRequired()])
    submit = SubmitField(label='Create Account')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists! Please try a different username')

    def validate_email_address(self, email):
        user = User.query.filter_by(email_address=email.data).first()
        if user:
            raise ValidationError('Username already exists! Please try a different username')


class LoginForm(FlaskForm):
    username = StringField(label='User Name:', validators=[DataRequired()])
    password = PasswordField(label='Password:', validators=[DataRequired()])
    submit = SubmitField(label='Sign In')