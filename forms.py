from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField,PasswordField,SubmitField,validators
from flask_wtf.file import FileField 
from wtforms.validators import DataRequired,Email,InputRequired


class insertupdate_user(FlaskForm):
    email = StringField('email')
    password = PasswordField('password')  
    status   = IntegerField('status')
    full_name = StringField('full_name')
    foto_profile = StringField('foto_profile')
    submit = SubmitField('submit_register')
    


class LoginForm(FlaskForm):
    email = StringField('email', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])
    submit_login = SubmitField('submit_login')

class RegistrationForm(FlaskForm):
    full_name = StringField('full_name', validators=[DataRequired()])
    email = StringField('email', validators=[DataRequired(), Email()])  # Add Email validator
    password = PasswordField('password', validators=[DataRequired()])
    submit_register = SubmitField('submit_register')


class UploadFileForm(FlaskForm):
    foto_fisio = FileField("foto_fisio", validators=[InputRequired()])
    full_name = StringField('full_name')  # Change 'username' to 'fullname'
    status = StringField('status')  # Change 'username' to 'fullname'




class UpdatePasswordForm(FlaskForm):
    current_password = StringField('current_password')
    new_password = StringField('new_password')
    confirm_password = StringField('confirm_password')
    email = StringField('email') 