from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField, IntegerField, DateField, FloatField, FileField
from wtforms.validators import DataRequired, ValidationError, Email, EqualTo, Length
from app.models import User
# from wtforms.fields.html5 import DateField

class LoginForm(FlaskForm):
	username = StringField('Username', validators=[DataRequired()])
	password = PasswordField('Password', validators=[DataRequired()])
	remember_me = BooleanField('Remember Me')
	submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
	username = StringField('Username', validators=[DataRequired()])
	email = StringField('Email', validators=[DataRequired(), Email()])
	password = PasswordField('Password', validators=[DataRequired()])
	password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
	account_type = StringField('Account Type', validators=[DataRequired()])
	# def validate_username(self, username):
	# 	user = mongo.db.datax
	# 	userx =  user.find_one({'name': name})
	# 	if userx is not None:
	# 		raise ValidationError('Username already taken.')

	# def validate_email(self, email):
	# 	user = User.query.filter_by(email=email.data).first()
	# 	if user is not None:
	# 		raise ValidationError('Email already taken.')


class EditProfileForm(FlaskForm):
	username = StringField('Username', validators=[DataRequired()])
	about_me = TextAreaField('About me', validators=[Length(min=0, max=140)])
	submit = SubmitField('Submit')


	# def __init__(self, original_username, *args, **kwargs):
	#     super(EditProfileForm, self).__init__(*args, **kwargs)
	#     self.original_username = original_username

	# def validate_username(self, username):
	#     if username.data != self.original_username:
	#         user = User.query.filter_by(username=self.username.data).first()
	#         if user is not None:
	#             raise ValidationError('Please use a different username.')

class ODPForm(FlaskForm):
	odp_target = StringField('Nama ODP Target', validators=[DataRequired()])
	# tgl_order = DateField('Tanggal Order', validators=[DataRequired()], format='%d-%m-%Y')
	tgl_survei = DateField('Tanggal Survei', validators=[DataRequired()], format='%Y-%m-%d')
	onsite = StringField(' Onsite', validators=[DataRequired()])
	ondesk = StringField('Ondesk', validators=[DataRequired()])
	alamat = TextAreaField('Alamat ODP')
	longlat = StringField('Longlat', validators=[DataRequired()])
	port_olt = StringField('PORT OLT', validators=[DataRequired()])
	kendala = TextAreaField('Kendala')
	kap = IntegerField('Kap', validators=[DataRequired()])
	label_odp = StringField('Label ODP', validators=[DataRequired()])
	used = IntegerField('Used', validators=[DataRequired()])
	occu = FloatField('Occu', validators=[DataRequired()])
	odc = StringField('ODC', validators=[DataRequired()])
	sto = StringField('STO', validators=[DataRequired()])
	datel = StringField('DATEL', validators=[DataRequired()])
	uim = StringField('UIM', validators=[DataRequired()])
	tanggal_uim = DateField('Tanggal UIM', validators=[DataRequired()], format='%Y-%m-%d')
	eksekutor = StringField('Eksekutor', validators=[DataRequired()])
	aktual_odp = StringField('Nama ODP TKP', validators=[DataRequired()])
	photo = FileField('Foto ODP', validators=[DataRequired()])
	submit = SubmitField('Save')


