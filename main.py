import os
from dotenv import load_dotenv
from flask import Flask, render_template, flash, redirect, url_for, request
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin,login_required, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo
from wtforms import ValidationError

#Load enviroment variables from .env file.
load_dotenv()

#Initzialize Flask application.
app = Flask(__name__)

#Configurations for the Sqlite database.
base_dir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' +os.path.join(base_dir,'data.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']= False
app.config['SECRET_KEY'] = 'lala'
app.config['FLASK_APP'] = os.environ.get('FLASK_APP')
app.config['FLASK_DEBUG'] = os.environ.get('FLASK_DEBUG')

#Initzialize SQLAlchemy  and Flask-Migrate for database operations and migrations.
db = SQLAlchemy(app)
migrate = Migrate(app,db)

#Initzialize Flask-Login for user session managment.
login_manager = LoginManager(app)
login_manager.login_view = 'login' #Specify the login view.
@login_manager.user_loader

#Load user by ID.
def load_user(user_id):
    return User.query.get(int(user_id))


#Defines routes for the application.

@app.route('/')
def index():
    """Render the homepage."""
    return render_template('index.html')

@app.route('/secret')
@login_required
def secret():
    """Render a secret page that requires user login."""
    return render_template('secret.html')

@app.route('/register',methods=['GET','POST'])
def register():
    """Handle user registration.
    Detailed algorithm available at: [Register Function](#Register-Function)"""
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,
                    username=form.username.data,
                    password=form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Registro exitoso.Ahora te puedes logear')
        return redirect(url_for('login'))
    return render_template('register.html',form=form)

@app.route('/login',methods=['GET','POST'])
def login():
    """Handle user login"""
    form = LoginForm()
    #Si los datos ingresados son validos
    if form.validate_on_submit():
        #buscar un usuario que coincida con el email del formulario
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            #Si existe un usuario y el password es correcto.Logear usuario
            login_user(user,form.remember_me.data)
            #guardar en next la ruta guardada en el next de la session
            #next = request.args.get('next')
            #Si no hay guardada ninguna ruta en el next
            #asignar al next la ruta al inicio de la aplicacion.
            #if next is None or not next.startswith('/'):
                #next = url_for('index')
            #continuar a la ruta que iba antes de logearme
            return redirect(url_for('secret'))
        flash('Usuario o password incorrectos')
    
    return render_template('login.html',form=form)

@app.route('/logout')
@login_required
def logout():
    """Log the user out"""
    logout_user()
    flash('Has cerrado sesion')
    return redirect(url_for('index'))

#MODELOS PARA LA BASE DE DATOS

class Role(db.Model):
    '''Role model for user roles.'''
    __tablename__='roles'
    id= db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String(64),unique=True) 
    users = db.relationship('User',backref='role')

class User(UserMixin,db.Model):
    '''User model for storing user information.'''
    #UserMixin permite rastrear el estado de un usuario
    #dentro de la aplicacion.
    #db.Model permite realizar consulas sobre la base de datos.
    __tablename__='users'
    id = db.Column(db.Integer,primary_key=  True)
    email= db.Column(db.String(64),unique=True,index=True)
    username = db.Column(db.String(64),unique=True,index=True)
    password_hash = db.Column(db.String(128))
    role_id = db.Column(db.Integer,db.ForeignKey('roles.id'))
    
    @property
    def password(self):
        raise AttributeError('Password no es atributo de lectura')
    @password.setter
    def password(self,password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self,password):
        return check_password_hash(self.password_hash,password)



##FORMULARIOS

class RegisterForm(FlaskForm):
    """Form user registration."""
    email = StringField('Email',validators=[DataRequired(), Length(1,64), Email()])
    username = StringField('Username', validators=[DataRequired(), Length(1,64),
                           Regexp('^[A-Za-z][A-Za-z0-9_.]*$',0,
                            'Usuario debe tener solo letras, numeros, puntos y guiones.')])
    password = PasswordField('Password', validators=[DataRequired(),EqualTo('password2',
                            message='Los password deben coincidir.')])
    password2 = PasswordField('Confirmar Password',validators=[DataRequired()])
    submit = SubmitField('Registrarse')

    def validate_email(self,field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('El Email ingresado ya existe')
    
    def validate_username(self,field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Usuario ya esta en uso.')

class LoginForm(FlaskForm):
    """Form user login."""
    email = StringField('Email',validators=[DataRequired(),Length(1,64),Email()])
    password = PasswordField('Password',validators=[DataRequired()])
    remember_me = BooleanField('Mantenerme logeado')
    submit = SubmitField('Ingresar')