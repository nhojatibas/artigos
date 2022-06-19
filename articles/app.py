from flask import Flask, render_template, flash, request, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import BooleanField, PasswordField, StringField
from wtforms.validators import DataRequired
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import logging

logger = logging.getLogger("werkzeug")
db = SQLAlchemy()


# Formularios
class LoginForm(FlaskForm):
    username = StringField("username", validators=[DataRequired()])
    password = PasswordField("password", validators=[DataRequired()])


class SignupForm(FlaskForm):
    username = StringField("username", validators=[DataRequired()])
    email = StringField("email", validators=[DataRequired()])
    password = PasswordField("password", validators=[DataRequired()])


# Databases
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))


def create_app():

    app = Flask(__name__)

    app.config["SECRET_KEY"] = "secret"
    app.config["SQLALCHEMY_DATABASE_URI"] = 'mysql+mysqlconnector://nhoj:123456@localhost/articles'
    app.config["DEBUG"] = True

    db.init_app(app)

    #login_manager = LoginManager()
    #login_manager.login_view = 'auth.login'
    #login_manager.init_app(app)

    @app.route("/")
    def index():
        return "ARTICLES"

    # Rota para LOGIN
    @app.route("/login", methods=['GET', 'POST'])
    def login():
        if request.method == 'GET':
            form = LoginForm()
            return render_template("login.html", FORM=form)
        else:
            username = request.form['username']
            password = request.form['password']

            user = User.query.filter_by(username=username).first()

            if user:
                print("user já existe")

            else:
                print("novo usuário")

            print('username.....: ' + str(username))
            print('password.....: ' + str(password))
            form = LoginForm()
            form.username.data = username
            form.password.data = password
            return redirect(url_for('signup', FORM=form))

    # Rota para SIGNUP
    @app.route("/signup", methods=['GET', 'POST'])
    def signup():
        if request.method == 'GET':
            form = SignupForm()
            return render_template("signup.html", FORM=form)
        else:
            print(request.form)
            username = request.form['username']
            email = request.form['email']
            password = request.form['password']

            user_exists = User.query.filter_by(username=username).first()
            email_exists = User.query.filter_by(email=email).first()

            if user_exists or email_exists:
                print("user já existe")

            else:
                print("novo usuário")
                new_user = User(
                    username=username,
                    email=email,
                    password=generate_password_hash(password, method='md5'))
                #print(dir(db.session))
                db.session.add(new_user)
                db.session.commit()

            print('username.....: ' + str(username))
            print('email........: ' + str(email))
            print('password.....: ' + str(password))
            form = SignupForm()
            form.username.data = username
            form.email.data = email
            form.password.data = password
            return render_template('signup.html', FORM=form)

    return app
