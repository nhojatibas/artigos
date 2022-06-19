from flask import Flask, render_template, flash, request
from flask_wtf import FlaskForm
from wtforms import BooleanField, PasswordField, StringField
from wtforms.validators import DataRequired
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
import logging

logger = logging.getLogger("werkzeug")
db = SQLAlchemy()


class LoginForm(FlaskForm):
    username = StringField("username", validators=[DataRequired()])
    password = PasswordField("password", validators=[DataRequired()])


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
            
            print(username)
            print(password)
            form = LoginForm()
            form.username.data = username
            form.password.data = password
            return render_template("login.html", FORM=form)

    return app
