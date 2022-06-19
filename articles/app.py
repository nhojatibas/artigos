from flask import Flask, render_template, flash, request
from flask_wtf import FlaskForm
from wtforms import BooleanField, PasswordField, StringField
from wtforms.validators import DataRequired
from flask_login import LoginManager
import logging

logger = logging.getLogger("werkzeug")


class LoginForm(FlaskForm):
    username = StringField("username", validators=[DataRequired()])
    password = PasswordField("password", validators=[DataRequired()])


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "secret"
    app.config["DEBUG"] = True

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

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
            print(username)
            print(password)
            form = LoginForm()
            form.username.data = username
            form.password.data = password
            return render_template("login.html", FORM=form)

    return app
