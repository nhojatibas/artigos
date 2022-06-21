from flask import Flask, render_template, flash, request, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import BooleanField, PasswordField, StringField
from wtforms.validators import DataRequired
from flask_login import LoginManager, UserMixin, login_user, logout_user
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
class User(UserMixin, db.Model):
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

    login_manager = LoginManager()
    login_manager.login_view = 'login'
    login_manager.init_app(app)
    print("ĺogin_manager_______")

    @login_manager.user_loader
    def load_user(user_id):
        print(user_id)
        return User.query.get(int(user_id))

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/login", methods=['GET'])
    def login_get():
        form = LoginForm()
        return render_template("login.html", FORM=form)

    @app.route("/login", methods=['POST'])
    def login_post():
        loginform = LoginForm()
        signupform = SignupForm()
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if not user:
            flash("Por favor, faça cadastramento para acesso")
            return redirect(url_for('signup', FORM=signupform))
        elif not check_password_hash(user.password, password):
            flash('Senha incorreta')
            return redirect(url_for('login_post', FORM=loginform))
        else:
            login_user(user)
            flash('Bem Vindo')
            return redirect(url_for('profile', USERID=user.id))

    # Rota para LOGOUT
    @app.route("/logout")
    def logout():
        logout_user()
        return redirect(url_for('login_get'))

    # Rota para SIGNUP
    @app.route("/signup", methods=['GET', 'POST'])
    def signup():
        if request.method == 'GET':
            form = SignupForm()
            return render_template("signup.html", FORM=form)
        else:
            form = SignupForm()
            form.username.username = request.form['username']
            form.username.email = request.form['email']
            form.username.password = request.form['password']

            user_exists = User.query.filter_by(username=form.username.username).first()
            email_exists = User.query.filter_by(email=form.username.email).first()

            if user_exists or email_exists:
                flash('user já existe')
                return redirect(url_for('signup', FORM=form))
            else:
                print("cadastrando novo usuário")
                new_user = User(
                    username=form.username.username,
                    email=form.username.email,
                    password=generate_password_hash(form.username.password, method='md5'))
                db.session.add(new_user)
                db.session.commit()
            return render_template('login.html', FORM=form)

    # Rota para PROFILE
    @app.route("/profile", methods=['GET', 'POST'])
    def profile():
        user = load_user(request.args['USERID'])
        return render_template('profile.html', NOME=user.username)

    return app
