from flask import Flask, render_template, flash, request, redirect, url_for
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_bootstrap import Bootstrap5
from wtforms import BooleanField, PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired

from werkzeug.security import generate_password_hash, check_password_hash
import logging

# Instanciando objetos dos módulos e propriedades padrão destes
logger = logging.getLogger("werkzeug")
db = SQLAlchemy()
bs = Bootstrap5()
login_manager = LoginManager()
login_manager.login_view = '/'
admin = Admin()
admin.name = 'Artigos'
admin.template_mode = 'bootstrap3'


# Formularios
class LoginForm(FlaskForm):
    username = StringField("username", validators=[DataRequired()])
    password = PasswordField("password", validators=[DataRequired()])
    submit = SubmitField()


class SignupForm(FlaskForm):
    username = StringField("username", validators=[DataRequired()])
    email = StringField("email", validators=[DataRequired()])
    password = PasswordField("password", validators=[DataRequired()])
    submit = SubmitField()


class ChangePasswordForm(FlaskForm):
    username = StringField("username", validators=[DataRequired()])
    password = PasswordField("password", validators=[DataRequired()])
    password1 = PasswordField("password", validators=[DataRequired()])
    password2 = PasswordField("password", validators=[DataRequired()])
    submit = SubmitField()


# Databases
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))


# Instanciando objetos dos módulos e propriedades padrão destes
logger = logging.getLogger("werkzeug")
db = SQLAlchemy()
bs = Bootstrap5()
login_manager = LoginManager()
login_manager.login_view = '/'
admin = Admin()
admin.name = 'Artigos'
admin.template_mode = 'bootstrap3'
admin.add_view(ModelView(User, db.session))

def create_app():

    app = Flask(__name__)

    # Injetando configurações no APP
    app.config["SECRET_KEY"] = "secret"
    app.config["SQLALCHEMY_DATABASE_URI"] = 'mysql+mysqlconnector://nhoj:123456@localhost/articles'
    app.config["DEBUG"] = True
    app.config["FLASK_ADMIN_SWATCH"] = 'slate'
    app.config['BOOTSTRAP_BOOTSWATCH_THEME'] = 'lumen'

    # Inicializando os módulos no APP
    bs.init_app(app)
    db.init_app(app)
    login_manager.init_app(app)
    admin.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    @app.route("/")
    def index():
        if current_user.is_active:
            user = load_user(current_user.get_id())
            logger.info("index:GET:user logged in:"+user.username)
            flash(str(user.username))
        else:
            logger.info("index:GET:user not logged in")
            flash("user nao logado")
        return render_template("index.html")

    @app.route("/login", methods=['GET'])
    def login_get():
        form = LoginForm()
        if current_user.is_active:
            user = load_user(current_user.get_id())
            logger.info("/login:GET:user logged in:"+user.username)
        else:
            logger.info("/login:GET:user not logged in")
        return render_template("login.html", FORM=form)

    @app.route("/login", methods=['POST'])
    def login_post():
        loginform = LoginForm()
        signupform = SignupForm()
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if not user:
            logger.info("/login:POST:user not found:"+username)
            flash("Por favor, faça cadastramento para acesso")
            return redirect(url_for('signup', FORM=signupform))
        elif not check_password_hash(user.password, password):
            logger.info("/login:POST:wrong password:"+username)
            flash('Senha incorreta')
            return redirect(url_for('login_post', FORM=loginform))
        else:
            logger.info("/login:POST:login sucessuful:"+username)
            login_user(user)
            flash('Bem Vindo '+username)
            return redirect(url_for('profile', USERID=user.id))

    # Rota para LOGOUT
    @app.route("/logout")
    @login_required
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

            if user_exists:
                flash('user já existe')
                return redirect(url_for('signup', FORM=form))
            elif email_exists:
                flash('email já existe')
                return redirect(url_for('signup', FORM=form))
            else:
                new_user = User(
                    username=form.username.username,
                    email=form.username.email,
                    password=generate_password_hash(form.username.password, method = 'md5'))
                db.session.add(new_user)
                db.session.commit()
            return render_template('login.html', FORM=form)

    # Rota para PROFILE
    @app.route("/profile", methods=['GET', 'POST'])
    @login_required
    def profile():
        user = load_user(request.args['USERID'])
        logger.info("/profile:GET/POST:user data showed:"+user.username)
        return render_template('profile.html', NOME=user.username)

    # Rota para CHANGE PASSWORD
    @app.route("/change_password", methods=['GET', 'POST'])
    @login_required
    def change_password():
        if request.method == 'GET':
            form = ChangePasswordForm()
            return render_template("change_password.html", FORM=form)
        elif request.method == 'POST':
            form = ChangePasswordForm()
            username = request.form['username']
            password = request.form['password']
            password1 = request.form['password1']
            password2 = request.form['password2']
            # verificar se username existe
            user = User.query.filter_by(username=username).first()
            if not user:
                flash("Usuário não encontrado")
                return redirect(url_for('change_password', FORM=form))

            # verificar se a senha atual está correta
            if not check_password_hash(user.password, password):
                flash("Senha atual incorreta")
                return redirect(url_for('change_password', FORM=form))

            # verificar se a senha1 e senha 2 são iguais
            if not (password1 == password2):
                flash("Nova senha não bate")
                return redirect(url_for('change_password', FORM=form))
            else:
                new_user = User(
                    username=user.username,
                    email=user.email,
                    password=generate_password_hash(password1, method='md5'))
                db.session.delete(user)
                db.session.commit()
                db.session.add(new_user)
                db.session.commit()
                flash("Senha trocada com sucesso")
                return redirect(url_for('change_password', FORM=form))
        else:
            return("Método não implementado")

    return app
