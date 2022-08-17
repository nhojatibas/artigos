from flask import render_template, flash, request, redirect, url_for
from flask_login import login_required, current_user, login_user, logout_user

from articles.ext.database import db
from articles.ext.auth import login_manager, load_user

from articles.models import User
from articles.forms import LoginForm, SignupForm, ChangePasswordForm

from werkzeug.security import generate_password_hash, check_password_hash

import logging

logger = logging.getLogger("werkzeug")


# /
def index():
    if current_user.is_active:
        user = load_user(current_user.get_id())
        logger.info("index:GET:user logged in:"+user.username)
        flash(str(user.username))
    else:
        logger.info("index:GET:user not logged in")
        flash("user nao logado")
    return render_template("index.html")


# /login
def login():
    loginform = LoginForm()
    if request.method == "GET":
        if current_user.is_active:
            user = load_user(current_user.get_id())
            logger.info("/login:GET:user logged in:"+user.username)
            flash(str(user.username))
            return render_template("login.html", FORM=loginform)
        else:
            logger.info("/login:GET:user not logged in")
            flash("user nao logado")
            return render_template("login.html", FORM=loginform)
    else:
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
            return redirect(url_for('webui.login', FORM=loginform))
        else:
            logger.info("/login:POST:login sucessuful:"+username)
            login_user(user)
            flash('Bem Vindo '+username)
            return redirect(url_for('webui.profile', USERID=user.id))


# /logout
def logout():
    logout_user()
    return redirect(url_for('webui.login'))


# /signup
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
            return redirect(url_for('webui.signup', FORM=form))
        elif email_exists:
            flash('email já existe')
            return redirect(url_for('webui.signup', FORM=form))
        else:
            new_user = User(
                username=form.username.username,
                email=form.username.email,
                password=generate_password_hash(form.username.password, method='md5'))
            db.session.add(new_user)
            db.session.commit()
        return render_template('login.html', FORM=form)


# /profile
def profile():
    user = load_user(request.args['USERID'])
    logger.info("/profile:GET/POST:user data showed:"+user.username)
    return render_template('profile.html', NOME=user.username)


# /change_password
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
            return redirect(url_for('webui.change_password', FORM=form))

        # verificar se a senha atual está correta
        if not check_password_hash(user.password, password):
            flash("Senha atual incorreta")
            return redirect(url_for('webui.change_password', FORM=form))

        # verificar se a senha1 e senha 2 são iguais
        if not (password1 == password2):
            flash("Nova senha não bate")
            return redirect(url_for('webui.change_password', FORM=form))
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
            return redirect(url_for('webui.change_password', FORM=form))
    else:
        return("Método não implementado")
