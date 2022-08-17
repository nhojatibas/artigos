from flask import Flask

from articles.ext import appearance
from articles.ext import database
from articles.ext import auth
from articles.ext import admin

from articles.blueprints import webui

def create_app():

    app = Flask(__name__)

    # Injetando configurações no APP
    app.config["SECRET_KEY"] = "secret"
    app.config["SQLALCHEMY_DATABASE_URI"] = 'mysql+mysqlconnector://nhoj:123456@localhost/articles'
    app.config["DEBUG"] = True
    app.config["FLASK_ADMIN_SWATCH"] = 'slate'
    app.config['BOOTSTRAP_BOOTSWATCH_THEME'] = 'lumen'

    # Inicializando extensões e blueprints
    appearance.init_app(app)
    database.init_app(app)
    auth.init_app(app)
    admin.init_app(app)
    webui.init_app(app)

    return app
