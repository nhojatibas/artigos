from flask_admin import Admin
from flask_admin.contrib import sqla

from articles.ext.database import db
from articles.models import User, Article, Tag

admin = Admin()


def init_app(app):
    admin.name = 'Artigos'
    admin.template_mode = 'bootstrap3'
    admin.init_app(app)
    admin.add_view(sqla.ModelView(User, db.session))
    admin.add_view(sqla.ModelView(Article, db.session))
    admin.add_view(sqla.ModelView(Tag, db.session))
