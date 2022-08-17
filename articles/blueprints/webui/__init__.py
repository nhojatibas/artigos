from flask import Blueprint

from .views import index, login, logout, signup, profile, change_password


bp = Blueprint("webui", __name__)

bp.add_url_rule("/",
                view_func=index,
                methods=['GET'])
bp.add_url_rule("/login",
                view_func=login,
                methods=['GET', 'POST'])
bp.add_url_rule("/logout",
                view_func=logout,
                methods=['GET'])
bp.add_url_rule("/signup",
                view_func=signup,
                methods=['GET', 'POST'])
bp.add_url_rule("/profile",
                view_func=profile,
                methods=['GET'])
bp.add_url_rule("/change_password",
                view_func=change_password,
                methods=['GET', 'POST'])


def init_app(app):
    app.register_blueprint(bp)
