from flask_bootstrap import Bootstrap5

bs = Bootstrap5()


def init_app(app):
    bs.init_app(app)
