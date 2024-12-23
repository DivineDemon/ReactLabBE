from flask import Flask  # type: ignore
from flask_cors import CORS  # type: ignore
from flask_bcrypt import Bcrypt  # type: ignore
from flask_sqlalchemy import SQLAlchemy  # type: ignore
from flask_jwt_extended import JWTManager  # type: ignore

db = SQLAlchemy()
jwt = JWTManager()
bcrypt = Bcrypt()


def create_app():
    app = Flask(__name__)

    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['JWT_SECRET_KEY'] = 'your_secret_key'

    # Initialize extensions
    db.init_app(app)
    jwt.init_app(app)
    bcrypt.init_app(app)

    # Enable CORS
    CORS(app)

    # Register routes
    from .routes import main_bp
    app.register_blueprint(main_bp)

    return app
