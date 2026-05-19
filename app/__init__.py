import os
from flask import Flask
from app.models import db
from app.routes import api, v1
from config import Config
from flask_socketio import SocketIO

# Initialize extensions globally
socketio = SocketIO(cors_allowed_origins="*", async_mode="threading")

def create_app(config_class=Config):
    """
    Factory method initializing Flask extensions and registering blueprints.
    """
    _root = os.path.dirname(os.path.abspath(__file__))
    app = Flask(
        __name__,
        template_folder=os.path.join(_root, 'templates'),
        static_folder=os.path.join(_root, 'static'),
        static_url_path='/static',
    )
    app.config.from_object(config_class)
    
    # Initialize extensions with app context
    db.init_app(app)
    socketio.init_app(app)
    
    # Register Blueprints
    app.register_blueprint(api)
    app.register_blueprint(v1)
    
    return app
