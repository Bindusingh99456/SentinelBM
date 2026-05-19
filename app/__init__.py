from flask import Flask
from app.models import db
from app.routes import api
from config import Config
from flask_socketio import SocketIO

# Initialize extensions globally
socketio = SocketIO(cors_allowed_origins="*", async_mode="threading")

def create_app(config_class=Config):
    """
    Factory method initializing Flask extensions and registering blueprints.
    """
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize extensions with app context
    db.init_app(app)
    socketio.init_app(app)
    
    # Register Blueprints
    app.register_blueprint(api)
    
    return app
