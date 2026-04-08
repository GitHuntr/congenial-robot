from flask import Flask
from core.config import config
from flask_cors import CORS
from datetime import timedelta

def create_app():
    app = Flask(__name__)
    app.secret_key = config.SECRET_KEY
    app.permanent_session_lifetime = timedelta(days=365) # 1 year persistence
    CORS(app)
    
    with app.app_context():
        from web import routes
        app.register_blueprint(routes.bp)
        
    return app
