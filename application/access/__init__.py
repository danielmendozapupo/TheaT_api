from flask import Blueprint
from flask_restful import Api
from application import app, api

access_bp = Blueprint('access_bp', __name__)
access_api = Api(access_bp)
app.register_blueprint(access_bp)

from .models import *
from .routes import *