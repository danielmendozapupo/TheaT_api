from flask import Blueprint, jsonify
from flask_restful import Api
from application import app

movies_bp = Blueprint('movies_bp', __name__)
movies_api = Api(movies_bp)
app.register_blueprint(movies_bp)

from .models import *


