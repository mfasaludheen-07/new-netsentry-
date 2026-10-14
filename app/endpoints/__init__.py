from flask import Blueprint

bp = Blueprint('endpoints', __name__)

from app.endpoints import routes
