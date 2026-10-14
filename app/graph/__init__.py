from flask import Blueprint

bp = Blueprint('graph', __name__)

from app.graph import routes
