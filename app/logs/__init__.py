from flask import Blueprint

bp = Blueprint('logs', __name__)

from app.logs import routes
