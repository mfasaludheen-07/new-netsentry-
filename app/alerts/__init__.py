from flask import Blueprint

bp = Blueprint('alerts', __name__)

from app.alerts import routes
