from flask import Blueprint

bp = Blueprint('iocs', __name__)

from app.iocs import routes
