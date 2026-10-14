from flask import Blueprint

bp = Blueprint('evidence', __name__)

from app.evidence import routes
