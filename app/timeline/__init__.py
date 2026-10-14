from flask import Blueprint

bp = Blueprint('timeline', __name__)

from app.timeline import routes
