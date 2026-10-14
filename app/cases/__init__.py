from flask import Blueprint

bp = Blueprint('cases', __name__)

from app.cases import routes
