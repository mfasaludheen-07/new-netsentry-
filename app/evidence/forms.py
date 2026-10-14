from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import TextAreaField, SubmitField
from wtforms.validators import Length

class EvidenceUploadForm(FlaskForm):
    evidence_file = FileField('Evidence Artifact File', validators=[FileRequired()])
    description = TextAreaField('Chain of Custody Description / Context', validators=[Length(max=500)])
    submit = SubmitField('Upload & Compute Cryptographic Hash')
