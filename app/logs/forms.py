from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import SelectField, StringField, SubmitField
from wtforms.validators import DataRequired

class LogUploadForm(FlaskForm):
    log_file = FileField('Telemetry Log File', validators=[FileRequired()])
    source_type = SelectField(
        'Log Source Format',
        choices=[
            ('Generic Network Log', 'Generic Network Flow CSV / TSV'),
            ('Firewall', 'Perimeter Firewall Flow Log'),
            ('DNS Telemetry', 'DNS Resolver / Query Log (JSON or CSV)'),
            ('Zeek/Bro Connection Log', 'Zeek / Bro Conn Telemetry'),
            ('Suricata EVE Flow', 'Suricata EVE JSON Flow Log'),
            ('Custom CSV', 'Custom Security Sensor CSV')
        ],
        default='Generic Network Log'
    )
    timezone = StringField('Source Log Timezone', default='UTC', validators=[DataRequired()])
    submit = SubmitField('Upload & Ingest Telemetry')
