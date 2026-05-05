from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import uuid
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='viewer') # admin, analyst, viewer

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(50), nullable=False)
    event_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(500), nullable=True)
    country = db.Column(db.String(100), nullable=True)
    city = db.Column(db.String(100), nullable=True)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    risk_score = db.Column(db.Integer, nullable=True)
    threat_tags = db.Column(db.String(200), nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'ip_address': self.ip_address,
            'event_type': self.event_type,
            'description': self.description,
            'country': self.country,
            'city': self.city,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'risk_score': self.risk_score,
            'threat_tags': self.threat_tags
        }

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    rule_triggered = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(20), nullable=False) # 'low', 'medium', 'high', 'critical'
    description = db.Column(db.String(500), nullable=False)
    mitre_technique_id = db.Column(db.String(50), nullable=True)
    mitre_description = db.Column(db.String(200), nullable=True)
    assignee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    status = db.Column(db.String(20), default='open') # open, resolved
    notes = db.Column(db.Text, nullable=True)

    assignee = db.relationship('User', backref=db.backref('assigned_alerts', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'rule_triggered': self.rule_triggered,
            'severity': self.severity,
            'description': self.description,
            'mitre_technique_id': self.mitre_technique_id,
            'mitre_description': self.mitre_description,
            'assignee_id': self.assignee_id,
            'assignee_name': self.assignee.username if self.assignee else None,
            'status': self.status,
            'notes': self.notes
        }

class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    alert_type = db.Column(db.String(100), nullable=False)
    source_ip = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), nullable=False) # low, medium, high, critical
    status = db.Column(db.String(20), default='open') # open, in_progress, resolved
    assignee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = db.Column(db.DateTime, nullable=True)
    
    assignee = db.relationship('User', backref=db.backref('assigned_incidents', lazy=True))
    notes = db.relationship('IncidentNote', backref='incident', lazy=True, cascade="all, delete-orphan")

    def to_dict(self):
        return {
            'id': self.id,
            'alert_type': self.alert_type,
            'source_ip': self.source_ip,
            'severity': self.severity,
            'status': self.status,
            'assignee_id': self.assignee_id,
            'assignee_name': self.assignee.username if self.assignee else 'Unassigned',
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'notes': [note.to_dict() for note in self.notes]
        }

class IncidentNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey('incident.id'), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    author = db.relationship('User')

    def to_dict(self):
        return {
            'id': self.id,
            'author_name': self.author.username,
            'content': self.content,
            'timestamp': self.timestamp.isoformat()
        }
