from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import db, Incident, IncidentNote, User
from auth import require_role
from datetime import datetime

ir_bp = Blueprint('ir', __name__)

@ir_bp.route('/incidents', methods=['GET'])
@jwt_required()
def get_incidents():
    status = request.args.get('status')
    severity = request.args.get('severity')
    query = Incident.query

    if status and status != 'all':
        query = query.filter(Incident.status == status)
    if severity and severity != 'all':
        query = query.filter(Incident.severity == severity)

    incidents = query.order_by(Incident.created_at.desc()).all()
    return jsonify([inc.to_dict() for inc in incidents])

@ir_bp.route('/incidents', methods=['POST'])
@jwt_required()
@require_role(['admin', 'analyst'])
def create_incident():
    data = request.json
    if not all(k in data for k in ('alert_type', 'source_ip', 'severity')):
        return jsonify({'error': 'Missing required fields'}), 400

    new_incident = Incident(
        alert_type=data['alert_type'],
        source_ip=data['source_ip'],
        severity=data['severity'],
        description=data.get('description', '')
    )
    db.session.add(new_incident)
    db.session.commit()
    return jsonify(new_incident.to_dict()), 201

@ir_bp.route('/incidents/<int:id>/assign', methods=['POST'])
@jwt_required()
@require_role(['admin', 'analyst'])
def assign_incident(id):
    incident = Incident.query.get_or_404(id)
    data = request.json
    assignee_id = data.get('assignee_id')
    
    if not assignee_id:
        # Auto-assign to current user if not specified
        current_user_id = get_jwt_identity()
        assignee_id = current_user_id

    incident.assignee_id = assignee_id
    incident.status = 'in_progress'
    db.session.commit()
    return jsonify(incident.to_dict())

@ir_bp.route('/incidents/<int:id>/resolve', methods=['POST'])
@jwt_required()
@require_role(['admin', 'analyst'])
def resolve_incident(id):
    incident = Incident.query.get_or_404(id)
    incident.status = 'resolved'
    incident.resolved_at = datetime.utcnow()
    db.session.commit()
    return jsonify(incident.to_dict())

@ir_bp.route('/incidents/<int:id>/notes', methods=['POST'])
@jwt_required()
@require_role(['admin', 'analyst'])
def add_note(id):
    incident = Incident.query.get_or_404(id)
    data = request.json
    content = data.get('content')
    
    if not content:
        return jsonify({'error': 'Note content required'}), 400

    note = IncidentNote(
        incident_id=id,
        author_id=get_jwt_identity(),
        content=content
    )
    db.session.add(note)
    db.session.commit()
    return jsonify(note.to_dict()), 201
