import os
import csv
from io import StringIO
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from models import db, Log, Alert, User
from auth import auth_bp, require_role, bcrypt
from detection import run_detection_rules, ai_scorer
from socket_events import socketio, emit_new_log
from geo import get_ip_geolocation
from threat_intel import get_abuseipdb_score
from ir_routes import ir_bp

# Load environment variables
load_dotenv()

app = Flask(__name__, static_folder='../frontend', static_url_path='/')
CORS(app)

# Configure SQLite database (stored locally in the backend directory)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback-secret-key')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'jwt-fallback-secret-key')

# Initialize Extensions
db.init_app(app)
bcrypt.init_app(app)
socketio.init_app(app)
jwt = JWTManager(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["500 per day", "100 per hour"],
    storage_uri="memory://"
)

# Register Blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(ir_bp)

@app.route('/')
def index():
    return app.send_static_file('login.html')

@app.route('/dashboard')
def dashboard():
    return app.send_static_file('index.html')

@app.route('/health')
def health():
    return jsonify({'status': 'healthy'}), 200

with app.app_context():
    try:
        # Test if the new schema is present by querying User
        User.query.first()
        # Test if the Alert table has the new schema
        db.session.execute(db.text('SELECT status FROM alert LIMIT 1'))
    except Exception:
        # If it fails, we have the old schema. Drop and recreate for the enterprise upgrade.
        db.session.rollback()
        db.drop_all()
        
    db.create_all()
    
    # Create default admin if not exists
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(username='admin', role='admin')
        db.session.add(admin)
    admin.password_hash = bcrypt.generate_password_hash('Barath@Henz234').decode('utf-8')
    if not User.query.filter_by(username='viewer').first():
        viewer = User(username='viewer', role='viewer')
        viewer.password_hash = bcrypt.generate_password_hash('viewer123').decode('utf-8')
        db.session.add(viewer)
    db.session.commit()

    # Start automatic background log generator
    def background_log_generator():
        import random
        import time
        from datetime import datetime
        import threading
        
        def run():
            ips = ["192.168.1.5", "10.0.0.12", "172.16.0.22", "8.8.8.8", "192.168.1.100", "10.0.0.99", "203.0.113.45"]
            events = ["successful_login", "failed_login", "system_start", "config_change", "data_export"]
            
            while True:
                try:
                    with app.app_context():
                        ip = random.choice(ips)
                        event = random.choice(events)
                        
                        geo_data = get_ip_geolocation(ip)
                        threat_data = get_abuseipdb_score(ip)
                        
                        new_log = Log(
                            timestamp=datetime.utcnow(),
                            ip_address=ip,
                            event_type=event,
                            description=f"Automated background event: {event}",
                            country=geo_data.get('country'),
                            city=geo_data.get('city'),
                            latitude=geo_data.get('lat'),
                            longitude=geo_data.get('lon'),
                            threat_tags=threat_data.get('threat_tags')
                        )
                        new_log.risk_score = ai_scorer.predict_score(new_log)
                        
                        db.session.add(new_log)
                        db.session.commit()
                        
                        # Broadcast to connected clients
                        emit_new_log(new_log.to_dict())
                        # Run detection rules
                        run_detection_rules(new_log)
                except Exception as e:
                    print(f"Error in background generator: {e}")
                
                time.sleep(random.uniform(5, 10)) # Faster: Every 5-10 seconds

        thread = threading.Thread(target=run, daemon=True)
        thread.start()

    background_log_generator()

@app.route('/logs', methods=['POST'])
@limiter.limit("200 per minute")
def add_log():
    data = request.json
    if not data or not all(k in data for k in ('ip_address', 'event_type')):
        return jsonify({'error': 'Missing required fields'}), 400

    # Fetch Geolocation
    geo_data = get_ip_geolocation(data['ip_address'])
    
    # Fetch Threat Intel
    threat_data = get_abuseipdb_score(data['ip_address'])

    new_log = Log(
        timestamp=datetime.utcnow(),
        ip_address=data['ip_address'],
        event_type=data['event_type'],
        description=data.get('description', ''),
        country=geo_data.get('country'),
        city=geo_data.get('city'),
        latitude=geo_data.get('lat'),
        longitude=geo_data.get('lon'),
        threat_tags=threat_data.get('threat_tags')
    )
    
    # Calculate Risk Score
    new_log.risk_score = ai_scorer.predict_score(new_log)
    
    db.session.add(new_log)
    db.session.commit()

    # Broadcast to connected clients
    emit_new_log(new_log.to_dict())

    # Run detection rules on the new log entry
    run_detection_rules(new_log)

    return jsonify({'message': 'Log added successfully', 'log': new_log.to_dict()}), 201

@app.route('/logs/upload', methods=['POST'])
@jwt_required()
@require_role(['admin', 'analyst'])
def upload_logs():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
        
    if file and file.filename.endswith('.csv'):
        stream = StringIO(file.stream.read().decode("UTF8"), newline=None)
        csv_input = csv.DictReader(stream)
        added = 0
        for row in csv_input:
            if 'ip_address' in row and 'event_type' in row:
                geo_data = get_ip_geolocation(row['ip_address'])
                threat_data = get_abuseipdb_score(row['ip_address'])
                log = Log(
                    timestamp=datetime.utcnow(),
                    ip_address=row['ip_address'],
                    event_type=row['event_type'],
                    description=row.get('description', ''),
                    country=geo_data.get('country'),
                    city=geo_data.get('city'),
                    latitude=geo_data.get('lat'),
                    longitude=geo_data.get('lon'),
                    threat_tags=threat_data.get('threat_tags')
                )
                log.risk_score = ai_scorer.predict_score(log)
                db.session.add(log)
                run_detection_rules(log)
                added += 1
        db.session.commit()
        ai_scorer.fit_model()
        return jsonify({'message': f'Successfully uploaded and processed {added} logs'}), 200
        
    return jsonify({'error': 'Only CSV files are supported for now'}), 400

@app.route('/simulate', methods=['POST'])
@jwt_required()
@require_role(['admin'])
def simulate_attack():
    data = request.json
    attack_type = data.get('attack_type')
    
    if attack_type == 'brute_force':
        import log_generator
        socketio.start_background_task(log_generator.simulate_brute_force)
        return jsonify({'message': 'Brute force simulation started'}), 200
    elif attack_type == 'ddos':
        import log_generator
        socketio.start_background_task(log_generator.simulate_traffic_spike)
        return jsonify({'message': 'DDoS simulation started'}), 200
        
    return jsonify({'error': 'Unknown attack type'}), 400

@app.route('/logs', methods=['GET'])
@jwt_required()
def get_logs():
    event_type = request.args.get('event_type')
    search = request.args.get('search')
    
    query = Log.query

    if event_type and event_type != 'all':
        query = query.filter(Log.event_type == event_type)
    
    if search:
        query = query.filter(
            (Log.ip_address.contains(search)) |
            (Log.description.contains(search)) |
            (Log.event_type.contains(search))
        )

    logs = query.order_by(Log.timestamp.desc()).limit(100).all()
    return jsonify([log.to_dict() for log in logs])

@app.route('/alerts', methods=['GET'])
@jwt_required()
def get_alerts():
    alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(50).all()
    return jsonify([alert.to_dict() for alert in alerts])

@app.route('/alerts/<int:alert_id>', methods=['PUT'])
@jwt_required()
@require_role(['admin', 'analyst'])
def update_alert(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    data = request.json
    
    if 'status' in data:
        alert.status = data['status']
    if 'notes' in data:
        alert.notes = data['notes']
    if 'assignee_id' in data:
        alert.assignee_id = data['assignee_id']
        
    db.session.commit()
    # emit update event to sockets could be added here
    return jsonify(alert.to_dict())

@app.route('/stats', methods=['GET'])
@jwt_required()
def get_stats():
    total_logs = Log.query.count()
    total_alerts = Alert.query.count()
    critical_alerts = Alert.query.filter_by(severity='critical', status='open').count()
    
    return jsonify({
        'total_logs': total_logs,
        'total_alerts': total_alerts,
        'critical_alerts': critical_alerts
    })

@app.route('/analytics', methods=['GET'])
@jwt_required()
def get_analytics():
    # Top Attacking IPs
    top_ips = db.session.query(Log.ip_address, db.func.count(Log.id).label('total'))\
        .filter(Log.risk_score > 50)\
        .group_by(Log.ip_address).order_by(db.desc('total')).limit(5).all()
        
    # Country-wise attacks
    countries = db.session.query(Log.country, db.func.count(Log.id).label('total'))\
        .filter(Log.country.isnot(None))\
        .group_by(Log.country).order_by(db.desc('total')).limit(5).all()
        
    return jsonify({
        'top_ips': [{'ip': row[0], 'count': row[1]} for row in top_ips],
        'countries': [{'country': row[0], 'count': row[1]} for row in countries]
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
