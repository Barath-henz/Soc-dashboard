import pandas as pd
from sklearn.ensemble import IsolationForest
from datetime import datetime, timedelta
from models import db, Log, Alert
from alerts import send_email_alert
from socket_events import emit_new_alert

# Configuration for detection rules
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_TIMEFRAME_MINUTES = 5
TRAFFIC_SPIKE_THRESHOLD = 50
TRAFFIC_SPIKE_TIMEFRAME_MINUTES = 1
SUSPICIOUS_IPS = ['192.168.1.100', '10.0.0.99', '172.16.0.50']

class AILogScorer:
    def __init__(self):
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.is_fitted = False

    def fit_model(self):
        try:
            logs = Log.query.order_by(Log.timestamp.desc()).limit(1000).all()
            if len(logs) < 50:
                return # Not enough data to train

            data = []
            for log in logs:
                hour = log.timestamp.hour
                is_local = 1 if log.ip_address.startswith(('192.168', '10.', '172.', '127.0.0.1')) else 0
                event_type_val = len(log.event_type) # Simple encoding
                data.append([hour, is_local, event_type_val])
                
            df = pd.DataFrame(data, columns=['hour', 'is_local', 'event_type_val'])
            self.model.fit(df)
            self.is_fitted = True
        except Exception as e:
            print("Error fitting model:", e)

    def predict_score(self, log_entry):
        base_score = 0
        if log_entry.threat_tags:
            base_score += 50
            
        if not self.is_fitted:
            self.fit_model()
            
        if self.is_fitted:
            hour = log_entry.timestamp.hour
            is_local = 1 if log_entry.ip_address.startswith(('192.168', '10.', '172.', '127.0.0.1')) else 0
            event_type_val = len(log_entry.event_type)
            
            df = pd.DataFrame([[hour, is_local, event_type_val]], columns=['hour', 'is_local', 'event_type_val'])
            anomaly_score = self.model.decision_function(df)[0]
            # Map -1 to 1 into 0 to 100 risk score
            ai_risk = max(0, min(100, int((0.5 - anomaly_score) * 100)))
            base_score = max(base_score, ai_risk)
            
        return min(100, base_score)

ai_scorer = AILogScorer()

def check_suspicious_ip(log_entry):
    if log_entry.ip_address in SUSPICIOUS_IPS or (log_entry.risk_score and log_entry.risk_score > 80):
        create_alert(
            rule="Suspicious IP Access",
            severity="high",
            description=f"Access from known suspicious IP or high risk IP: {log_entry.ip_address} (Event: {log_entry.event_type})",
            mitre_id="T1078",
            mitre_desc="Valid Accounts"
        )

def check_brute_force(log_entry):
    if log_entry.event_type != 'failed_login':
        return

    time_threshold = datetime.utcnow() - timedelta(minutes=BRUTE_FORCE_TIMEFRAME_MINUTES)
    
    failed_attempts = Log.query.filter(
        Log.ip_address == log_entry.ip_address,
        Log.event_type == 'failed_login',
        Log.timestamp >= time_threshold
    ).count()

    if failed_attempts >= BRUTE_FORCE_THRESHOLD:
        recent_alert = Alert.query.filter(
            Alert.rule_triggered == 'Brute Force Attack',
            Alert.description.contains(log_entry.ip_address),
            Alert.timestamp >= time_threshold
        ).first()

        if not recent_alert:
            create_alert(
                rule="Brute Force Attack",
                severity="critical",
                description=f"Detected {failed_attempts} failed login attempts from IP {log_entry.ip_address} within {BRUTE_FORCE_TIMEFRAME_MINUTES} minutes.",
                mitre_id="T1110",
                mitre_desc="Brute Force"
            )

def check_traffic_spike():
    time_threshold = datetime.utcnow() - timedelta(minutes=TRAFFIC_SPIKE_TIMEFRAME_MINUTES)
    
    log_count = Log.query.filter(
        Log.timestamp >= time_threshold
    ).count()

    if log_count >= TRAFFIC_SPIKE_THRESHOLD:
        recent_alert = Alert.query.filter(
            Alert.rule_triggered == 'Abnormal Traffic Spike',
            Alert.timestamp >= time_threshold
        ).first()

        if not recent_alert:
            create_alert(
                rule="Abnormal Traffic Spike",
                severity="medium",
                description=f"High log volume detected: {log_count} events in the last {TRAFFIC_SPIKE_TIMEFRAME_MINUTES} minute(s).",
                mitre_id="T1498",
                mitre_desc="Network Denial of Service"
            )

def create_alert(rule, severity, description, mitre_id=None, mitre_desc=None):
    new_alert = Alert(
        rule_triggered=rule,
        severity=severity,
        description=description,
        mitre_technique_id=mitre_id,
        mitre_description=mitre_desc
    )
    db.session.add(new_alert)
    db.session.commit()
    
    emit_new_alert(new_alert.to_dict())

    if severity == 'critical':
        send_email_alert(new_alert)

def run_detection_rules(log_entry):
    check_suspicious_ip(log_entry)
    check_brute_force(log_entry)
    check_traffic_spike()
