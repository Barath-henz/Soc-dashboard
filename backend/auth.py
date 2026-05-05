from flask import Blueprint, request, jsonify
from functools import wraps
from models import db, User
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request

auth_bp = Blueprint('auth', __name__)
bcrypt = Bcrypt()

def require_role(roles):
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            verify_jwt_in_request()
            username = get_jwt_identity()
            user = User.query.filter_by(username=username).first()
            if not user or user.role not in roles:
                return jsonify({'error': 'Unauthorized - Insufficient privileges'}), 403
            return f(*args, **kwargs)
        return decorated
    return wrapper

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Missing username or password'}), 400
        
    user = User.query.filter_by(username=data['username']).first()
    
    if user:
        try:
            if bcrypt.check_password_hash(user.password_hash, data['password']):
                access_token = create_access_token(identity=user.username)
                return jsonify({'token': access_token, 'username': user.username, 'role': user.role})
        except ValueError:
            # Upgrade legacy hash
            if user.check_password(data['password']):
                user.password_hash = bcrypt.generate_password_hash(data['password']).decode('utf-8')
                db.session.commit()
                access_token = create_access_token(identity=user.username)
                return jsonify({'token': access_token, 'username': user.username, 'role': user.role})
            
    return jsonify({'error': 'Invalid credentials'}), 401

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    return jsonify({'message': 'Logged out successfully'})

@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def me():
    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'username': user.username, 'role': user.role})
