from flask import Blueprint, request, jsonify
from app.models import ThreatAlert
from app.pipeline import update_signatures, metrics, metrics_lock, active_signatures, signatures_lock

api = Blueprint('api', __name__, url_prefix='/api/v1')

@api.route('/alerts', methods=['GET'])
def get_alerts():
    """
    Fetches paginated logs of historical alerts from the database.
    """
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    # Query database using Flask-SQLAlchemy
    pagination = ThreatAlert.query.order_by(ThreatAlert.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return jsonify({
        'alerts': [alert.to_dict() for alert in pagination.items],
        'total': pagination.total,
        'pages': pagination.pages,
        'current_page': page
    })

@api.route('/signatures', methods=['POST'])
def post_signatures():
    """
    Dynamically updates the active threat signatures dictionary and its 
    precomputed bad character tables in memory without needing a server reboot.
    Expects a JSON dictionary: {"attack_name": "signature_string"}
    """
    data = request.get_json()
    if not data or not isinstance(data, dict):
        return jsonify({'error': 'Invalid payload. Expected a JSON dictionary of signatures.'}), 400
        
    update_signatures(data)
    
    return jsonify({
        'message': 'Signatures updated successfully', 
        'active_signatures': list(data.keys())
    })

@api.route('/metrics', methods=['GET'])
def get_metrics():
    """
    Returns a summary JSON payload of cumulative scanner efficiency metrics.
    """
    with metrics_lock:
        current_metrics = metrics.copy()
    with signatures_lock:
        active_sigs_count = len(active_signatures)
        
    return jsonify({
        'metrics': current_metrics,
        'active_signatures_count': active_sigs_count
    })
