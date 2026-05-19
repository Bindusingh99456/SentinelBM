from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class ThreatAlert(db.Model):
    """
    Database Model to permanently store triggered incidents.
    """
    __tablename__ = 'threat_alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    attack_type = db.Column(db.String(100), nullable=False)
    source_ip = db.Column(db.String(45), nullable=False) # 45 handles IPv6 mapping
    raw_log = db.Column(db.Text, nullable=False)
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() + 'Z',
            'attack_type': self.attack_type,
            'source_ip': self.source_ip,
            'raw_log': self.raw_log
        }
