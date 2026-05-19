import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'super-secret-ids-key'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'ids_alerts.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Predefined Threat Signatures Mapping
    INITIAL_SIGNATURES = {
        "SQL Injection": "UNION SELECT",
        "Cross-Site Scripting (XSS)": "<script>alert",
        "Path Traversal": "../../../../etc/passwd",
        "Command Injection": "; rm -rf /"
    }
