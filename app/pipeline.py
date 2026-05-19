import queue
import time
import random
import threading
from app.engine import boyer_moore_scan, build_bad_char_table
from app.models import db, ThreatAlert

# Thread-safe global state for log ingestion, signatures, and metrics
log_queue = queue.Queue(maxsize=10000)
active_signatures = {}
bad_char_tables = {}

metrics = {
    "total_logs_processed": 0,
    "total_threats_detected": 0,
    "total_execution_time_ms": 0.0,
    "total_comparisons": 0,
    "total_characters_skipped": 0
}

metrics_lock = threading.Lock()
signatures_lock = threading.Lock()

def update_signatures(new_signatures: dict):
    """
    Dynamically updates the active threat signatures dictionary and its 
    precomputed bad character tables in memory.
    """
    with signatures_lock:
        active_signatures.clear()
        bad_char_tables.clear()
        for name, pattern in new_signatures.items():
            active_signatures[name] = pattern
            bad_char_tables[name] = build_bad_char_table(pattern)

def log_tailer_worker():
    """
    Thread 1: Simulates or reads an incoming stream of server traffic, 
    pushing lines into the Queue.
    """
    sample_ips = ["192.168.1.10", "10.0.0.5", "172.16.0.2", "203.0.113.40", "114.5.3.1"]
    sample_logs = [
        "GET /index.html HTTP/1.1 200 OK",
        "POST /login HTTP/1.1 401 Unauthorized",
        "GET /api/data?query=UNION SELECT * FROM users HTTP/1.1 200 OK", # SQLi
        "GET /images/logo.png HTTP/1.1 200 OK",
        "GET /search?q=<script>alert('xss')</script> HTTP/1.1 200 OK", # XSS
        "GET /download?file=../../../../etc/passwd HTTP/1.1 403 Forbidden", # Path Traversal
        "POST /upload HTTP/1.1 200 OK",
        "GET /ping?host=127.0.0.1 ; rm -rf / HTTP/1.1 200 OK", # Command Injection
        "GET /about HTTP/1.1 200 OK"
    ]
    
    while True:
        ip = random.choice(sample_ips)
        log_msg = random.choice(sample_logs)
        raw_log = f"{ip} - - [{time.strftime('%d/%b/%Y:%H:%M:%S %z')}] \"{log_msg}\""
        
        try:
            log_queue.put(raw_log, timeout=1)
        except queue.Full:
            pass
            
        time.sleep(random.uniform(0.1, 1.5))

def engine_worker(app, socketio):
    """
    Thread 2: Continuously pops lines from the Queue, runs them through the 
    Boyer-Moore matching function against all active signatures, records hits 
    to the SQLite database via SQLAlchemy, and broadcasts real-time updates 
    using Flask-SocketIO.
    """
    while True:
        try:
            raw_log = log_queue.get(timeout=1)
        except queue.Empty:
            continue
            
        # Safely copy signatures to prevent dict size change during iteration
        with signatures_lock:
            current_sigs = active_signatures.copy()
            current_tables = bad_char_tables.copy()
            
        threat_detected = False
        detected_attack_type = None
        
        log_metrics = {
            "execution_time_ms": 0.0,
            "comparisons": 0,
            "characters_skipped": 0
        }
        
        for attack_type, pattern in current_sigs.items():
            table = current_tables[attack_type]
            match, scan_metrics = boyer_moore_scan(raw_log, pattern, table)
            
            log_metrics["execution_time_ms"] += scan_metrics["execution_time_ms"]
            log_metrics["comparisons"] += scan_metrics["comparisons"]
            log_metrics["characters_skipped"] += scan_metrics["characters_skipped"]
            
            if match:
                threat_detected = True
                detected_attack_type = attack_type
                break # Short-circuit
                
        # Safely update aggregate metrics
        with metrics_lock:
            metrics["total_logs_processed"] += 1
            metrics["total_execution_time_ms"] += log_metrics["execution_time_ms"]
            metrics["total_comparisons"] += log_metrics["comparisons"]
            metrics["total_characters_skipped"] += log_metrics["characters_skipped"]
            if threat_detected:
                metrics["total_threats_detected"] += 1
                
        if threat_detected:
            # We need an application context to use SQLAlchemy outside of a web request
            with app.app_context():
                source_ip = raw_log.split(' ')[0] # Basic space delimiter parsing
                alert = ThreatAlert(attack_type=detected_attack_type, source_ip=source_ip, raw_log=raw_log)
                db.session.add(alert)
                db.session.commit()
                
                # Broadcast the new alert via WebSocket
                socketio.emit('new_alert', alert.to_dict())
                
        log_queue.task_done()
