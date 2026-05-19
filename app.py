import threading
from app import create_app, socketio, db
from app.pipeline import log_tailer_worker, engine_worker, update_signatures

# Initialize application factory
app = create_app()

with app.app_context():
    # Create tables
    db.create_all()
    # Initialize threat signatures in memory from configuration
    update_signatures(app.config['INITIAL_SIGNATURES'])

if __name__ == '__main__':
    # Thread 1: Start Log Tailer
    tailer_thread = threading.Thread(target=log_tailer_worker, daemon=True)
    tailer_thread.start()
    
    # Thread 2: Start Engine Worker
    engine_thread = threading.Thread(target=engine_worker, args=(app, socketio), daemon=True)
    engine_thread.start()
    
    print("Starting IDS Log Analyzer server...")
    # Run the SocketIO-wrapped Flask server
    # We use_reloader=False because the reloader creates multiple processes, 
    # which duplicates background threads.
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, use_reloader=False, allow_unsafe_werkzeug=True)
