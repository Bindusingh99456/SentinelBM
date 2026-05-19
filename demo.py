from app import create_app
from app.engine import boyer_moore_scan, build_bad_char_table
from config import Config

# Initialize signatures
signatures = Config.INITIAL_SIGNATURES
tables = {name: build_bad_char_table(pattern) for name, pattern in signatures.items()}

print("--- IDS Log Analyzer Engine Demo ---")
print("Active Signatures:")
for name, pattern in signatures.items():
    print(f" - {name}: '{pattern}'")
print("\n--- Scanning Incoming Server Logs ---")

logs = [
    "192.168.1.10 - - [19/May/2026:10:00:00 +0000] \"GET /index.html HTTP/1.1 200 OK\"",
    "10.0.0.5 - - [19/May/2026:10:01:00 +0000] \"GET /api/data?query=UNION SELECT * FROM users HTTP/1.1 200 OK\"",
    "172.16.0.2 - - [19/May/2026:10:02:00 +0000] \"GET /search?q=<script>alert('xss')</script> HTTP/1.1 200 OK\"",
    "114.5.3.1 - - [19/May/2026:10:03:00 +0000] \"GET /download?file=../../../../etc/passwd HTTP/1.1 403 Forbidden\""
]

total_comparisons = 0
total_skipped = 0

for log in logs:
    print(f"\n[LOG]: {log}")
    threat_detected = False
    for attack_type, pattern in signatures.items():
        table = tables[attack_type]
        match, metrics = boyer_moore_scan(log, pattern, table)
        
        total_comparisons += metrics['comparisons']
        total_skipped += metrics['characters_skipped']
        
        if match:
            print(f"  [!] THREAT DETECTED: {attack_type} (Matched signature: '{pattern}')")
            print(f"  [+] Scan Metrics -> Time: {metrics['execution_time_ms']:.4f}ms | Comparisons: {metrics['comparisons']} | Boyer-Moore Skips: {metrics['characters_skipped']}")
            threat_detected = True
            break
            
    if not threat_detected:
        print("  [+] CLEAN: No threats detected.")
        
print("\n--- Cumulative Summary ---")
print(f"Total Logs Scanned: {len(logs)}")
print(f"Total Engine Comparisons: {total_comparisons}")
print(f"Total Characters Skipped (Boyer-Moore Efficiency): {total_skipped}")
