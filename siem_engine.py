import sqlite3
import time
from datetime import datetime, timedelta, timezone
from collections import defaultdict


class SIEMEngine:
    def __init__(self, db_path):
        self.db_path = db_path
        self.setup_tables()
        
        self.failed_logins = defaultdict(list)
        self.port_scan_attempts = defaultdict(lambda: {'ports': set(), 'timestamps': []})
        self.sudo_commands = defaultdict(list)
        
    def setup_tables(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                alert_type TEXT,
                severity TEXT,
                source_ip TEXT,
                description TEXT,
                evidence TEXT,
                status TEXT DEFAULT 'new',
                created_at REAL DEFAULT (strftime('%s', 'now'))
            )
        ''')
        
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_ts_ip ON alerts(timestamp, source_ip)')
        conn.commit()
        conn.close()
        
    def analyze_logs(self, hours=24):
        print("Starting SIEM Analysis...")
        
        logs = self.get_recent_logs(hours)
        print(f"Analyzing {len(logs)} logs from last {hours} hours")
        
        if len(logs) == 0:
            print("No logs found to analyze!")
            return
            
        self.failed_logins.clear()
        self.port_scan_attempts.clear()
        self.sudo_commands.clear()
        
        for log in logs:
            self.analyze_single_log(log)
            
        self.run_correlation_rules()
        
        print("Analysis complete!")
        
    def get_recent_logs(self, hours=24):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cutoff_time = time.time() - (hours * 3600)
        
        cursor.execute('''
            SELECT id, timestamp, source_ip, log_type, severity, message, raw_log_id
            FROM logs 
            WHERE timestamp >= ?
            ORDER BY timestamp
        ''', (cutoff_time,))
        
        logs = cursor.fetchall()
        conn.close()
        
        return logs
        
    def analyze_single_log(self, log):
        log_id, timestamp, source_ip, log_type, severity, message, raw = log
        
        # Use timezone-aware UTC datetime from timestamp
        log_time = datetime.fromtimestamp(timestamp, timezone.utc)
        
        if log_type == 'ssh' or log_type == "ssh_auth":
            self.analyze_ssh_auth(log_time, source_ip, message, severity, log_id)
        elif log_type == 'iptables':
            self.analyze_iptables(log_time, source_ip, message, severity, log_id)
            
    def analyze_ssh_auth(self, timestamp, source_ip, message, severity, log_id):
        if 'Failed SSH login' in message:
            if source_ip not in self.failed_logins:
                self.failed_logins[source_ip] = []
            self.failed_logins[source_ip].append({
                'timestamp': timestamp,
                'message': message,
                'log_id': log_id
            })
            
        elif 'sudo command executed' in message:
            if source_ip not in self.sudo_commands:
                self.sudo_commands[source_ip] = []
            self.sudo_commands[source_ip].append({
                'timestamp': timestamp,
                'message': message,
                'log_id': log_id
            })
            
    def analyze_iptables(self, timestamp, source_ip, message, severity, log_id):
        if 'port' in message:
            try:
                port_str = message.split('port ')[1].split()[0]
                port = int(port_str)
                
                if source_ip not in self.port_scan_attempts:
                    self.port_scan_attempts[source_ip] = {'ports': set(), 'timestamps': []}
                    
                self.port_scan_attempts[source_ip]['ports'].add(port)
                self.port_scan_attempts[source_ip]['timestamps'].append(timestamp)
                
            except (IndexError, ValueError):
                pass
                
    def run_correlation_rules(self):
        print("Running correlation rules...")
        
        self.detect_brute_force_attacks()
        self.detect_port_scans()
        self.detect_suspicious_sudo()
        self.detect_multi_threat_ips()
        
    def detect_brute_force_attacks(self):
        now_utc = datetime.now(timezone.utc)
        for source_ip, attempts in self.failed_logins.items():
            if len(attempts) >= 5:
                recent_attempts = [
                    attempt for attempt in attempts 
                    if attempt['timestamp'] > now_utc - timedelta(minutes=10)
                ]
                
                if len(recent_attempts) >= 5:
                    evidence = f"{len(recent_attempts)} failed SSH attempts in 10 minutes"
                    
                    self.create_alert(
                        timestamp=time.time(),
                        alert_type="SSH Brute Force Attack",
                        severity="HIGH",
                        source_ip=source_ip,
                        description=f"Multiple failed SSH login attempts from {source_ip}",
                        evidence=evidence
                    )
                    print(f"Brute force detected from {source_ip}: {len(recent_attempts)} attempts")
                    
    def detect_port_scans(self):
        now_utc = datetime.now(timezone.utc)
        for source_ip, scan_data in self.port_scan_attempts.items():
            unique_ports = len(scan_data['ports'])
            
            if unique_ports >= 5:
                recent_scans = [
                    ts for ts in scan_data['timestamps']
                    if ts > now_utc - timedelta(minutes=5)
                ]
                
                if len(recent_scans) >= 5:
                    port_list = ', '.join(map(str, sorted(list(scan_data['ports']))[:10]))
                    evidence = f"Scanned {unique_ports} ports: {port_list}"
                    
                    self.create_alert(
                        timestamp=time.time(),
                        alert_type="Port Scanning Detected",
                        severity="MEDIUM",
                        source_ip=source_ip,
                        description=f"Port scanning activity from {source_ip}",
                        evidence=evidence
                    )
                    print(f"Port scan detected from {source_ip}: {unique_ports} ports")
                    
    def detect_suspicious_sudo(self):
        for source_ip, commands in self.sudo_commands.items():
            if commands:
                if source_ip in self.failed_logins and len(self.failed_logins[source_ip]) > 0:
                    evidence = "Sudo command executed after failed login attempts"
                    
                    self.create_alert(
                        timestamp=time.time(),
                        alert_type="Suspicious Privilege Escalation",
                        severity="HIGH", 
                        source_ip=source_ip,
                        description=f"Sudo command executed after failed logins from {source_ip}",
                        evidence=evidence
                    )
                    print(f"Suspicious sudo activity from {source_ip}")
                    
    def detect_multi_threat_ips(self):
        brute_force_ips = set(self.failed_logins.keys())
        port_scan_ips = set(self.port_scan_attempts.keys())
        
        multi_threat_ips = brute_force_ips.intersection(port_scan_ips)
        
        for ip in multi_threat_ips:
            evidence = f"Multiple threat types: brute force + port scanning"
            
            self.create_alert(
                timestamp=time.time(),
                alert_type="Multi-Threat Actor",
                severity="HIGH",
                source_ip=ip,
                description=f"IP {ip} exhibiting multiple attack patterns",
                evidence=evidence
            )
            print(f"Multi-threat actor detected: {ip}")
            
    def create_alert(self, timestamp, alert_type, severity, source_ip, description, evidence):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO alerts (timestamp, alert_type, severity, source_ip, description, evidence)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (timestamp, alert_type, severity, source_ip, description, evidence))
        
        conn.commit()
        conn.close()
        
    def get_recent_alerts(self, hours=24):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cutoff_time = time.time() - (hours * 3600)
        
        cursor.execute('''
            SELECT timestamp, alert_type, severity, source_ip, description, evidence
            FROM alerts 
            WHERE timestamp >= ?
            ORDER BY timestamp DESC
        ''', (cutoff_time,))
        
        alerts = cursor.fetchall()
        conn.close()
        
        return alerts
        
    def print_alerts(self, hours=24):
        alerts = self.get_recent_alerts(hours)
        
        print("\n" + "=" * 80)
        print(f"SECURITY ALERTS (Last {hours} hours)")
        print("=" * 80)
        
        if not alerts:
            print("No security alerts found")
            return
            
        for timestamp, alert_type, severity, source_ip, description, evidence in alerts:
            # Convert alert timestamp using localtime for display (optional)
            alert_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            
            print(f"Time: {alert_time}")
            print(f"Alert Type: {alert_type}")
            print(f"Severity: {severity}")
            print(f"Source: {source_ip}")
            print(f"Description: {description}")
            print(f"Evidence: {evidence}")
            print("-" * 80)
