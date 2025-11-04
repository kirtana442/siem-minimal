import sqlite3
import re
from datetime import datetime, timezone


DB_PATH = "data/siem.db"


def extract_timestamp(raw_message):
    """
    Extract a timestamp from the start of the log line in 'MMM DD HH:MM:SS' format,
    add current year, and convert to UTC Unix timestamp.
    """
    ts_match = re.match(r'(?P<ts>\w{3} \d{1,2} \d{2}:\d{2}:\d{2})', raw_message)
    if ts_match:
        ts_str = ts_match.group('ts')
        try:
            dt = datetime.strptime(ts_str, "%b %d %H:%M:%S")
            dt = dt.replace(year=datetime.now(timezone.utc).year, tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            pass
    return datetime.now(timezone.utc).timestamp()


def parse_raw_log(source, raw_message):
    """
    Parses a raw log line and returns a tuple matching 
    the logs table fields (excluding raw):
    (timestamp, source_ip, log_type, severity, message)
    """
    timestamp = extract_timestamp(raw_message)
    source_ip = None
    log_type = source
    severity = "INFO"
    message = raw_message

    ssh_failed_pattern = r'Failed password for (?P<user>[\w\-]+) from (?P<ip>[\d\.]+)'
    ssh_success_pattern = r'Accepted password for (?P<user>[\w\-]+) from (?P<ip>[\d\.]+)'
    sudo_pattern = r'sudo:(?P<user>[\w\-]+):'
    sshd_session_pattern = r'session (opened|closed) for user (?P<user>[\w\-]+)'

    if source == "ssh":
        failed_match = re.search(ssh_failed_pattern, raw_message)
        success_match = re.search(ssh_success_pattern, raw_message)
        session_match = re.search(sshd_session_pattern, raw_message)
        if failed_match:
            source_ip = failed_match.group("ip")
            severity = "WARN"
            log_type = "ssh_auth"
            message = f"Failed SSH login for {failed_match.group('user')} from {source_ip}"
        elif success_match:
            source_ip = success_match.group("ip")
            severity = "INFO"
            log_type = "ssh_auth"
            message = f"Successful SSH login for {success_match.group('user')} from {source_ip}"
        elif session_match:
            user = session_match.group('user')
            action = session_match.group(1)  # "opened" or "closed"
            severity = "INFO"
            log_type = "ssh_session"
            message = f"SSH session {action} for user {user}"

    elif source == "sudo":
        sudo_match = re.search(sudo_pattern, raw_message)
        if sudo_match:
            severity = "HIGH"
            log_type = "sudo"
            message = f"Sudo command executed by {sudo_match.group('user')}"

    return (timestamp, source_ip, log_type, severity, message)


def process_raw_logs():
    """
    Process unprocessed entries in raw_logs, parse them and insert into logs table.
    Marks raw logs as processed after successful parsing.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT id, source, raw_message FROM raw_logs WHERE processed=0")
    rows = cursor.fetchall()

    processed_count = 0
    for raw_log_id, source, raw_message in rows:
        parsed_log = parse_raw_log(source, raw_message)

        cursor.execute('''
            INSERT INTO logs (raw_log_id, timestamp, source_ip, log_type, severity, message)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (raw_log_id, *parsed_log))

        cursor.execute('UPDATE raw_logs SET processed=1 WHERE id=?', (raw_log_id,))
        processed_count += 1

    conn.commit()
    conn.close()
    print(f"Processed {processed_count} raw logs.")


if __name__ == "__main__":
    process_raw_logs()
