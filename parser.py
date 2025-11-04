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
    timestamp = extract_timestamp(raw_message)
    source_ip = None
    log_type = source
    severity = "INFO"
    message = raw_message

    ssh_failed_pattern = r'Failed password for (invalid user )?(?P<user>[\w\-]+) from (?P<ip>[\d\.]+)( port (?P<port>\d+))?'
    ssh_success_pattern = r'Accepted password for (?P<user>[\w\-]+) from (?P<ip>[\d\.]+)'
    sudo_pattern = r'sudo:(?P<user>[\w\-]+):'
    sudo_incorrect_pass_pattern = (
        r'sudo\[\d+\]:\s+(?P<user>[\w\-]+)\s*:\s*(?P<attempts>\d+)\s+incorrect password attempts\s*; '
        r'TTY=(?P<tty>[\w\/]+)\s*; PWD=(?P<pwd>[\w\/]+)\s*; USER=(?P<target_user>[\w\-]+)\s*; COMMAND=(?P<command>.+)'
    )
    sudo_pam_auth_fail_pattern = (
        r'pam_unix\(sudo:auth\): authentication failure; .* user=(?P<user>[\w\-]+)'
    )
    sshd_session_pattern = r'session (opened|closed) for user (?P<user>[\w\-]+)'
    pam_failure_pattern = r'(pam_unix|pam_winbind)\(sshd:auth\): (check pass; user unknown|pam_get_item returned a password)'

    if source == "ssh":
        failed_match = re.search(ssh_failed_pattern, raw_message)
        success_match = re.search(ssh_success_pattern, raw_message)
        session_match = re.search(sshd_session_pattern, raw_message)
        pam_match = re.search(pam_failure_pattern, raw_message)

        if failed_match:
            source_ip = failed_match.group("ip")
            severity = "WARN"
            log_type = "ssh_auth"
            user = failed_match.group("user")
            message = f"Failed SSH login for {user} from {source_ip}"
        elif success_match:
            source_ip = success_match.group("ip")
            severity = "INFO"
            log_type = "ssh_auth"
            user = success_match.group("user")
            message = f"Successful SSH login for {user} from {source_ip}"
        elif session_match:
            user = session_match.group('user')
            action = session_match.group(1)
            severity = "INFO"
            log_type = "ssh_session"
            message = f"SSH session {action} for user {user}"
        elif pam_match:
            severity = "WARN"
            log_type = "ssh_auth"
            message = f"SSH PAM auth failure: {raw_message}"

    elif source == "sudo":
        incorrect_pass_match = re.search(sudo_incorrect_pass_pattern, raw_message)
        pam_auth_fail_match = re.search(sudo_pam_auth_fail_pattern, raw_message)

        if incorrect_pass_match:
            severity = "WARN"
            log_type = "sudo"
            user = incorrect_pass_match.group("user")
            attempts = incorrect_pass_match.group("attempts")
            target_user = incorrect_pass_match.group("target_user")
            command = incorrect_pass_match.group("command").strip()
            message = (f"Sudo incorrect password attempts by {user} ({attempts} attempts) "
                       f"to run command '{command}' as {target_user}")
        elif pam_auth_fail_match:
            severity = "WARN"
            log_type = "sudo"
            user = pam_auth_fail_match.group("user")
            message = f"Sudo PAM authentication failure for user {user}"
        else:
            sudo_match = re.search(sudo_pattern, raw_message)
            if sudo_match:
                severity = "HIGH"
                log_type = "sudo"
                user = sudo_match.group("user")
                message = f"Sudo command executed by {user}"

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
