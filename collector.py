import asyncio
import sqlite3
from datetime import datetime

DB_PATH = "data/siem.db"

def insert_raw_log(source, raw_message, db_path=DB_PATH):
    # Use UTC ISO timestamp for flexibility
    timestamp = datetime.utcnow().isoformat(timespec='seconds')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO raw_logs (source, timestamp, raw_message)
        VALUES (?, ?, ?)
    ''', (source, timestamp, raw_message))
    conn.commit()
    conn.close()

async def read_process_output(cmd, source):
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    async for raw_line in proc.stdout:
        line = raw_line.decode('utf-8').strip()
        insert_raw_log(source, line)
    await proc.wait()

async def get_ssh_logs():
    cmd = [
        "journalctl",
        "-u", "ssh.service",
        "--no-pager",
        "-f",
        "--since", "now"
    ]
    await read_process_output(cmd, "ssh")

async def get_sudo_logs():
    cmd = [
        "journalctl",
        "-t", "sudo",
        "--no-pager",
        "-f",
        "--since", "now"
    ]
    await read_process_output(cmd, "sudo")

async def main():
    await asyncio.gather(
        get_ssh_logs(),
        get_sudo_logs()
    )

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Collector stopped by user")
