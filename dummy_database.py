import sqlite3

def init_db(db_path='data/siem.db'):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            source_ip TEXT,
            log_type TEXT,
            severity TEXT,
            message TEXT,
            raw TEXT,
            indexed_at REAL DEFAULT (strftime('%s', 'now'))
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_ts_source ON logs(timestamp, source_ip)')
    conn.commit()
    conn.close()

def insert_log(timestamp, source_ip, log_type, severity, message, raw, db_path='data/siem.db'):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO logs (timestamp, source_ip, log_type, severity, message, raw)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (timestamp, source_ip, log_type, severity, message, raw))
    conn.commit()
    conn.close()
