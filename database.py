import sqlite3

DB_PATH = 'data/siem.db'

def init_db(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Raw logs table with processed flag
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS raw_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT,
            timestamp TEXT,
            raw_message TEXT,
            processed INTEGER DEFAULT 0   -- 0 = unprocessed, 1 = processed
        )
    ''')

    # Parsed logs table referencing raw_logs.id
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            raw_log_id INTEGER,
            timestamp REAL,
            source_ip TEXT,
            log_type TEXT,
            severity TEXT,
            message TEXT,
            indexed_at REAL DEFAULT (strftime('%s', 'now')),
            FOREIGN KEY (raw_log_id) REFERENCES raw_logs(id)
        )
    ''')

    cursor.execute('CREATE INDEX IF NOT EXISTS idx_ts_source ON logs(timestamp, source_ip)')

    conn.commit()
    conn.close()

def insert_raw_log(source, timestamp, raw_message, db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO raw_logs (source, timestamp, raw_message, processed)
        VALUES (?, ?, ?, 0)
    ''', (source, timestamp, raw_message))
    conn.commit()
    inserted_id = cursor.lastrowid
    conn.close()
    return inserted_id

def mark_raw_log_processed(log_id, db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('UPDATE raw_logs SET processed=1 WHERE id=?', (log_id,))
    conn.commit()
    conn.close()

def insert_log(raw_log_id, timestamp, source_ip, log_type, severity, message, db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO logs (raw_log_id, timestamp, source_ip, log_type, severity, message)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (raw_log_id, timestamp, source_ip, log_type, severity, message))
    conn.commit()
    conn.close()

init_db()