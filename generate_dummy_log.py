import time
from dummy_database import init_db, insert_log

def generate_dummy_data():
    init_db()

    current_time = time.time()

    # SSH auth logs (failed attempts and sudo command)
    logs = [
        (current_time - 300, '192.168.1.50', 'ssh_auth', 'WARN', 'Failed SSH login for admin', '<raw ssh log line>'),
        (current_time - 280, '192.168.1.50', 'ssh_auth', 'WARN', 'Failed SSH login for admin', '<raw ssh log line>'),
        (current_time - 260, '192.168.1.50', 'ssh_auth', 'WARN', 'Failed SSH login for admin', '<raw ssh log line>'),
        (current_time - 240, '192.168.1.50', 'ssh_auth', 'WARN', 'Failed SSH login for admin', '<raw ssh log line>'),
        (current_time - 220, '192.168.1.50', 'ssh_auth', 'WARN', 'Failed SSH login for admin', '<raw ssh log line>'),
        (current_time - 100, '192.168.1.51', 'ssh_auth', 'HIGH', 'sudo command executed by john', '<raw sudo log line>'),
    ]

    # Iptables firewall logs (port scan simulation)
    for port in range(20, 31):
        logs.append((current_time - port*5, '10.0.0.100', 'iptables', 'INFO', f'Connection attempt to port {port}', '<raw iptables log line>'))

    for log in logs:
        insert_log(*log)

if __name__ == "__main__":
    generate_dummy_data()
    print("Dummy logs inserted into database.")
