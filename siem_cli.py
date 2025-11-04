
import argparse
import time
import siem_engine

def main():
    parser = argparse.ArgumentParser(description='SIEM Engine CLI')
    parser.add_argument('command', choices=['analyze', 'alerts', 'dashboard', 'monitor'])
    parser.add_argument('--hours', type=int, default=24, help='Time window in hours')
    
    args = parser.parse_args()
    
    siem = siem_engine.SIEMEngine("data/siem.db")
    
    if args.command == 'analyze':
        print("Starting SIEM analysis...")
        siem.analyze_logs(args.hours)
        siem.print_alerts(args.hours)
        
    elif args.command == 'alerts':
        siem.print_alerts(args.hours)
        
    elif args.command == 'dashboard':
        show_dashboard(siem, args.hours)
        
    elif args.command == 'monitor':
        continuous_monitoring(siem, args.hours)
        
def show_dashboard(siem, hours):
    print("\n" + "=" * 60)
    print("SIEM SECURITY DASHBOARD")
    print("=" * 60)
    
    alerts = siem.get_recent_alerts(hours)
    
    high_count = sum(1 for alert in alerts if alert[2] == 'HIGH')
    medium_count = sum(1 for alert in alerts if alert[2] == 'MEDIUM')
    low_count = sum(1 for alert in alerts if alert[2] == 'LOW')
    
    print(f"Active Alerts: {len(alerts)}")
    print(f"High Severity: {high_count}")
    print(f"Medium Severity: {medium_count}") 
    print(f"Low Severity: {low_count}")
    
    source_ips = {}
    for alert in alerts:
        ip = alert[3]
        source_ips[ip] = source_ips.get(ip, 0) + 1
        
    if source_ips:
        print("\nTop Threat Sources:")
        for ip, count in sorted(source_ips.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"   {ip}: {count} alerts")
    else:
        print("\nTop Threat Sources: No alerts found")
            
    alert_types = {}
    for alert in alerts:
        alert_type = alert[1]
        alert_types[alert_type] = alert_types.get(alert_type, 0) + 1
        
    if alert_types:
        print("\nAlert Types:")
        for alert_type, count in alert_types.items():
            print(f"   {alert_type}: {count}")
    else:
        print("\nAlert Types: No alerts found")
            
    print("\nRun 'python3 siem_cli.py alerts' for detailed alerts")
    
def continuous_monitoring(siem, hours):
    print("Starting continuous monitoring...")
    print("Press Ctrl+C to stop")
    
    try:
        while True:
            siem.analyze_logs(hours)
            alerts = siem.get_recent_alerts(hours)
            
            if alerts:
                print(f"\nNew analysis completed: {len(alerts)} alerts found")
                high_alerts = [alert for alert in alerts if alert[2] == 'HIGH']
                if high_alerts:
                    print("HIGH SEVERITY ALERTS:")
                    for alert in high_alerts[-3:]:
                        print(f"   - {alert[1]} from {alert[3]}")
            else:
                print("No new alerts detected")
                
            time.sleep(10)
            
    except KeyboardInterrupt:
        print("\nMonitoring stopped")

if __name__ == "__main__":
    main()