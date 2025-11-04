import siem_engine

def main():
    print("Starting SIEM System...")
    print("=" * 50)
    
    # Initialize SIEM engine
    siem = siem_engine.SIEMEngine("data/siem.db")
    
    # Analyze the logs
    siem.analyze_logs(hours=24)
    
    # Show results
    siem.print_alerts(hours=24)
    
    print("\nNext steps:")
    print("   python3 siem_cli.py dashboard    # View security dashboard")
    print("   python3 siem_cli.py alerts       # Show detailed alerts")

if __name__ == "__main__":
    main()