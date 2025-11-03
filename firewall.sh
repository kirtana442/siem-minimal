#!/bin/bash
# iptables firewall script with port scan detection and persistence

# Flush existing rules
iptables -F
iptables -X
iptables -Z

# Set default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow established and related incoming connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow localhost (loopback) traffic
iptables -A INPUT -i lo -j ACCEPT

# Allow SSH on port 22
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Port scan detection for TCP ports 1-1024
iptables -N PORTSCAN
iptables -A INPUT -p tcp -m multiport --dports 1:1024 \
  -m recent --name portscan --rcheck --seconds 60 --hitcount 10 \
  -j LOG --log-prefix "PORTSCAN DETECTED: " --log-level 4
iptables -A INPUT -p tcp -m multiport --dports 1:1024 \
  -m recent --name portscan --update --seconds 60 --hitcount 10 -j DROP
iptables -A INPUT -p tcp -m multiport --dports 1:1024 -m recent --name portscan --set -j ACCEPT

# Log dropped packets (limit to avoid flooding logs)
iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "IPTables-Dropped: " --log-level 4

# Save iptables rules to restore on reboot
iptables-save > /etc/iptables/rules.v4

echo "Firewall rules set, port-scan detection added, and saved for persistence."

# Reminder to install iptables-persistent if not already
echo "Install iptables-persistent for auto-loading rules at boot: sudo apt install iptables-persistent"
