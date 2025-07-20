# PyShield

PyShield is a powerfull stateful packet filtering firewall built using Python, Scapy, and PyYAML. I made this project to use personally for my home lab that I am currently working on. This project uses the concepts of traffic inspection, TCP connection tracking, and rule-based filtering.

Firewall features:
1. Stateful TCP filtering: Tracks SYN, ACK, FIN, and RST flags to identify valid connections
2. Custom rule engine: You can make your own firewall rules based on your personal preference through YAML configuration.
3. Real-time packet sniffing using Scapy.

Installation for personal use: 
1. Install the dependencies in requirements.txt using your CLI
2. Modify the firewall rules using rules.yaml
3. Createa firewall.log file in the firewall folder to see everything in live-action
4. Run the firewall by running main.py
