import yaml
from scapy.all import IP, TCP, UDP

with open("rules.yaml", "r") as f:
    RULES = yaml.safe_load(f)

def check_packet(packet):
    ip_layer = packet.getlayer(IP)
    if not ip_layer:
        return "allow"

    for rule in RULES:
        if rule["protocol"] == "tcp" and packet.haslayer(TCP):
            if rule.get("src_ip") and rule["src_ip"] != ip_layer.src:
                continue
            if rule.get("dst_port") and rule["dst_port"] != packet[TCP].dport:
                continue
            return rule["action"]

        elif rule["protocol"] == "udp" and packet.haslayer(UDP):
            if rule.get("dst_port") and rule["dst_port"] != packet[UDP].dport:
                continue
            return rule["action"]

    return "allow"
