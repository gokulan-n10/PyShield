from datetime import datetime

def log_packet(packet, decision):
    with open("firewall/firewall.log", "a") as f:
        f.write(f"{datetime.now()} | {decision.upper()} | {packet.summary()}\n")
