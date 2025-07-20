from scapy.all import sniff, IP
from firewall.rule_engine import check_packet
from firewall.logger import log_packet
from firewall.stateful_tracker import update_connection_state, is_connection_established

def process_packet(packet):
    update_connection_state(packet)
    decision = check_packet(packet)

    # If packet is TCP, only allow if connection is established or allowed by rules
    if packet.haslayer(IP) and packet.haslayer("TCP"):
        if decision == "allow" and not is_connection_established(packet):
            decision = "drop"

    log_packet(packet, decision)

    if decision == "drop":
        print(f"[DROP] {packet.summary()}")
    else:
        print(f"[ALLOW] {packet.summary()}")

def start_sniffing():
    sniff(filter="ip", prn=process_packet, store=False)
