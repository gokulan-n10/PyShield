from scapy.all import TCP

# Dictionary to track connection states: (src_ip, dst_ip, src_port, dst_port) -> state
connection_table = {}

def update_connection_state(packet):
    if not packet.haslayer(TCP):
        return

    tcp = packet[TCP]
    key = (packet[0][1].src, packet[0][1].dst, tcp.sport, tcp.dport)

    if tcp.flags == "S":  # SYN
        connection_table[key] = "SYN"
    elif tcp.flags == "SA":  # SYN-ACK
        connection_table[key] = "SYN-ACK"
    elif tcp.flags == "A":  # ACK
        if key in connection_table and connection_table[key] == "SYN-ACK":
            connection_table[key] = "ESTABLISHED"
    elif tcp.flags == "F":  # FIN
        if key in connection_table:
            connection_table[key] = "FINISHED"
    elif tcp.flags == "R":  # RST
        if key in connection_table:
            del connection_table[key]

def is_connection_established(packet):
    if not packet.haslayer(TCP):
        return False

    ip = packet.getlayer(IP)
    tcp = packet.getlayer(TCP)
    key1 = (ip.src, ip.dst, tcp.sport, tcp.dport)
    key2 = (ip.dst, ip.src, tcp.dport, tcp.sport)

    return connection_table.get(key1) == "ESTABLISHED" or connection_table.get(key2) == "ESTABLISHED"

