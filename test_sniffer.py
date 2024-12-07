from scapy.all import sniff

def process_packet(packet):
    print(packet.summary())

print("Starting packet capture...")
sniff(count=10, prn=process_packet)
