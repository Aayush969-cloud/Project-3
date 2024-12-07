from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, wrpcap
from datetime import datetime
from collections import Counter
import os

# Configuration
SAVE_TO_PCAP = True          # Save captured packets to a PCAP file
FILTER_PROTOCOL = None       # Example: 'TCP', 'UDP', 'ICMP', 'ARP', or None for all
TIMEOUT = 30                 # Capture time in seconds (None for indefinite)

# Global variables for statistics
packet_count = 0
protocol_counter = Counter()
captured_packets = []

# Color codes for terminal output
class Colors:
    RESET = "\033[0m"
    GREEN = "\033[92m"
    BLUE = "\033[94m"
    RED = "\033[91m"
    YELLOW = "\033[93m"

# Function to display packet details
def packet_handler(packet):
    global packet_count, captured_packets
    try:
        packet_count += 1
        captured_packets.append(packet)  # Store packet for PCAP export

        # Extract and print details based on protocol
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            protocol_name = "Unknown"

            if packet.haslayer(TCP):
                protocol_name = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                print(f"{Colors.GREEN}TCP Packet:{Colors.RESET} {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            elif packet.haslayer(UDP):
                protocol_name = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                print(f"{Colors.BLUE}UDP Packet:{Colors.RESET} {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            elif packet.haslayer(ICMP):
                protocol_name = "ICMP"
                print(f"{Colors.YELLOW}ICMP Packet:{Colors.RESET} {src_ip} -> {dst_ip}")
            else:
                protocol_name = "IP"
                print(f"{Colors.RED}IP Packet:{Colors.RESET} {src_ip} -> {dst_ip}")
            
            # Update statistics
            protocol_counter[protocol_name] += 1

        elif packet.haslayer(ARP):
            protocol_counter["ARP"] += 1
            print(f"{Colors.YELLOW}ARP Packet:{Colors.RESET} {packet[ARP].psrc} -> {packet[ARP].pdst}")
        else:
            protocol_counter["Others"] += 1
            print(f"{Colors.RED}Non-IP Packet Detected{Colors.RESET}")

        # Print live statistics every 5 packets
        if packet_count % 5 == 0:
            print(f"\n{Colors.BLUE}Live Statistics:{Colors.RESET}")
            for proto, count in protocol_counter.items():
                print(f"  {proto}: {count} packets")
            print("-" * 50)

    except Exception as e:
        print(f"{Colors.RED}Error processing packet:{Colors.RESET} {e}")

# Function to start sniffing packets
def start_sniffing():
    print(f"{Colors.GREEN}Starting network sniffer...{Colors.RESET}")
    print(f"Filters: {FILTER_PROTOCOL if FILTER_PROTOCOL else 'None'} | Timeout: {TIMEOUT if TIMEOUT else 'Unlimited'}")
    print("-" * 50)

    sniff(
        prn=packet_handler,
        filter=None if not FILTER_PROTOCOL else FILTER_PROTOCOL.lower(),
        store=0,
        timeout=TIMEOUT
    )

    # Save packets to PCAP if enabled
    if SAVE_TO_PCAP:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pcap_file = f"captured_packets_{timestamp}.pcap"
        wrpcap(pcap_file, captured_packets)
        print(f"{Colors.GREEN}Captured packets saved to:{Colors.RESET} {pcap_file}")

    # Print final statistics
    print(f"\n{Colors.YELLOW}Final Statistics:{Colors.RESET}")
    for proto, count in protocol_counter.items():
        print(f"  {proto}: {count} packets")
    print("-" * 50)

# Start the packet sniffer
start_sniffing()
