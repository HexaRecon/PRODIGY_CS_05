from scapy.all import sniff, IP, TCP, UDP, ICMP, wrpcap
import datetime

# Generate a timestamped filename to save captured packets
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
pcap_file = f"comillas_negras_capture_{timestamp}.pcap"

# List to hold captured packets
packet_log = []

# Function to handle each captured packet
def analyze_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Identify protocol
        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
        else:
            protocol = f"IP (proto={packet[IP].proto})"

        print(f"[{protocol}] {src_ip} ➡ {dst_ip}")

        # Optional: Display TCP payload
        if packet.haslayer(TCP) and packet[TCP].payload:
            payload = bytes(packet[TCP].payload)
            print(f"   Payload: {payload[:40]}{'...' if len(payload) > 40 else ''}\n")

        # Add packet to save list
        packet_log.append(packet)

# Main function to start sniffing
def start_packet_sniffer():
    print("\n📡 Comillas Negras – Network Packet Analyzer")
    print("🔴 Sniffing started... (Press Ctrl+C to stop)\n")

    try:
        sniff(filter="ip", prn=analyze_packet, store=False)
    except KeyboardInterrupt:
        print("\n🛑 Sniffing stopped by user.")
        if packet_log:
            wrpcap(pcap_file, packet_log)
            print(f"✅ Packets saved to: {pcap_file}")
            print("📂 Open this file in Wireshark for analysis.")
        else:
            print("⚠️ No packets captured to save.")

# Run the sniffer
if __name__ == "__main__":
    start_packet_sniffer()

