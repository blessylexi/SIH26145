from scapy.all import IP, TCP, UDP, Ether, wrpcap


OUTPUT_FILE = "data/raw/test_traffic.pcap"


def create_test_pcap():
    packets = []

    # Normal TCP traffic
    packets.append(
        Ether() /
        IP(src="192.168.1.10", dst="192.168.1.20") /
        TCP(sport=12345, dport=80)
    )

    packets.append(
        Ether() /
        IP(src="192.168.1.20", dst="192.168.1.10") /
        TCP(sport=80, dport=12345)
    )

    # Normal UDP traffic
    packets.append(
        Ether() /
        IP(src="192.168.1.10", dst="8.8.8.8") /
        UDP(sport=53000, dport=53)
    )

    packets.append(
        Ether() /
        IP(src="8.8.8.8", dst="192.168.1.10") /
        UDP(sport=53, dport=53000)
    )

    wrpcap(OUTPUT_FILE, packets)

    print(f"[TEST] Created PCAP: {OUTPUT_FILE}")
    print(f"[TEST] Packets written: {len(packets)}")


if __name__ == "__main__":
    create_test_pcap()
    