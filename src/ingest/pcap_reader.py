from scapy.all import rdpcap


def read_pcap(file_path):
    """
    Read a PCAP file in read-only mode.

    Returns:
        packets: Scapy packet list
    """

    print(f"[INGEST] Reading PCAP: {file_path}")

    packets = rdpcap(file_path)

    print(f"[INGEST] Packets loaded: {len(packets)}")

    return packets


if __name__ == "__main__":
    print("PCAP reader module ready.")
    