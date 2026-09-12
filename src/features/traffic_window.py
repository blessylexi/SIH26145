from collections import Counter
from math import log2


def calculate_entropy(values):
    if not values:
        return 0.0

    counts = Counter(values)
    total = len(values)

    entropy = 0.0

    for count in counts.values():
        probability = count / total
        entropy -= probability * log2(probability)

    return entropy


def aggregate_traffic_window(packets, window_duration=1.0):
    """
    Aggregate packets into a fixed-duration traffic-analysis window.

    Features are derived only from packet metadata.

    Supports:
        - TCP
        - UDP
        - source/destination IPs
        - source/destination ports
        - SYN/ACK behavior
        - source-IP entropy
        - destination concentration
    """

    if window_duration <= 0:
        raise ValueError(
            "window_duration must be greater than zero"
        )

    total_packets = 0
    total_bytes = 0

    syn_count = 0
    ack_count = 0
    syn_ack_count = 0

    source_ips = []
    destination_ips = []

    source_ports = []
    destination_ports = []

    # --------------------------------------------------
    # Packet processing
    # --------------------------------------------------

    for packet in packets:

        if not packet.haslayer("IP"):
            continue

        total_packets += 1
        total_bytes += len(packet)

        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst

        source_ips.append(src_ip)
        destination_ips.append(dst_ip)

        # ----------------------------------------------
        # TCP
        # ----------------------------------------------

        if packet.haslayer("TCP"):

            tcp = packet["TCP"]

            source_ports.append(
                int(tcp.sport)
            )

            destination_ports.append(
                int(tcp.dport)
            )

            flags = int(tcp.flags)

            if flags & 0x02:
                syn_count += 1

            if flags & 0x10:
                ack_count += 1

            if flags & 0x12 == 0x12:
                syn_ack_count += 1

        # ----------------------------------------------
        # UDP
        # ----------------------------------------------

        elif packet.haslayer("UDP"):

            udp = packet["UDP"]

            source_ports.append(
                int(udp.sport)
            )

            destination_ports.append(
                int(udp.dport)
            )

    # --------------------------------------------------
    # Rates
    # --------------------------------------------------

    packets_per_second = (
        total_packets / window_duration
    )

    bytes_per_second = (
        total_bytes / window_duration
    )

    syns_per_second = (
        syn_count / window_duration
    )

    # --------------------------------------------------
    # Ratios
    # --------------------------------------------------

    if total_packets > 0:

        syn_ratio = (
            syn_count / total_packets
        )

    else:

        syn_ratio = 0.0

    # --------------------------------------------------
    # SYN / SYN-ACK relationship
    # --------------------------------------------------

    if syn_ack_count > 0:

        syn_to_syn_ack_ratio = (
            syn_count / syn_ack_count
        )

    elif syn_count > 0:

        syn_to_syn_ack_ratio = float("inf")

    else:

        syn_to_syn_ack_ratio = 0.0

    # --------------------------------------------------
    # Diversity
    # --------------------------------------------------

    unique_source_ips = len(
        set(source_ips)
    )

    unique_destination_ips = len(
        set(destination_ips)
    )

    unique_source_ports = len(
        set(source_ports)
    )

    unique_destination_ports = len(
        set(destination_ports)
    )

    # --------------------------------------------------
    # Source-IP entropy
    # --------------------------------------------------

    source_ip_entropy = calculate_entropy(
        source_ips
    )

    # --------------------------------------------------
    # Destination concentration
    # --------------------------------------------------

    if destination_ips:

        destination_counts = Counter(
            destination_ips
        )

        most_common_destination_count = (
            destination_counts
            .most_common(1)[0][1]
        )

        destination_concentration = (
            most_common_destination_count
            / len(destination_ips)
        )

    else:

        destination_concentration = 0.0

    # --------------------------------------------------
    # Return feature vector
    # --------------------------------------------------

    return {

        "window_duration": window_duration,

        "total_packets": total_packets,

        "total_bytes": total_bytes,

        "packets_per_second": (
            packets_per_second
        ),

        "bytes_per_second": (
            bytes_per_second
        ),

        "syns_per_second": (
            syns_per_second
        ),

        "syn_count": syn_count,

        "ack_count": ack_count,

        "syn_ack_count": syn_ack_count,

        "syn_ratio": syn_ratio,

        "syn_to_syn_ack_ratio": (
            syn_to_syn_ack_ratio
        ),

        "unique_source_ips": (
            unique_source_ips
        ),

        "unique_destination_ips": (
            unique_destination_ips
        ),

        "unique_source_ports": (
            unique_source_ports
        ),

        "unique_destination_ports": (
            unique_destination_ports
        ),

        "source_ip_entropy": (
            source_ip_entropy
        ),

        "destination_concentration": (
            destination_concentration
        ),
    }


if __name__ == "__main__":

    print(
        "Traffic-window feature extractor ready."
    )
    