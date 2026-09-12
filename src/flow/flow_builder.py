from scapy.layers.inet import IP, TCP, UDP


def get_protocol(packet):
    if packet.haslayer(TCP):
        return "TCP"

    if packet.haslayer(UDP):
        return "UDP"

    return "OTHER"


def get_tcp_flags(packet):
    """
    Extract TCP flags from a packet.

    Returns:
        Integer representation of TCP flags.
        0 for non-TCP packets.
    """

    if packet.haslayer(TCP):
        return int(packet[TCP].flags)

    return 0


def build_flows(packets):
    """
    Build bidirectional flows from packets.

    The first observed packet establishes the original
    forward direction of the flow.

    This allows later detection modules to reason about:

        - client -> server behavior
        - server -> client behavior
        - directional imbalance
        - SYN floods
        - reconnaissance
        - scanning
        - beaconing
        - possible exfiltration
    """

    flows = {}

    for packet in packets:

        if not packet.haslayer(IP):
            continue

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        protocol = get_protocol(packet)

        src_port = 0
        dst_port = 0

        if packet.haslayer(TCP):

            src_port = int(packet[TCP].sport)
            dst_port = int(packet[TCP].dport)

        elif packet.haslayer(UDP):

            src_port = int(packet[UDP].sport)
            dst_port = int(packet[UDP].dport)

        endpoint_a = (src_ip, src_port)
        endpoint_b = (dst_ip, dst_port)

        # --------------------------------------------------
        # Canonical flow identity
        # --------------------------------------------------
        #
        # Sorting is ONLY used to identify the same
        # bidirectional connection.
        #
        # It is NOT used to determine direction.
        #

        if endpoint_a <= endpoint_b:

            flow_key = (
                endpoint_a,
                endpoint_b,
                protocol
            )

        else:

            flow_key = (
                endpoint_b,
                endpoint_a,
                protocol
            )

        # --------------------------------------------------
        # Create flow
        # --------------------------------------------------

        if flow_key not in flows:

            flows[flow_key] = {

                "packet_count": 0,
                "total_bytes": 0,

                "timestamps": [],

                # First observed packet direction.
                "forward_endpoint": endpoint_a,
                "reverse_endpoint": endpoint_b,

                "forward_packets": 0,
                "reverse_packets": 0,

                "forward_bytes": 0,
                "reverse_bytes": 0,

                # TCP behavior
                "syn_count": 0,
                "ack_count": 0,
                "syn_ack_count": 0,
                "fin_count": 0,
                "rst_count": 0,
            }

        flow = flows[flow_key]

        # --------------------------------------------------
        # Basic statistics
        # --------------------------------------------------

        flow["packet_count"] += 1

        flow["total_bytes"] += len(packet)

        timestamp = float(packet.time)

        flow["timestamps"].append(timestamp)

        # --------------------------------------------------
        # Direction
        # --------------------------------------------------

        if endpoint_a == flow["forward_endpoint"]:

            flow["forward_packets"] += 1
            flow["forward_bytes"] += len(packet)

        else:

            flow["reverse_packets"] += 1
            flow["reverse_bytes"] += len(packet)

        # --------------------------------------------------
        # TCP flags
        # --------------------------------------------------

        if packet.haslayer(TCP):

            flags = int(packet[TCP].flags)

            if flags & 0x02:
                flow["syn_count"] += 1

            if flags & 0x10:
                flow["ack_count"] += 1

            if flags & 0x12 == 0x12:
                flow["syn_ack_count"] += 1

            if flags & 0x01:
                flow["fin_count"] += 1

            if flags & 0x04:
                flow["rst_count"] += 1

    return flows


if __name__ == "__main__":
    print(
        "Flow builder with first-observed direction ready."
    )
    