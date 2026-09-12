def extract_flow_features(flow_key, flow_data):
    """
    Convert raw flow information into numerical features
    for threat detection.

    These features are designed to support:
        - DDoS / SYN-flood detection
        - reconnaissance detection
        - data-exfiltration analysis
        - behavioral ML models
    """

    endpoint_a, endpoint_b, protocol = flow_key

    packet_count = flow_data["packet_count"]
    total_bytes = flow_data["total_bytes"]
    timestamps = flow_data["timestamps"]

    forward_packets = flow_data["forward_packets"]
    reverse_packets = flow_data["reverse_packets"]

    forward_bytes = flow_data["forward_bytes"]
    reverse_bytes = flow_data["reverse_bytes"]

    # --------------------------------
    # Flow duration
    # --------------------------------

    if len(timestamps) >= 2:
        duration = max(timestamps) - min(timestamps)
    else:
        duration = 0.0

    # Prevent division by zero
    safe_duration = max(duration, 0.000001)

    # --------------------------------
    # Traffic rates
    # --------------------------------

    packets_per_second = packet_count / safe_duration
    bytes_per_second = total_bytes / safe_duration

    # --------------------------------
    # Direction ratios
    # --------------------------------

    if packet_count > 0:
        forward_ratio = forward_packets / packet_count
        reverse_ratio = reverse_packets / packet_count
    else:
        forward_ratio = 0.0
        reverse_ratio = 0.0

    # --------------------------------
    # TCP behavior
    # --------------------------------

    syn_count = flow_data["syn_count"]
    ack_count = flow_data["ack_count"]
    syn_ack_count = flow_data["syn_ack_count"]
    fin_count = flow_data["fin_count"]
    rst_count = flow_data["rst_count"]

    # SYN ratio
    if packet_count > 0:
        syn_ratio = syn_count / packet_count
    else:
        syn_ratio = 0.0

    # ACK ratio
    if packet_count > 0:
        ack_ratio = ack_count / packet_count
    else:
        ack_ratio = 0.0

    # SYN-to-ACK ratio
    if ack_count > 0:
        syn_to_ack_ratio = syn_count / ack_count
    else:
        syn_to_ack_ratio = float(syn_count)

    # SYN-to-SYN/ACK ratio
    if syn_ack_count > 0:
        syn_to_syn_ack_ratio = syn_count / syn_ack_count
    else:
        syn_to_syn_ack_ratio = float(syn_count)

    # --------------------------------
    # Packet/byte asymmetry
    # --------------------------------

    if reverse_packets > 0:
        packet_direction_ratio = (
            forward_packets / reverse_packets
        )
    else:
        packet_direction_ratio = float(forward_packets)

    if reverse_bytes > 0:
        byte_direction_ratio = (
            forward_bytes / reverse_bytes
        )
    else:
        byte_direction_ratio = float(forward_bytes)

    # --------------------------------
    # Feature dictionary
    # --------------------------------

    features = {
        # Flow identity
        "protocol": protocol,
        "src_ip": endpoint_a[0],
        "src_port": endpoint_a[1],
        "dst_ip": endpoint_b[0],
        "dst_port": endpoint_b[1],

        # Basic traffic
        "packet_count": packet_count,
        "total_bytes": total_bytes,
        "duration": duration,
        "packets_per_second": packets_per_second,
        "bytes_per_second": bytes_per_second,

        # Direction
        "forward_packets": forward_packets,
        "reverse_packets": reverse_packets,
        "forward_bytes": forward_bytes,
        "reverse_bytes": reverse_bytes,
        "forward_ratio": forward_ratio,
        "reverse_ratio": reverse_ratio,

        # TCP behavior
        "syn_count": syn_count,
        "ack_count": ack_count,
        "syn_ack_count": syn_ack_count,
        "fin_count": fin_count,
        "rst_count": rst_count,

        # TCP ratios
        "syn_ratio": syn_ratio,
        "ack_ratio": ack_ratio,
        "syn_to_ack_ratio": syn_to_ack_ratio,
        "syn_to_syn_ack_ratio": syn_to_syn_ack_ratio,

        # Asymmetry
        "packet_direction_ratio": packet_direction_ratio,
        "byte_direction_ratio": byte_direction_ratio,
    }

    return features


if __name__ == "__main__":
    print("Enhanced flow feature extractor ready.")
    