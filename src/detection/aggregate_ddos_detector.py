def detect_aggregate_ddos(features):
    """
    Detect DDoS-like behavior using traffic-window features.

    This detector works at the network-window level rather than
    on a single flow.

    The score is based on multiple behavioral indicators:
        - packet rate
        - SYN rate
        - SYN concentration
        - unique source IPs
        - source-IP entropy
        - destination concentration
        - source-port diversity
        - SYN/SYN-ACK relationship

    Returns an explainable detection result.
    """

    score = 0
    evidence = []

    total_packets = features["total_packets"]
    packets_per_second = features["packets_per_second"]
    syns_per_second = features["syns_per_second"]

    syn_count = features["syn_count"]
    syn_ack_count = features["syn_ack_count"]
    syn_ratio = features["syn_ratio"]

    unique_source_ips = features["unique_source_ips"]
    unique_source_ports = features["unique_source_ports"]

    source_ip_entropy = features["source_ip_entropy"]
    destination_concentration = features["destination_concentration"]

    # --------------------------------------------------
    # 1. High packet rate
    # --------------------------------------------------

    if packets_per_second > 1000:
        score += 2
        evidence.append(
            f"high packet rate: "
            f"{packets_per_second:.2f} packets/sec"
        )

    # --------------------------------------------------
    # 2. High SYN rate
    # --------------------------------------------------

    if syns_per_second > 500:
        score += 2
        evidence.append(
            f"high SYN rate: "
            f"{syns_per_second:.2f} SYNs/sec"
        )

    # --------------------------------------------------
    # 3. High SYN concentration
    # --------------------------------------------------

    if total_packets > 0 and syn_ratio > 0.70:
        score += 2
        evidence.append(
            f"high SYN concentration: "
            f"{syn_ratio:.2f}"
        )

    # --------------------------------------------------
    # 4. Multiple source IPs
    # --------------------------------------------------

    if unique_source_ips >= 5:
        score += 1
        evidence.append(
            f"multiple source IPs: "
            f"{unique_source_ips}"
        )

    # --------------------------------------------------
    # 5. High source-IP entropy
    #
    # Higher entropy means traffic is distributed
    # across more source addresses.
    # --------------------------------------------------

    if source_ip_entropy >= 2.0:
        score += 1
        evidence.append(
            f"high source-IP entropy: "
            f"{source_ip_entropy:.2f}"
        )

    # --------------------------------------------------
    # 6. Destination concentration
    #
    # Many packets targeting one destination can indicate
    # a concentrated flood.
    # --------------------------------------------------

    if destination_concentration >= 0.90:
        score += 2
        evidence.append(
            f"high destination concentration: "
            f"{destination_concentration:.2f}"
        )

    # --------------------------------------------------
    # 7. Source-port diversity
    # --------------------------------------------------

    if unique_source_ports >= 5:
        score += 1
        evidence.append(
            f"high source-port diversity: "
            f"{unique_source_ports}"
        )

    # --------------------------------------------------
    # 8. SYN/SYN-ACK imbalance
    #
    # A large number of SYNs with no observed SYN/ACK
    # response is suspicious.
    # --------------------------------------------------

    if syn_count >= 5 and syn_ack_count == 0:
        score += 2
        evidence.append(
            f"SYN/ACK response absence: "
            f"SYN={syn_count}, "
            f"SYN/ACK={syn_ack_count}"
        )

    # --------------------------------------------------
    # Final classification
    # --------------------------------------------------

    if score >= 8:

        threat_class = "DDoS / SYN-Flood Suspicious"
        severity = "HIGH"
        confidence = 0.95

    elif score >= 5:

        threat_class = "Potential Volumetric Attack"
        severity = "MEDIUM"
        confidence = 0.75

    elif score >= 3:

        threat_class = "Suspicious Traffic Pattern"
        severity = "LOW"
        confidence = 0.50

    else:

        threat_class = "No DDoS Detected"
        severity = "INFO"
        confidence = 0.10

    return {
        "threat_class": threat_class,
        "severity": severity,
        "confidence": confidence,
        "score": score,
        "evidence": evidence,
    }


if __name__ == "__main__":
    print("Aggregate DDoS detector module ready.")
    