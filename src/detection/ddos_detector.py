def detect_ddos(features):
    """
    Detect suspicious volumetric and SYN-flood-like behavior.

    This is a rule-based baseline detector.
    It is intentionally explainable and will later be
    compared with the ML-based detection layer.
    """

    score = 0
    evidence = []

    protocol = features["protocol"]

    packet_count = features["packet_count"]
    packets_per_second = features["packets_per_second"]

    forward_ratio = features["forward_ratio"]
    reverse_ratio = features["reverse_ratio"]

    syn_count = features["syn_count"]
    ack_count = features["ack_count"]
    syn_ack_count = features["syn_ack_count"]

    syn_ratio = features["syn_ratio"]

    dst_port = features["dst_port"]

    # ----------------------------------------
    # HIGH PACKET RATE
    # ----------------------------------------

    if packets_per_second > 1000:
        score += 2
        evidence.append(
            f"high packet rate: "
            f"{packets_per_second:.2f} packets/sec"
        )

    # ----------------------------------------
    # HIGH PACKET COUNT
    # ----------------------------------------

    if packet_count > 100:
        score += 1
        evidence.append(
            f"high packet count: {packet_count}"
        )

    # ----------------------------------------
    # DIRECTIONAL IMBALANCE
    # ----------------------------------------

    if forward_ratio > 0.9 or reverse_ratio > 0.9:
        score += 1
        evidence.append(
            f"directional imbalance: "
            f"forward={forward_ratio:.2f}, "
            f"reverse={reverse_ratio:.2f}"
        )

    # ----------------------------------------
    # HIGH SYN CONCENTRATION
    # ----------------------------------------

    if protocol == "TCP" and syn_ratio > 0.7:
        score += 2
        evidence.append(
            f"high SYN concentration: "
            f"{syn_ratio:.2f}"
        )

    # ----------------------------------------
    # SYN WITHOUT ACK
    # ----------------------------------------

    if (
        protocol == "TCP"
        and syn_count >= 10
        and ack_count == 0
    ):
        score += 2
        evidence.append(
            f"SYN-heavy traffic with no ACKs: "
            f"SYN={syn_count}, ACK={ack_count}"
        )

    # ----------------------------------------
    # SYN WITHOUT SYN/ACK
    # ----------------------------------------

    if (
        protocol == "TCP"
        and syn_count >= 10
        and syn_ack_count == 0
    ):
        score += 1
        evidence.append(
            f"no SYN/ACK responses observed: "
            f"SYN={syn_count}, "
            f"SYN/ACK={syn_ack_count}"
        )

    # ----------------------------------------
    # COMMON SERVICE PORT
    # ----------------------------------------

    if (
        protocol == "TCP"
        and dst_port in {22, 25, 53, 80, 443}
    ):
        score += 1
        evidence.append(
            f"TCP traffic targeting "
            f"service port {dst_port}"
        )

    # ----------------------------------------
    # FINAL CLASSIFICATION
    # ----------------------------------------

    if score >= 6:

        threat_class = "DDoS / SYN-Flood Suspicious"
        severity = "HIGH"
        confidence = 0.95

    elif score >= 4:

        threat_class = "DDoS / SYN-Flood Suspicious"
        severity = "HIGH"
        confidence = 0.85

    elif score >= 2:

        threat_class = "Potential Volumetric Attack"
        severity = "LOW"
        confidence = 0.55

    else:

        threat_class = "No DDoS Detected"
        severity = "INFO"
        confidence = 0.10

    return {
        "threat_class": threat_class,
        "severity": severity,
        "confidence": confidence,
        "evidence": evidence,
    }


if __name__ == "__main__":
    print("Enhanced DDoS detector module ready.")
    