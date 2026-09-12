def detect_reconnaissance(features):
    """
    Detect reconnaissance and port-scanning behavior.

    Primary behavioral signals:

        - destination-port diversity
        - destination-IP diversity
        - SYN concentration
        - SYN attempts without SYN/ACK responses

    The detector does not treat source-port diversity
    as primary evidence of scanning.
    """

    score = 0
    evidence = []

    total_packets = features[
        "total_packets"
    ]

    syn_count = features[
        "syn_count"
    ]

    syn_ack_count = features[
        "syn_ack_count"
    ]

    syn_ratio = features[
        "syn_ratio"
    ]

    unique_destination_ips = features[
        "unique_destination_ips"
    ]

    unique_destination_ports = features[
        "unique_destination_ports"
    ]

    # --------------------------------------------------
    # Destination-port scanning
    # --------------------------------------------------

    if unique_destination_ports >= 20:

        score += 3

        evidence.append(
            "high destination-port diversity: "
            f"{unique_destination_ports}"
        )

    elif unique_destination_ports >= 10:

        score += 2

        evidence.append(
            "elevated destination-port diversity: "
            f"{unique_destination_ports}"
        )

    elif unique_destination_ports >= 5:

        score += 1

        evidence.append(
            "multiple destination ports: "
            f"{unique_destination_ports}"
        )

    # --------------------------------------------------
    # Multiple targets
    # --------------------------------------------------

    if unique_destination_ips >= 20:

        score += 3

        evidence.append(
            "many destination IPs: "
            f"{unique_destination_ips}"
        )

    elif unique_destination_ips >= 10:

        score += 2

        evidence.append(
            "multiple destination IPs: "
            f"{unique_destination_ips}"
        )

    elif unique_destination_ips >= 5:

        score += 1

        evidence.append(
            "elevated destination-IP diversity: "
            f"{unique_destination_ips}"
        )

    # --------------------------------------------------
    # SYN concentration
    # --------------------------------------------------

    if (
        total_packets > 0
        and syn_ratio >= 0.70
    ):

        score += 2

        evidence.append(
            f"high SYN concentration: "
            f"{syn_ratio:.2f}"
        )

    # --------------------------------------------------
    # SYN attempts without responses
    # --------------------------------------------------

    if syn_count >= 5:

        if syn_ack_count == 0:

            score += 3

            evidence.append(
                "SYN attempts without SYN/ACK "
                f"responses: SYN={syn_count}, "
                f"SYN/ACK={syn_ack_count}"
            )

        elif syn_count >= (
            syn_ack_count * 3
        ):

            score += 2

            evidence.append(
                "SYN attempts greatly exceed "
                f"SYN/ACK responses: "
                f"SYN={syn_count}, "
                f"SYN/ACK={syn_ack_count}"
            )

    # --------------------------------------------------
    # Classification
    # --------------------------------------------------

    if score >= 7:

        threat_class = (
            "Reconnaissance / Port Scan"
        )

        severity = "HIGH"
        confidence = 0.90

    elif score >= 4:

        threat_class = (
            "Potential Reconnaissance"
        )

        severity = "MEDIUM"
        confidence = 0.70

    elif score >= 2:

        threat_class = (
            "Suspicious Scanning Pattern"
        )

        severity = "LOW"
        confidence = 0.50

    else:

        threat_class = (
            "No Reconnaissance Detected"
        )

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

    print(
        "Reconnaissance detector ready."
    )
    