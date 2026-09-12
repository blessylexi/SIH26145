def detect_dns_anomaly(features):
    """
    Detect suspicious DNS behavior associated with
    possible DGA or DNS tunnelling.

    This detector uses multiple behavioral signals.
    A single feature must not be treated as proof of
    malicious activity.
    """

    score = 0
    evidence = []

    dns_query_count = features["dns_query_count"]
    unique_domains = features["unique_domains"]

    average_query_length = (
        features["average_query_length"]
    )

    max_query_length = (
        features["max_query_length"]
    )

    average_label_length = (
        features["average_label_length"]
    )

    max_label_length = (
        features["max_label_length"]
    )

    average_domain_entropy = (
        features["average_domain_entropy"]
    )

    max_domain_entropy = (
        features["max_domain_entropy"]
    )

    average_numeric_ratio = (
        features["average_numeric_ratio"]
    )

    repeated_long_subdomains = (
        features["repeated_long_subdomains"]
    )

    # --------------------------------------------------
    # Query volume
    # --------------------------------------------------

    if dns_query_count >= 100:

        score += 3

        evidence.append(
            "very high DNS query volume: "
            f"{dns_query_count}"
        )

    elif dns_query_count >= 50:

        score += 2

        evidence.append(
            "high DNS query volume: "
            f"{dns_query_count}"
        )

    elif dns_query_count >= 20:

        score += 1

        evidence.append(
            "elevated DNS query volume: "
            f"{dns_query_count}"
        )

    # --------------------------------------------------
    # Domain diversity
    # --------------------------------------------------

    if unique_domains >= 50:

        score += 2

        evidence.append(
            "high queried-domain diversity: "
            f"{unique_domains}"
        )

    elif unique_domains >= 20:

        score += 1

        evidence.append(
            "elevated queried-domain diversity: "
            f"{unique_domains}"
        )

    # --------------------------------------------------
    # Query length
    # --------------------------------------------------

    if average_query_length >= 50:

        score += 3

        evidence.append(
            "very long average DNS query length: "
            f"{average_query_length:.2f}"
        )

    elif average_query_length >= 30:

        score += 2

        evidence.append(
            "long average DNS query length: "
            f"{average_query_length:.2f}"
        )

    elif average_query_length >= 20:

        score += 1

        evidence.append(
            "elevated average DNS query length: "
            f"{average_query_length:.2f}"
        )

    # --------------------------------------------------
    # Maximum query length
    # --------------------------------------------------

    if max_query_length >= 100:

        score += 2

        evidence.append(
            "extremely long DNS query observed: "
            f"{max_query_length}"
        )

    elif max_query_length >= 70:

        score += 1

        evidence.append(
            "long DNS query observed: "
            f"{max_query_length}"
        )

    # --------------------------------------------------
    # Label length
    # --------------------------------------------------

    if average_label_length >= 40:

        score += 3

        evidence.append(
            "very long average DNS label: "
            f"{average_label_length:.2f}"
        )

    elif average_label_length >= 25:

        score += 2

        evidence.append(
            "long average DNS label: "
            f"{average_label_length:.2f}"
        )

    elif average_label_length >= 15:

        score += 1

        evidence.append(
            "elevated DNS label length: "
            f"{average_label_length:.2f}"
        )

    # --------------------------------------------------
    # Maximum label length
    # --------------------------------------------------

    if max_label_length >= 50:

        score += 2

        evidence.append(
            "extremely long DNS label observed: "
            f"{max_label_length}"
        )

    elif max_label_length >= 30:

        score += 1

        evidence.append(
            "long DNS label observed: "
            f"{max_label_length}"
        )

    # --------------------------------------------------
    # Entropy
    # --------------------------------------------------

    if average_domain_entropy >= 4.5:

        score += 3

        evidence.append(
            "very high average domain entropy: "
            f"{average_domain_entropy:.2f}"
        )

    elif average_domain_entropy >= 4.0:

        score += 2

        evidence.append(
            "high average domain entropy: "
            f"{average_domain_entropy:.2f}"
        )

    elif average_domain_entropy >= 3.5:

        score += 1

        evidence.append(
            "elevated domain entropy: "
            f"{average_domain_entropy:.2f}"
        )

    # --------------------------------------------------
    # Maximum entropy
    # --------------------------------------------------

    if max_domain_entropy >= 5.0:

        score += 2

        evidence.append(
            "very high domain entropy observed: "
            f"{max_domain_entropy:.2f}"
        )

    elif max_domain_entropy >= 4.5:

        score += 1

        evidence.append(
            "high domain entropy observed: "
            f"{max_domain_entropy:.2f}"
        )

    # --------------------------------------------------
    # Numeric character ratio
    # --------------------------------------------------

    if average_numeric_ratio >= 0.40:

        score += 3

        evidence.append(
            "very high numeric-character ratio: "
            f"{average_numeric_ratio:.2f}"
        )

    elif average_numeric_ratio >= 0.25:

        score += 2

        evidence.append(
            "high numeric-character ratio: "
            f"{average_numeric_ratio:.2f}"
        )

    elif average_numeric_ratio >= 0.15:

        score += 1

        evidence.append(
            "elevated numeric-character ratio: "
            f"{average_numeric_ratio:.2f}"
        )

    # --------------------------------------------------
    # Repeated long subdomains
    # --------------------------------------------------

    if repeated_long_subdomains >= 10:

        score += 3

        evidence.append(
            "many repeated long subdomains: "
            f"{repeated_long_subdomains}"
        )

    elif repeated_long_subdomains >= 5:

        score += 2

        evidence.append(
            "repeated long subdomains: "
            f"{repeated_long_subdomains}"
        )

    elif repeated_long_subdomains >= 2:

        score += 1

        evidence.append(
            "some repeated long subdomains: "
            f"{repeated_long_subdomains}"
        )

    # --------------------------------------------------
    # Classification
    # --------------------------------------------------

    if score >= 10:

        threat_class = (
            "Potential DGA / DNS Tunnelling"
        )

        severity = "HIGH"
        confidence = 0.90

    elif score >= 6:

        threat_class = (
            "Suspicious DNS Behavior"
        )

        severity = "MEDIUM"
        confidence = 0.70

    elif score >= 3:

        threat_class = (
            "Potentially Suspicious DNS"
        )

        severity = "LOW"
        confidence = 0.50

    else:

        threat_class = (
            "No Suspicious DNS Behavior"
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
        "DNS anomaly detector ready."
    )
    