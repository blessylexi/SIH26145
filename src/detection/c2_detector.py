def detect_c2_beaconing(features):
    """
    Detect possible command-and-control beaconing.

    Repeated communication alone is not sufficient to classify
    traffic as C2. Stronger evidence comes from temporal
    regularity and repeated periodic communication.

    Returns:
        threat_class
        severity
        confidence
        score
        evidence
    """

    score = 0
    evidence = []

    conversation_count = features["conversation_count"]
    periodic_conversations = features["periodic_conversations"]
    periodicity_ratio = features["periodicity_ratio"]
    conversations = features["conversations"]

    # --------------------------------------------------
    # Repeated communication
    # --------------------------------------------------
    #
    # Repetition is only weak supporting evidence.
    # It does NOT independently trigger a suspicious result.

    repeated_conversations = [
        conversation
        for conversation in conversations
        if conversation["connection_count"] >= 5
    ]

    if repeated_conversations:

        evidence.append(
            f"repeated communication observed in "
            f"{len(repeated_conversations)} "
            f"conversation(s)"
        )

    # --------------------------------------------------
    # Periodic communication
    # --------------------------------------------------

    if periodic_conversations >= 1:

        score += 3

        evidence.append(
            f"periodic communication detected in "
            f"{periodic_conversations} "
            f"conversation(s)"
        )

    # --------------------------------------------------
    # Strong periodicity across conversations
    # --------------------------------------------------

    if (
        conversation_count > 0
        and periodicity_ratio >= 0.50
    ):

        score += 2

        evidence.append(
            f"high periodicity ratio: "
            f"{periodicity_ratio:.2f}"
        )

    # --------------------------------------------------
    # Highly regular beacon timing
    # --------------------------------------------------

    regular_intervals = [
        conversation
        for conversation in conversations
        if (
            conversation["coefficient_of_variation"] <= 0.10
            and conversation["connection_count"] >= 5
        )
    ]

    if regular_intervals:

        score += 2

        evidence.append(
            f"highly regular beacon timing in "
            f"{len(regular_intervals)} "
            f"conversation(s)"
        )

    # --------------------------------------------------
    # Classification
    # --------------------------------------------------

    if score >= 7:

        threat_class = "Potential C2 Beaconing"
        severity = "HIGH"
        confidence = 0.90

    elif score >= 4:

        threat_class = "Suspicious Periodic Communication"
        severity = "MEDIUM"
        confidence = 0.70

    elif score >= 3:

        threat_class = "Possible Beaconing Pattern"
        severity = "LOW"
        confidence = 0.50

    else:

        threat_class = "No C2 Beaconing Detected"
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

    print("C2 beaconing detector module ready.")
    