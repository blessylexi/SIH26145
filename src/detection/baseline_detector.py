from math import isfinite


# --------------------------------------------------
# Default normal-traffic baseline
# --------------------------------------------------
#
# These are deliberately simple prototype values.
# They are NOT claimed to be learned from real traffic.
#
# Later, the dashboard/experiment can replace these
# values with statistics calculated from a normal
# traffic replay.
# --------------------------------------------------

DEFAULT_BASELINE = {
    "packets_per_second": {
        "mean": 10.0,
        "std": 5.0,
    },

    "bytes_per_second": {
        "mean": 5000.0,
        "std": 2500.0,
    },

    "syn_ratio": {
        "mean": 0.10,
        "std": 0.10,
    },

    "unique_destination_ips": {
        "mean": 3.0,
        "std": 2.0,
    },

    "unique_destination_ports": {
        "mean": 5.0,
        "std": 4.0,
    },

    "source_ip_entropy": {
        "mean": 1.0,
        "std": 0.7,
    },

    "destination_concentration": {
        "mean": 0.70,
        "std": 0.20,
    },

    "average_packet_size": {
        "mean": 500.0,
        "std": 250.0,
    },

    "average_inter_arrival": {
        "mean": 0.10,
        "std": 0.10,
    },

    "tcp_ratio": {
        "mean": 0.70,
        "std": 0.30,
    },

    "udp_ratio": {
        "mean": 0.30,
        "std": 0.30,
    },
}


# --------------------------------------------------
# Feature weights
# --------------------------------------------------

FEATURE_WEIGHTS = {
    "packets_per_second": 1.0,
    "bytes_per_second": 1.0,
    "syn_ratio": 1.2,
    "unique_destination_ips": 0.8,
    "unique_destination_ports": 1.2,
    "source_ip_entropy": 0.8,
    "destination_concentration": 0.8,
    "average_packet_size": 0.8,
    "average_inter_arrival": 1.0,
    "tcp_ratio": 0.5,
    "udp_ratio": 0.5,
}


def _safe_float(value):
    """
    Convert a value to a finite float.
    """

    try:
        value = float(value)

    except (TypeError, ValueError):
        return None

    if not isfinite(value):
        return None

    return value


def _normalized_deviation(
    value,
    baseline_mean,
    baseline_std,
):
    """
    Calculate normalized deviation from the baseline.

    A deviation of:
        0 = matches baseline
        1 = one standard deviation away
        2 = two standard deviations away
        etc.

    A minimum standard deviation is used to avoid
    division by zero for very stable features.
    """

    value = _safe_float(value)
    baseline_mean = _safe_float(baseline_mean)
    baseline_std = _safe_float(baseline_std)

    if (
        value is None
        or baseline_mean is None
        or baseline_std is None
    ):
        return 0.0

    baseline_std = max(
        abs(baseline_std),
        1e-6,
    )

    return abs(
        value - baseline_mean
    ) / baseline_std


def _deviation_to_score(deviation):
    """
    Convert normalized deviation into a 0-1 score.

    0 deviation -> 0
    1 std        -> ~0.39
    2 std        -> ~0.63
    3 std        -> ~0.78
    5+ std       -> ~0.92+
    """

    if deviation <= 0:
        return 0.0

    score = (
        deviation
        / (1.0 + deviation)
    )

    return min(
        max(score, 0.0),
        1.0,
    )


def detect_baseline_anomaly(
    behavior,
    baseline=None,
):
    """
    Compare a behavioral vector against a normal-traffic
    baseline.

    Returns:
        {
            "anomaly_score": 0-1,
            "classification": ...,
            "severity": ...,
            "confidence": ...,
            "evidence": [...],
            "feature_scores": {...}
        }
    """

    if baseline is None:
        baseline = DEFAULT_BASELINE

    feature_scores = {}
    evidence = []

    weighted_score = 0.0
    total_weight = 0.0

    for feature_name, baseline_data in baseline.items():

        if feature_name not in behavior:
            continue

        value = behavior[
            feature_name
        ]

        deviation = _normalized_deviation(
            value,
            baseline_data["mean"],
            baseline_data["std"],
        )

        score = _deviation_to_score(
            deviation
        )

        weight = FEATURE_WEIGHTS.get(
            feature_name,
            1.0,
        )

        weighted_score += (
            score * weight
        )

        total_weight += weight

        feature_scores[
            feature_name
        ] = round(
            score,
            4,
        )

        # ------------------------------------------
        # Explanation evidence
        # ------------------------------------------

        if deviation >= 2.0:

            direction = (
                "above"
                if value > baseline_data["mean"]
                else "below"
            )

            evidence.append(
                {
                    "feature": feature_name,
                    "value": value,
                    "baseline_mean": (
                        baseline_data["mean"]
                    ),
                    "deviation": round(
                        deviation,
                        2,
                    ),
                    "description": (
                        f"{feature_name} is "
                        f"{direction} the normal "
                        f"baseline"
                    ),
                }
            )

    # ----------------------------------------------
    # Final score
    # ----------------------------------------------

    if total_weight > 0:

        anomaly_score = (
            weighted_score
            / total_weight
        )

    else:

        anomaly_score = 0.0

    anomaly_score = min(
        max(anomaly_score, 0.0),
        1.0,
    )

    # ----------------------------------------------
    # Classification
    # ----------------------------------------------

    if anomaly_score >= 0.75:

        classification = (
            "High Behavioral Anomaly"
        )

        severity = "HIGH"
        confidence = 0.90

    elif anomaly_score >= 0.50:

        classification = (
            "Suspicious Behavioral Deviation"
        )

        severity = "MEDIUM"
        confidence = 0.70

    elif anomaly_score >= 0.25:

        classification = (
            "Mild Behavioral Deviation"
        )

        severity = "LOW"
        confidence = 0.50

    else:

        classification = (
            "Normal Behavioral Pattern"
        )

        severity = "INFO"
        confidence = 0.10

    return {
        "anomaly_score": round(
            anomaly_score,
            4,
        ),

        "classification": classification,

        "severity": severity,

        "confidence": confidence,

        "evidence": evidence,

        "feature_scores": feature_scores,
    }


def explain_baseline_result(
    result,
):
    """
    Produce a short human-readable explanation
    for the dashboard.
    """

    if not result["evidence"]:

        return (
            "Behavior is within the expected "
            "normal-traffic baseline."
        )

    explanations = []

    for item in result["evidence"]:

        explanations.append(
            item["description"]
            + f" ({item['deviation']}σ)."
        )

    return " | ".join(
        explanations
    )


if __name__ == "__main__":

    print(
        "Baseline anomaly detector ready."
    )

