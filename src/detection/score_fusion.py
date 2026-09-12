"""
SIH 2026 - Score Fusion

Combines:
    1. Baseline anomaly score
    2. Ghost counterfactual deviation

into one final threat score.

The purpose is to provide a single explainable
threat score for the SIH prototype.
"""


def _clamp(value, minimum=0.0, maximum=1.0):
    """
    Keep a numeric value inside the given range.
    """

    try:
        value = float(value)
    except (TypeError, ValueError):
        value = 0.0

    return max(
        minimum,
        min(maximum, value),
    )


def _normalize_baseline_score(score):
    """
    Convert the existing baseline detector score
    into a 0-1 range.

    The baseline detector currently produces scores
    on a 0-1 scale, so this mainly provides safety.
    """

    return _clamp(score)


def _get_severity(threat_score):
    """
    Convert the final threat score into a
    human-readable severity.
    """

    if threat_score >= 0.75:
        return "HIGH"

    if threat_score >= 0.45:
        return "MEDIUM"

    if threat_score >= 0.20:
        return "LOW"

    return "INFO"


def _get_classification(threat_score):
    """
    Convert the final threat score into a
    human-readable classification.
    """

    if threat_score >= 0.75:
        return "High Threat"

    if threat_score >= 0.45:
        return "Moderate Threat"

    if threat_score >= 0.20:
        return "Low Suspicion"

    return "Normal Behavior"


def _build_evidence(
    baseline_result,
    ghost_result,
):
    """
    Combine evidence from both detection layers.
    """

    evidence = []

    baseline_evidence = (
        baseline_result.get(
            "evidence",
            [],
        )
    )

    for item in baseline_evidence:

        if isinstance(item, dict):

            description = item.get(
                "description",
                item.get(
                    "feature",
                    "Baseline anomaly detected",
                ),
            )

            evidence.append(
                {
                    "source": "Baseline",
                    "description": description,
                    "score": item.get(
                        "deviation",
                        None,
                    ),
                }
            )

        else:

            evidence.append(
                {
                    "source": "Baseline",
                    "description": str(item),
                    "score": None,
                }
            )

    ghost_evidence = (
        ghost_result.get(
            "evidence",
            [],
        )
    )

    for item in ghost_evidence:

        if isinstance(item, dict):

            description = item.get(
                "description",
                item.get(
                    "feature",
                    "Ghost inconsistency detected",
                ),
            )

            evidence.append(
                {
                    "source": "Ghost Response",
                    "description": description,
                    "score": item.get(
                        "counterfactual_deviation",
                        None,
                    ),
                }
            )

        else:

            evidence.append(
                {
                    "source": "Ghost Response",
                    "description": str(item),
                    "score": None,
                }
            )

    return evidence


def _build_explanation(
    classification,
    threat_score,
    baseline_score,
    ghost_deviation,
    evidence,
):
    """
    Build the human-readable WHY explanation.
    """

    if not evidence:

        return (
            f"{classification}. "
            f"Final threat score={threat_score:.2f}. "
            f"Baseline anomaly={baseline_score:.2f}. "
            f"Ghost deviation={ghost_deviation:.2f}. "
            "No significant behavioral deviations "
            "were detected."
        )

    baseline_count = sum(
        1
        for item in evidence
        if item["source"] == "Baseline"
    )

    ghost_count = sum(
        1
        for item in evidence
        if item["source"] == "Ghost Response"
    )

    reasons = []

    if baseline_count > 0:

        reasons.append(
            f"{baseline_count} baseline "
            "behavioral deviation(s)"
        )

    if ghost_count > 0:

        reasons.append(
            f"{ghost_count} Ghost behavioral "
            "inconsistency/inconsistencies"
        )

    reason_text = " and ".join(
        reasons
    )

    return (
        f"{classification}. "
        f"Final threat score={threat_score:.2f}. "
        f"Baseline anomaly={baseline_score:.2f}. "
        f"Ghost deviation={ghost_deviation:.2f}. "
        f"Detection was supported by "
        f"{reason_text}."
    )


def fuse_scores(
    baseline_result,
    ghost_result,
    baseline_weight=0.55,
    ghost_weight=0.45,
):
    """
    Combine baseline anomaly and Ghost deviation.

    Default weighting:

        Baseline = 55%
        Ghost    = 45%

    The slightly higher baseline weight keeps the
    existing detector as the primary signal while
    allowing the Ghost Response Model to contribute
    a meaningful behavioral perspective.

    Returns a structured result suitable for:
        - dashboard
        - alert engine
        - WHY explanation
        - before/after experiment
    """

    baseline_score = _normalize_baseline_score(
        baseline_result.get(
            "score",
            baseline_result.get(
                "anomaly_score",
                0.0,
            ),
        )
    )

    ghost_deviation = _clamp(
        ghost_result.get(
            "counterfactual_deviation",
            0.0,
        )
    )

    try:
        baseline_weight = float(
            baseline_weight
        )
    except (TypeError, ValueError):

        baseline_weight = 0.55

    try:
        ghost_weight = float(
            ghost_weight
        )
    except (TypeError, ValueError):

        ghost_weight = 0.45

    total_weight = (
        baseline_weight
        + ghost_weight
    )

    if total_weight <= 0:

        baseline_weight = 0.55
        ghost_weight = 0.45
        total_weight = 1.0

    baseline_weight = (
        baseline_weight
        / total_weight
    )

    ghost_weight = (
        ghost_weight
        / total_weight
    )

    final_threat_score = (
        baseline_score
        * baseline_weight
        +
        ghost_deviation
        * ghost_weight
    )

    final_threat_score = _clamp(
        final_threat_score
    )

    classification = _get_classification(
        final_threat_score
    )

    severity = _get_severity(
        final_threat_score
    )

    evidence = _build_evidence(
        baseline_result,
        ghost_result,
    )

    explanation = _build_explanation(
        classification,
        final_threat_score,
        baseline_score,
        ghost_deviation,
        evidence,
    )

    return {
        "final_threat_score": round(
            final_threat_score,
            4,
        ),
        "baseline_score": round(
            baseline_score,
            4,
        ),
        "ghost_deviation": round(
            ghost_deviation,
            4,
        ),
        "baseline_weight": round(
            baseline_weight,
            4,
        ),
        "ghost_weight": round(
            ghost_weight,
            4,
        ),
        "classification": classification,
        "severity": severity,
        "evidence": evidence,
        "explanation": explanation,
    }


if __name__ == "__main__":

    print(
        "SIH Score Fusion module ready."
    )
