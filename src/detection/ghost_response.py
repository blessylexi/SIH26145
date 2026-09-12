from math import exp


DEFAULT_GHOST_PROFILE = {
    "packets_per_second": {
        "expected": 10.0,
        "tolerance": 10.0,
    },
    "bytes_per_second": {
        "expected": 5000.0,
        "tolerance": 5000.0,
    },
    "syn_ratio": {
        "expected": 0.10,
        "tolerance": 0.20,
    },
    "unique_destination_ips": {
        "expected": 3.0,
        "tolerance": 4.0,
    },
    "unique_destination_ports": {
        "expected": 5.0,
        "tolerance": 8.0,
    },
    "destination_concentration": {
        "expected": 0.70,
        "tolerance": 0.40,
    },
    "average_packet_size": {
        "expected": 500.0,
        "tolerance": 500.0,
    },
    "average_inter_arrival": {
        "expected": 0.10,
        "tolerance": 0.20,
    },
}


def _safe_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _normalized_deviation(value, expected, tolerance):
    value = _safe_float(value)
    expected = _safe_float(expected)
    tolerance = abs(_safe_float(tolerance))

    if tolerance <= 0:
        return 0.0

    return abs(value - expected) / tolerance


def _deviation_to_consistency(deviation):
    deviation = max(0.0, _safe_float(deviation))
    return max(0.0, min(1.0, exp(-deviation)))


def ghost_response(behavior, ghost_profile=None):
    """
    Compare observed behavior with expected
    normal interaction behavior.
    """

    if ghost_profile is None:
        ghost_profile = DEFAULT_GHOST_PROFILE

    feature_results = {}
    evidence = []

    total_consistency = 0.0
    total_deviation = 0.0
    feature_count = 0

    for feature, config in ghost_profile.items():

        if feature not in behavior:
            continue

        observed = _safe_float(
            behavior.get(feature)
        )

        expected = _safe_float(
            config.get("expected")
        )

        tolerance = _safe_float(
            config.get("tolerance")
        )

        deviation = _normalized_deviation(
            observed,
            expected,
            tolerance,
        )

        consistency = _deviation_to_consistency(
            deviation
        )

        counterfactual_deviation = (
            1.0 - consistency
        )

        feature_results[feature] = {
            "observed": observed,
            "expected": expected,
            "tolerance": tolerance,
            "deviation": round(
                deviation,
                4,
            ),
            "consistency": round(
                consistency,
                4,
            ),
            "counterfactual_deviation": round(
                counterfactual_deviation,
                4,
            ),
        }

        total_consistency += consistency
        total_deviation += counterfactual_deviation
        feature_count += 1

        if counterfactual_deviation >= 0.70:

            direction = (
                "above"
                if observed > expected
                else "below"
            )

            evidence.append(
                {
                    "feature": feature,
                    "observed": observed,
                    "expected": expected,
                    "counterfactual_deviation": round(
                        counterfactual_deviation,
                        4,
                    ),
                    "description": (
                        f"{feature} is {direction} "
                        "the expected interaction pattern"
                    ),
                }
            )

    if feature_count > 0:

        ghost_consistency = (
            total_consistency
            / feature_count
        )

        counterfactual_deviation = (
            total_deviation
            / feature_count
        )

    else:

        ghost_consistency = 1.0
        counterfactual_deviation = 0.0

    ghost_consistency = max(
        0.0,
        min(
            1.0,
            ghost_consistency,
        ),
    )

    counterfactual_deviation = max(
        0.0,
        min(
            1.0,
            counterfactual_deviation,
        ),
    )

    if counterfactual_deviation >= 0.70:

        classification = (
            "Strong Ghost Inconsistency"
        )

    elif counterfactual_deviation >= 0.40:

        classification = (
            "Moderate Ghost Inconsistency"
        )

    elif counterfactual_deviation >= 0.20:

        classification = (
            "Mild Ghost Deviation"
        )

    else:

        classification = (
            "Ghost Consistent"
        )

    return {
        "ghost_consistency": round(
            ghost_consistency,
            4,
        ),
        "counterfactual_deviation": round(
            counterfactual_deviation,
            4,
        ),
        "classification": classification,
        "feature_results": feature_results,
        "evidence": evidence,
    }


def explain_ghost_result(result):

    consistency = result.get(
        "ghost_consistency",
        1.0,
    )

    deviation = result.get(
        "counterfactual_deviation",
        0.0,
    )

    classification = result.get(
        "classification",
        "Unknown",
    )

    evidence = result.get(
        "evidence",
        [],
    )

    if not evidence:

        return (
            f"{classification}. "
            f"Observed interaction is consistent "
            f"with expected behavior "
            f"(consistency={consistency:.2f}, "
            f"deviation={deviation:.2f})."
        )

    descriptions = [
        item["description"]
        for item in evidence
    ]

    return (
        f"{classification}. "
        f"The observed interaction differs "
        f"from the expected behavioral response "
        f"(consistency={consistency:.2f}, "
        f"deviation={deviation:.2f}). "
        f"Key deviations: "
        + "; ".join(descriptions)
        + "."
    )


if __name__ == "__main__":

    print(
        "Ghost Response Model ready."
    )
