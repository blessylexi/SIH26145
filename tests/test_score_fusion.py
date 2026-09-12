"""
Test for SIH 2026 Score Fusion.
"""

from src.detection.score_fusion import (
    fuse_scores,
)


def print_result(title, result):

    print()
    print(title)
    print("-" * len(title))

    print(
        f"Final threat score: "
        f"{result['final_threat_score']}"
    )

    print(
        f"Baseline score: "
        f"{result['baseline_score']}"
    )

    print(
        f"Ghost deviation: "
        f"{result['ghost_deviation']}"
    )

    print(
        f"Classification: "
        f"{result['classification']}"
    )

    print(
        f"Severity: "
        f"{result['severity']}"
    )

    print(
        f"Explanation: "
        f"{result['explanation']}"
    )

    print()
    print("Evidence:")

    if not result["evidence"]:

        print("- None")

    else:

        for item in result["evidence"]:

            print(
                f"- [{item['source']}] "
                f"{item['description']}"
            )


def main():

    print("=" * 40)
    print("       SCORE FUSION TEST")
    print("=" * 40)

    # ------------------------------------------
    # NORMAL TRAFFIC
    # ------------------------------------------

    normal_baseline = {
        "score": 0.0,
        "classification": (
            "Normal Behavioral Pattern"
        ),
        "severity": "INFO",
        "confidence": 0.1,
        "evidence": [],
    }

    normal_ghost = {
        "ghost_consistency": 1.0,
        "counterfactual_deviation": 0.0,
        "classification": (
            "Ghost Consistent"
        ),
        "evidence": [],
    }

    normal_result = fuse_scores(
        normal_baseline,
        normal_ghost,
    )

    print_result(
        "NORMAL TRAFFIC",
        normal_result,
    )

    assert (
        normal_result["final_threat_score"]
        == 0.0
    )

    assert (
        normal_result["classification"]
        == "Normal Behavior"
    )

    assert (
        normal_result["severity"]
        == "INFO"
    )

    # ------------------------------------------
    # SUSPICIOUS TRAFFIC
    # ------------------------------------------

    suspicious_baseline = {
        "score": 0.79,
        "classification": (
            "High Behavioral Anomaly"
        ),
        "severity": "HIGH",
        "confidence": 0.9,
        "evidence": [
            {
                "feature": "packets_per_second",
                "description": (
                    "packets_per_second is above "
                    "the normal baseline"
                ),
                "deviation": 18.0,
            },
            {
                "feature": "syn_ratio",
                "description": (
                    "syn_ratio is above "
                    "the normal baseline"
                ),
                "deviation": 9.0,
            },
        ],
    }

    suspicious_ghost = {
        "ghost_consistency": 0.1368,
        "counterfactual_deviation": 0.8632,
        "classification": (
            "Strong Ghost Inconsistency"
        ),
        "evidence": [
            {
                "feature": "packets_per_second",
                "description": (
                    "packets_per_second is above "
                    "the expected interaction pattern"
                ),
                "counterfactual_deviation": 0.9999,
            },
            {
                "feature": "unique_destination_ports",
                "description": (
                    "unique_destination_ports is above "
                    "the expected interaction pattern"
                ),
                "counterfactual_deviation": 0.9964,
            },
        ],
    }

    suspicious_result = fuse_scores(
        suspicious_baseline,
        suspicious_ghost,
    )

    print_result(
        "SUSPICIOUS TRAFFIC",
        suspicious_result,
    )

    assert (
        suspicious_result["final_threat_score"]
        > normal_result["final_threat_score"]
    )

    assert (
        suspicious_result["final_threat_score"]
        > 0.70
    )

    assert (
        suspicious_result["classification"]
        == "High Threat"
    )

    assert (
        suspicious_result["severity"]
        == "HIGH"
    )

    assert (
        len(
            suspicious_result["evidence"]
        )
        > 0
    )

    # ------------------------------------------
    # GHOST-ONLY DEVIATION
    # ------------------------------------------

    ghost_only_baseline = {
        "score": 0.10,
        "classification": (
            "Normal Behavioral Pattern"
        ),
        "severity": "INFO",
        "confidence": 0.1,
        "evidence": [],
    }

    ghost_only_ghost = {
        "ghost_consistency": 0.30,
        "counterfactual_deviation": 0.70,
        "classification": (
            "Strong Ghost Inconsistency"
        ),
        "evidence": [
            {
                "feature": "syn_ratio",
                "description": (
                    "syn_ratio is above "
                    "the expected interaction pattern"
                ),
                "counterfactual_deviation": 0.90,
            }
        ],
    }

    ghost_only_result = fuse_scores(
        ghost_only_baseline,
        ghost_only_ghost,
    )

    print_result(
        "GHOST-ONLY DEVIATION",
        ghost_only_result,
    )

    assert (
        ghost_only_result["final_threat_score"]
        > ghost_only_baseline["score"]
    )

    print()
    print("=" * 40)
    print("Score Fusion test passed.")
    print("=" * 40)


if __name__ == "__main__":
    main()
