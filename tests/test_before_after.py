"""
SIH 2026 - Before vs After Experiment

Compares:

    BEFORE
        Baseline detector only

    AFTER
        Baseline detector + Ghost Response Model
        + Score Fusion

The experiment uses controlled behavioral vectors
rather than fabricated performance claims.
"""

from src.detection.baseline_detector import (
    detect_baseline_anomaly,
)

from src.detection.ghost_response import (
    ghost_response,
)

from src.detection.score_fusion import (
    fuse_scores,
)


def make_normal_behavior():
    """
    Behavior close to the expected normal profile.
    """

    return {
        "packets_per_second": 10.0,
        "bytes_per_second": 5000.0,
        "syn_ratio": 0.10,
        "unique_destination_ips": 3.0,
        "unique_destination_ports": 5.0,
        "destination_concentration": 0.70,
        "average_packet_size": 500.0,
        "average_inter_arrival": 0.10,
        "source_ip_entropy": 1.0,
    }


def make_suspicious_behavior():
    """
    Strongly abnormal interaction pattern.
    """

    return {
        "packets_per_second": 100.0,
        "bytes_per_second": 50000.0,
        "syn_ratio": 1.0,
        "unique_destination_ips": 20.0,
        "unique_destination_ports": 50.0,
        "destination_concentration": 0.05,
        "average_packet_size": 1200.0,
        "average_inter_arrival": 0.005,
        "source_ip_entropy": 4.0,
    }


def run_detection(behavior):
    """
    Run both detection layers on one behavior vector.
    """

    baseline = detect_baseline_anomaly(
        behavior
    )

    ghost = ghost_response(
        behavior
    )

    fused = fuse_scores(
        baseline,
        ghost
    )

    return baseline, ghost, fused


def print_case(
    name,
    baseline,
    ghost,
    fused,
):
    print()
    print("=" * 55)
    print(name)
    print("=" * 55)

    print()
    print("BEFORE - BASELINE ONLY")
    print("-----------------------")

    print(
        f"Baseline score: "
        f"{baseline.get('anomaly_score', 0.0)}"
    )

    print(
        f"Classification: "
        f"{baseline.get('classification', 'Unknown')}"
    )

    print(
        f"Severity: "
        f"{baseline.get('severity', 'UNKNOWN')}"
    )

    print()
    print("AFTER - BASELINE + GHOST")
    print("------------------------")

    print(
        f"Baseline score: "
        f"{fused['baseline_score']}"
    )

    print(
        f"Ghost deviation: "
        f"{fused['ghost_deviation']}"
    )

    print(
        f"Final threat score: "
        f"{fused['final_threat_score']}"
    )

    print(
        f"Classification: "
        f"{fused['classification']}"
    )

    print(
        f"Severity: "
        f"{fused['severity']}"
    )

    print()
    print(
        f"Ghost consistency: "
        f"{ghost['ghost_consistency']}"
    )


def main():

    print("=" * 55)
    print("       SIH 2026 BEFORE vs AFTER EXPERIMENT")
    print("=" * 55)

    # --------------------------------------------------
    # NORMAL CASE
    # --------------------------------------------------

    normal_behavior = make_normal_behavior()

    (
        normal_baseline,
        normal_ghost,
        normal_fused,
    ) = run_detection(
        normal_behavior
    )

    print_case(
        "NORMAL TRAFFIC",
        normal_baseline,
        normal_ghost,
        normal_fused,
    )

    # --------------------------------------------------
    # SUSPICIOUS CASE
    # --------------------------------------------------

    suspicious_behavior = (
        make_suspicious_behavior()
    )

    (
        suspicious_baseline,
        suspicious_ghost,
        suspicious_fused,
    ) = run_detection(
        suspicious_behavior
    )

    print_case(
        "SUSPICIOUS TRAFFIC",
        suspicious_baseline,
        suspicious_ghost,
        suspicious_fused,
    )

    # --------------------------------------------------
    # COMPARISON
    # --------------------------------------------------

    baseline_normal = float(
        normal_baseline.get(
            "anomaly_score",
            0.0,
        )
    )

    baseline_suspicious = float(
        suspicious_baseline.get(
            "anomaly_score",
            0.0,
        )
    )

    fused_normal = float(
        normal_fused[
            "final_threat_score"
        ]
    )

    fused_suspicious = float(
        suspicious_fused[
            "final_threat_score"
        ]
    )

    baseline_separation = (
        baseline_suspicious
        - baseline_normal
    )

    fused_separation = (
        fused_suspicious
        - fused_normal
    )

    print()
    print("=" * 55)
    print("EXPERIMENT COMPARISON")
    print("=" * 55)

    print()
    print("Baseline-only separation:")
    print(
        f"{baseline_separation:.4f}"
    )

    print()
    print("Baseline + Ghost separation:")
    print(
        f"{fused_separation:.4f}"
    )

    print()
    print("Normal traffic:")
    print(
        f"  Before = {baseline_normal:.4f}"
    )
    print(
        f"  After  = {fused_normal:.4f}"
    )

    print()
    print("Suspicious traffic:")
    print(
        f"  Before = {baseline_suspicious:.4f}"
    )
    print(
        f"  After  = {fused_suspicious:.4f}"
    )

    # --------------------------------------------------
    # VALIDATION
    # --------------------------------------------------

    assert (
        normal_ghost["ghost_consistency"]
        >
        suspicious_ghost["ghost_consistency"]
    )

    assert (
        normal_fused["final_threat_score"]
        <
        suspicious_fused["final_threat_score"]
    )

    assert (
        fused_suspicious
        >
        fused_normal
    )

    print()
    print("=" * 55)
    print("Before vs After experiment passed.")
    print("=" * 55)


if __name__ == "__main__":
    main()
