"""
SIH 2026 - Multi-Sample Controlled Experiment

Compares:

    BEFORE
        Baseline detector only

    AFTER
        Baseline detector + Ghost Response Model
        + Score Fusion

The experiment uses controlled synthetic behavioral
vectors. It does NOT claim real-world accuracy.

Test categories:

    1. Normal behavior
    2. Mild deviation
    3. Suspicious traffic
    4. SYN-heavy behavior
    5. Port-scan-like behavior
    6. High-rate behavior
    7. Low destination concentration
    8. Combined abnormal behavior

The purpose is to observe how the two-stage
architecture behaves across multiple controlled
behavioral patterns.
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


# --------------------------------------------------
# Controlled behavioral test cases
# --------------------------------------------------

TEST_CASES = [

    (
        "Normal 1",
        {
            "packets_per_second": 10.0,
            "bytes_per_second": 5000.0,
            "syn_ratio": 0.10,
            "unique_destination_ips": 3.0,
            "unique_destination_ports": 5.0,
            "destination_concentration": 0.70,
            "average_packet_size": 500.0,
            "average_inter_arrival": 0.10,
            "source_ip_entropy": 1.0,
        },
        "normal",
    ),

    (
        "Normal 2",
        {
            "packets_per_second": 12.0,
            "bytes_per_second": 6000.0,
            "syn_ratio": 0.12,
            "unique_destination_ips": 4.0,
            "unique_destination_ports": 6.0,
            "destination_concentration": 0.65,
            "average_packet_size": 550.0,
            "average_inter_arrival": 0.09,
            "source_ip_entropy": 1.1,
        },
        "normal",
    ),

    (
        "Normal 3",
        {
            "packets_per_second": 8.0,
            "bytes_per_second": 4200.0,
            "syn_ratio": 0.08,
            "unique_destination_ips": 2.0,
            "unique_destination_ports": 4.0,
            "destination_concentration": 0.75,
            "average_packet_size": 480.0,
            "average_inter_arrival": 0.12,
            "source_ip_entropy": 0.9,
        },
        "normal",
    ),

    (
        "Mild Deviation 1",
        {
            "packets_per_second": 20.0,
            "bytes_per_second": 10000.0,
            "syn_ratio": 0.20,
            "unique_destination_ips": 6.0,
            "unique_destination_ports": 10.0,
            "destination_concentration": 0.50,
            "average_packet_size": 700.0,
            "average_inter_arrival": 0.05,
            "source_ip_entropy": 1.5,
        },
        "mild",
    ),

    (
        "Mild Deviation 2",
        {
            "packets_per_second": 18.0,
            "bytes_per_second": 8500.0,
            "syn_ratio": 0.18,
            "unique_destination_ips": 5.0,
            "unique_destination_ports": 9.0,
            "destination_concentration": 0.55,
            "average_packet_size": 650.0,
            "average_inter_arrival": 0.06,
            "source_ip_entropy": 1.4,
        },
        "mild",
    ),

    (
        "Suspicious 1",
        {
            "packets_per_second": 50.0,
            "bytes_per_second": 25000.0,
            "syn_ratio": 0.60,
            "unique_destination_ips": 12.0,
            "unique_destination_ports": 25.0,
            "destination_concentration": 0.20,
            "average_packet_size": 900.0,
            "average_inter_arrival": 0.015,
            "source_ip_entropy": 2.5,
        },
        "suspicious",
    ),

    (
        "Suspicious 2",
        {
            "packets_per_second": 70.0,
            "bytes_per_second": 35000.0,
            "syn_ratio": 0.75,
            "unique_destination_ips": 15.0,
            "unique_destination_ports": 35.0,
            "destination_concentration": 0.15,
            "average_packet_size": 1000.0,
            "average_inter_arrival": 0.010,
            "source_ip_entropy": 3.0,
        },
        "suspicious",
    ),

    (
        "SYN Heavy",
        {
            "packets_per_second": 40.0,
            "bytes_per_second": 20000.0,
            "syn_ratio": 0.95,
            "unique_destination_ips": 8.0,
            "unique_destination_ports": 12.0,
            "destination_concentration": 0.30,
            "average_packet_size": 600.0,
            "average_inter_arrival": 0.02,
            "source_ip_entropy": 2.0,
        },
        "attack-like",
    ),

    (
        "Port Scan Like",
        {
            "packets_per_second": 35.0,
            "bytes_per_second": 12000.0,
            "syn_ratio": 0.80,
            "unique_destination_ips": 10.0,
            "unique_destination_ports": 45.0,
            "destination_concentration": 0.10,
            "average_packet_size": 400.0,
            "average_inter_arrival": 0.025,
            "source_ip_entropy": 2.8,
        },
        "attack-like",
    ),

    (
        "High Rate",
        {
            "packets_per_second": 90.0,
            "bytes_per_second": 45000.0,
            "syn_ratio": 0.40,
            "unique_destination_ips": 10.0,
            "unique_destination_ports": 15.0,
            "destination_concentration": 0.25,
            "average_packet_size": 800.0,
            "average_inter_arrival": 0.008,
            "source_ip_entropy": 2.2,
        },
        "attack-like",
    ),

    (
        "Low Concentration",
        {
            "packets_per_second": 30.0,
            "bytes_per_second": 15000.0,
            "syn_ratio": 0.35,
            "unique_destination_ips": 25.0,
            "unique_destination_ports": 30.0,
            "destination_concentration": 0.05,
            "average_packet_size": 700.0,
            "average_inter_arrival": 0.03,
            "source_ip_entropy": 4.0,
        },
        "attack-like",
    ),

    (
        "Combined Abnormal",
        {
            "packets_per_second": 100.0,
            "bytes_per_second": 50000.0,
            "syn_ratio": 1.0,
            "unique_destination_ips": 20.0,
            "unique_destination_ports": 50.0,
            "destination_concentration": 0.05,
            "average_packet_size": 1200.0,
            "average_inter_arrival": 0.005,
            "source_ip_entropy": 4.0,
        },
        "attack-like",
    ),
]


def run_case(behavior):
    """
    Run baseline, Ghost, and fused detection.
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
    expected_category,
    baseline,
    ghost,
    fused,
):
    """
    Print one experiment result.
    """

    print()
    print("-" * 75)
    print(name)
    print("-" * 75)

    print(
        f"Expected category : "
        f"{expected_category}"
    )

    print(
        f"Baseline score    : "
        f"{baseline['anomaly_score']:.4f}"
    )

    print(
        f"Ghost consistency : "
        f"{ghost['ghost_consistency']:.4f}"
    )

    print(
        f"Ghost deviation   : "
        f"{ghost['counterfactual_deviation']:.4f}"
    )

    print(
        f"Final score       : "
        f"{fused['final_threat_score']:.4f}"
    )

    print(
        f"Before class      : "
        f"{baseline['classification']}"
    )

    print(
        f"After class       : "
        f"{fused['classification']}"
    )


def main():

    print("=" * 75)
    print("       SIH 2026 MULTI-SAMPLE CONTROLLED EXPERIMENT")
    print("=" * 75)

    results = []

    for (
        name,
        behavior,
        expected_category,
    ) in TEST_CASES:

        baseline, ghost, fused = run_case(
            behavior
        )

        print_case(
            name,
            expected_category,
            baseline,
            ghost,
            fused,
        )

        results.append(
            {
                "name": name,
                "category": expected_category,
                "baseline": float(
                    baseline["anomaly_score"]
                ),
                "ghost_consistency": float(
                    ghost["ghost_consistency"]
                ),
                "ghost_deviation": float(
                    ghost[
                        "counterfactual_deviation"
                    ]
                ),
                "final": float(
                    fused["final_threat_score"]
                ),
            }
        )

    # --------------------------------------------------
    # Group analysis
    # --------------------------------------------------

    normal_results = [
        item
        for item in results
        if item["category"] == "normal"
    ]

    suspicious_results = [
        item
        for item in results
        if item["category"] in (
            "suspicious",
            "attack-like",
        )
    ]

    normal_baseline_avg = (
        sum(
            item["baseline"]
            for item in normal_results
        )
        / len(normal_results)
    )

    normal_final_avg = (
        sum(
            item["final"]
            for item in normal_results
        )
        / len(normal_results)
    )

    suspicious_baseline_avg = (
        sum(
            item["baseline"]
            for item in suspicious_results
        )
        / len(suspicious_results)
    )

    suspicious_final_avg = (
        sum(
            item["final"]
            for item in suspicious_results
        )
        / len(suspicious_results)
    )

    baseline_separation = (
        suspicious_baseline_avg
        - normal_baseline_avg
    )

    final_separation = (
        suspicious_final_avg
        - normal_final_avg
    )

    # --------------------------------------------------
    # Ghost consistency analysis
    # --------------------------------------------------

    normal_ghost_avg = (
        sum(
            item["ghost_consistency"]
            for item in normal_results
        )
        / len(normal_results)
    )

    suspicious_ghost_avg = (
        sum(
            item["ghost_consistency"]
            for item in suspicious_results
        )
        / len(suspicious_results)
    )

    # --------------------------------------------------
    # Summary
    # --------------------------------------------------

    print()
    print("=" * 75)
    print("GROUP ANALYSIS")
    print("=" * 75)

    print()
    print(
        f"Normal samples: "
        f"{len(normal_results)}"
    )

    print(
        f"Suspicious/attack-like samples: "
        f"{len(suspicious_results)}"
    )

    print()
    print(
        f"Average baseline score - normal: "
        f"{normal_baseline_avg:.4f}"
    )

    print(
        f"Average final score - normal: "
        f"{normal_final_avg:.4f}"
    )

    print()
    print(
        f"Average baseline score - "
        f"suspicious/attack-like: "
        f"{suspicious_baseline_avg:.4f}"
    )

    print(
        f"Average final score - "
        f"suspicious/attack-like: "
        f"{suspicious_final_avg:.4f}"
    )

    print()
    print(
        f"Baseline separation: "
        f"{baseline_separation:.4f}"
    )

    print(
        f"Baseline + Ghost separation: "
        f"{final_separation:.4f}"
    )

    print()
    print(
        f"Average Ghost consistency - normal: "
        f"{normal_ghost_avg:.4f}"
    )

    print(
        f"Average Ghost consistency - "
        f"suspicious/attack-like: "
        f"{suspicious_ghost_avg:.4f}"
    )

    # --------------------------------------------------
    # Validation
    # --------------------------------------------------

    assert (
        normal_ghost_avg
        >
        suspicious_ghost_avg
    )

    assert (
        final_separation
        >=
        baseline_separation
    )

    assert (
        normal_final_avg
        <
        suspicious_final_avg
    )

    print()
    print("=" * 75)
    print("Multi-sample controlled experiment passed.")
    print("=" * 75)


if __name__ == "__main__":
    main()
