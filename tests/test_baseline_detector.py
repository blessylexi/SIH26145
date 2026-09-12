from src.detection.baseline_detector import (
    detect_baseline_anomaly,
    explain_baseline_result,
)


def create_normal_behavior():

    return {
        "packets_per_second": 10.0,
        "bytes_per_second": 5000.0,
        "syn_ratio": 0.10,
        "unique_destination_ips": 3,
        "unique_destination_ports": 5,
        "source_ip_entropy": 1.0,
        "destination_concentration": 0.70,
        "average_packet_size": 500.0,
        "average_inter_arrival": 0.10,
        "tcp_ratio": 0.70,
        "udp_ratio": 0.30,
    }


def create_suspicious_behavior():

    return {
        "packets_per_second": 100.0,
        "bytes_per_second": 50000.0,
        "syn_ratio": 1.0,
        "unique_destination_ips": 20,
        "unique_destination_ports": 50,
        "source_ip_entropy": 4.0,
        "destination_concentration": 0.05,
        "average_packet_size": 1200.0,
        "average_inter_arrival": 0.005,
        "tcp_ratio": 0.95,
        "udp_ratio": 0.05,
    }


def main():

    print("========================================")
    print("       BASELINE DETECTOR TEST")
    print("========================================")

    normal_behavior = create_normal_behavior()

    normal_result = detect_baseline_anomaly(
        normal_behavior
    )

    print("\nNORMAL TRAFFIC")
    print("----------------")

    print(
        "Anomaly score:",
        normal_result["anomaly_score"],
    )

    print(
        "Classification:",
        normal_result["classification"],
    )

    print(
        "Severity:",
        normal_result["severity"],
    )

    print(
        "Confidence:",
        normal_result["confidence"],
    )

    print(
        "Explanation:",
        explain_baseline_result(
            normal_result
        ),
    )

    suspicious_behavior = (
        create_suspicious_behavior()
    )

    suspicious_result = (
        detect_baseline_anomaly(
            suspicious_behavior
        )
    )

    print("\nSUSPICIOUS TRAFFIC")
    print("-------------------")

    print(
        "Anomaly score:",
        suspicious_result["anomaly_score"],
    )

    print(
        "Classification:",
        suspicious_result["classification"],
    )

    print(
        "Severity:",
        suspicious_result["severity"],
    )

    print(
        "Confidence:",
        suspicious_result["confidence"],
    )

    print(
        "Explanation:",
        explain_baseline_result(
            suspicious_result
        ),
    )

    print("\nEvidence:")

    for item in suspicious_result[
        "evidence"
    ]:

        print(
            f"- {item['description']} "
            f"| deviation={item['deviation']}s"
        )

    assert (
        0.0
        <= normal_result["anomaly_score"]
        <= 1.0
    )

    assert (
        0.0
        <= suspicious_result["anomaly_score"]
        <= 1.0
    )

    assert (
        normal_result["anomaly_score"]
        < suspicious_result["anomaly_score"]
    )

    assert (
        len(
            suspicious_result["evidence"]
        )
        > 0
    )

    print("\n========================================")
    print(
        "Baseline detector test passed."
    )
    print("========================================")


if __name__ == "__main__":
    main()
