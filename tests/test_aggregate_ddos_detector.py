from src.detection.aggregate_ddos_detector import (
    detect_aggregate_ddos,
)


def main():

    normal_traffic = {
        "total_packets": 100,
        "packets_per_second": 100,
        "syns_per_second": 2,

        "syn_count": 2,
        "syn_ack_count": 2,
        "syn_ratio": 0.02,

        "unique_source_ips": 2,
        "unique_source_ports": 2,

        "source_ip_entropy": 1.0,
        "destination_concentration": 0.50,
    }

    suspicious_traffic = {
        "total_packets": 1000,
        "packets_per_second": 5000,
        "syns_per_second": 5000,

        "syn_count": 1000,
        "syn_ack_count": 0,
        "syn_ratio": 1.0,

        "unique_source_ips": 50,
        "unique_source_ports": 50,

        "source_ip_entropy": 5.0,
        "destination_concentration": 0.98,
    }

    print("========================================")
    print("     AGGREGATE DDoS DETECTOR TEST")
    print("========================================")

    print("\n[NORMAL TRAFFIC]")

    normal_result = detect_aggregate_ddos(
        normal_traffic
    )

    for key, value in normal_result.items():
        print(f"{key}: {value}")

    print("\n[SUSPICIOUS TRAFFIC]")

    suspicious_result = detect_aggregate_ddos(
        suspicious_traffic
    )

    for key, value in suspicious_result.items():
        print(f"{key}: {value}")

    assert (
        normal_result["threat_class"]
        == "No DDoS Detected"
    )

    assert (
        suspicious_result["threat_class"]
        == "DDoS / SYN-Flood Suspicious"
    )

    assert (
        suspicious_result["score"]
        > normal_result["score"]
    )

    assert (
        suspicious_result["confidence"]
        > normal_result["confidence"]
    )

    print("\n========================================")
    print("Aggregate DDoS detector tests passed.")
    print("========================================")


if __name__ == "__main__":
    main()
    