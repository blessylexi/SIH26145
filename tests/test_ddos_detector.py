from src.detection.ddos_detector import detect_ddos


def main():

    # ========================================
    # NORMAL TRAFFIC
    # ========================================

    normal_flow = {
        "protocol": "TCP",

        "packet_count": 20,
        "packets_per_second": 50,

        "forward_ratio": 0.60,
        "reverse_ratio": 0.40,

        "syn_count": 1,
        "ack_count": 10,
        "syn_ack_count": 1,

        "syn_ratio": 0.05,

        "dst_port": 80,
    }

    # ========================================
    # SUSPICIOUS SYN-FLOOD TRAFFIC
    # ========================================

    suspicious_flow = {
        "protocol": "TCP",

        "packet_count": 500,
        "packets_per_second": 5000,

        "forward_ratio": 0.98,
        "reverse_ratio": 0.02,

        "syn_count": 490,
        "ack_count": 0,
        "syn_ack_count": 0,

        "syn_ratio": 0.98,

        "dst_port": 80,
    }

    print("========================================")
    print("       DDoS DETECTOR TEST")
    print("========================================")

    # ========================================
    # NORMAL TRAFFIC TEST
    # ========================================

    print("\n[NORMAL TRAFFIC]")

    normal_result = detect_ddos(normal_flow)

    for key, value in normal_result.items():
        print(f"{key}: {value}")

    # ========================================
    # SUSPICIOUS TRAFFIC TEST
    # ========================================

    print("\n[SUSPICIOUS SYN-FLOOD TRAFFIC]")

    suspicious_result = detect_ddos(suspicious_flow)

    for key, value in suspicious_result.items():
        print(f"{key}: {value}")

    # ========================================
    # VALIDATION
    # ========================================

    assert normal_result["threat_class"] == "No DDoS Detected"

    assert suspicious_result["threat_class"] == (
        "DDoS / SYN-Flood Suspicious"
    )

    assert suspicious_result["confidence"] > (
        normal_result["confidence"]
    )

    print("\n========================================")
    print("All DDoS detector tests passed.")
    print("========================================")


if __name__ == "__main__":
    main()
    