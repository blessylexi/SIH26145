from scapy.all import Ether, IP, TCP

from src.features.c2_features import (
    extract_c2_features,
)

from src.detection.c2_detector import (
    detect_c2_beaconing,
)


def create_normal_traffic():

    packets = []

    timestamps = [
        0.0,
        0.7,
        2.3,
        4.9,
        8.1,
    ]

    for timestamp in timestamps:

        packet = (
            Ether()
            / IP(
                src="192.168.1.10",
                dst="192.168.1.20"
            )
            / TCP(
                sport=50000,
                dport=443,
                flags="A"
            )
        )

        packet.time = timestamp

        packets.append(packet)

    return packets


def create_beacon_traffic():

    packets = []

    # Approximately every 10 seconds.
    # Small timing variation represents realistic
    # network jitter.

    timestamps = [
        0.0,
        10.1,
        19.9,
        30.2,
        40.0,
        50.1,
        60.0,
        70.2,
    ]

    for timestamp in timestamps:

        packet = (
            Ether()
            / IP(
                src="10.0.0.50",
                dst="203.0.113.10"
            )
            / TCP(
                sport=51000,
                dport=443,
                flags="A"
            )
        )

        packet.time = timestamp

        packets.append(packet)

    return packets


def print_result(title, features, result):

    print(f"\n[{title}]")

    print("\nFeatures:")

    print(
        f"conversation_count: "
        f"{features['conversation_count']}"
    )

    print(
        f"periodic_conversations: "
        f"{features['periodic_conversations']}"
    )

    print(
        f"periodicity_ratio: "
        f"{features['periodicity_ratio']}"
    )

    print("\nDetection:")

    for key, value in result.items():

        print(f"{key}: {value}")


def main():

    print("========================================")
    print("        C2 BEACONING DETECTOR TEST")
    print("========================================")

    # ------------------------------------------
    # Normal traffic
    # ------------------------------------------

    normal_packets = create_normal_traffic()

    normal_features = extract_c2_features(
        normal_packets
    )

    normal_result = detect_c2_beaconing(
        normal_features
    )

    print_result(
        "NORMAL TRAFFIC",
        normal_features,
        normal_result
    )

    # ------------------------------------------
    # Beaconing traffic
    # ------------------------------------------

    beacon_packets = create_beacon_traffic()

    beacon_features = extract_c2_features(
        beacon_packets
    )

    beacon_result = detect_c2_beaconing(
        beacon_features
    )

    print_result(
        "BEACONING TRAFFIC",
        beacon_features,
        beacon_result
    )

    # ------------------------------------------
    # Assertions
    # ------------------------------------------

    assert (
        normal_result["threat_class"]
        == "No C2 Beaconing Detected"
    )

    assert (
        beacon_result["threat_class"]
        == "Potential C2 Beaconing"
    )

    assert (
        beacon_result["score"]
        > normal_result["score"]
    )

    assert (
        beacon_result["confidence"]
        > normal_result["confidence"]
    )

    assert (
        beacon_features[
            "periodic_conversations"
        ]
        >= 1
    )

    assert (
        beacon_features[
            "periodicity_ratio"
        ]
        > 0
    )

    print("\n========================================")
    print("C2 beaconing detector tests passed.")
    print("========================================")


if __name__ == "__main__":
    main()
    