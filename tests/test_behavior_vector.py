from scapy.all import Ether, IP, TCP, UDP

from src.features.behavior_vector import (
    build_behavior_vector,
    get_numeric_behavior_features,
)


def create_test_traffic():

    packets = []

    # ------------------------------------------
    # TCP packet 1
    # ------------------------------------------

    packet_1 = (
        Ether()
        / IP(
            src="192.168.1.10",
            dst="192.168.1.20",
        )
        / TCP(
            sport=50000,
            dport=443,
            flags="S",
        )
    )

    packet_1.time = 1000.0

    packets.append(packet_1)

    # ------------------------------------------
    # TCP response
    # ------------------------------------------

    packet_2 = (
        Ether()
        / IP(
            src="192.168.1.20",
            dst="192.168.1.10",
        )
        / TCP(
            sport=443,
            dport=50000,
            flags="SA",
        )
    )

    packet_2.time = 1000.050

    packets.append(packet_2)

    # ------------------------------------------
    # UDP packet
    # ------------------------------------------

    packet_3 = (
        Ether()
        / IP(
            src="192.168.1.10",
            dst="192.168.1.30",
        )
        / UDP(
            sport=53000,
            dport=53,
        )
        / b"test"
    )

    packet_3.time = 1000.150

    packets.append(packet_3)

    return packets


def main():

    print("========================================")
    print("       BEHAVIOR VECTOR TEST")
    print("========================================")

    packets = create_test_traffic()

    behavior = build_behavior_vector(
        packets,
        window_duration=1.0,
    )

    numeric_features = (
        get_numeric_behavior_features(
            behavior
        )
    )

    print("\nUnified Behavioral Representation:")

    for key, value in behavior.items():

        print(
            f"{key}: {value}"
        )

    print("\nNumeric Model Features:")

    for key, value in numeric_features.items():

        print(
            f"{key}: {value}"
        )

    # ------------------------------------------
    # Assertions
    # ------------------------------------------

    assert (
        behavior["total_packets"]
        == 3
    )

    assert (
        behavior["total_bytes"]
        > 0
    )

    assert (
        behavior["average_packet_size"]
        > 0
    )

    assert (
        behavior["average_inter_arrival"]
        > 0
    )

    assert (
        behavior["inter_arrival_variance"]
        >= 0
    )

    assert (
        behavior["unique_source_ips"]
        == 2
    )

    assert (
        behavior["unique_destination_ips"]
        == 3
    )

    assert (
        behavior["tcp_ratio"]
        > 0
    )

    assert (
        behavior["udp_ratio"]
        > 0
    )

    assert (
        "192.168.1.10"
        in behavior["source_ips"]
    )

    assert (
        "192.168.1.20"
        in behavior["destination_ips"]
    )

    assert (
        "TCP"
        in behavior["protocols"]
    )

    assert (
        "UDP"
        in behavior["protocols"]
    )

    assert (
        "source_ips"
        not in numeric_features
    )

    assert (
        "destination_ips"
        not in numeric_features
    )

    assert (
        "protocols"
        not in numeric_features
    )

    print("\n========================================")
    print(
        "Behavior vector test passed."
    )
    print("========================================")


if __name__ == "__main__":
    main()
