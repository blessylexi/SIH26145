from scapy.all import Ether, IP, TCP

from src.features.traffic_window import (
    aggregate_traffic_window,
)


def create_normal_traffic():

    packets = []

    # Client → Server
    packets.append(
        Ether()
        / IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(
            sport=50000,
            dport=80,
            flags="S"
        )
    )

    # Server → Client
    packets.append(
        Ether()
        / IP(src="192.168.1.20", dst="192.168.1.10")
        / TCP(
            sport=80,
            dport=50000,
            flags="SA"
        )
    )

    # Client → Server
    packets.append(
        Ether()
        / IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(
            sport=50000,
            dport=80,
            flags="A"
        )
    )

    return packets


def create_syn_flood():

    packets = []

    # Multiple sources attacking one destination.
    sources = [
        "10.0.0.1",
        "10.0.0.2",
        "10.0.0.3",
        "10.0.0.4",
        "10.0.0.5",
        "10.0.0.6",
        "10.0.0.7",
        "10.0.0.8",
    ]

    for index, source_ip in enumerate(sources):

        packet = (
            Ether()
            / IP(
                src=source_ip,
                dst="192.168.1.20"
            )
            / TCP(
                sport=40000 + index,
                dport=80,
                flags="S"
            )
        )

        packets.append(packet)

    return packets


def main():

    print("========================================")
    print("     TRAFFIC WINDOW AGGREGATOR TEST")
    print("========================================")

    # ----------------------------------------
    # NORMAL
    # ----------------------------------------

    normal_packets = create_normal_traffic()

    normal_features = aggregate_traffic_window(
        normal_packets
    )

    print("\n[NORMAL TRAFFIC]")

    for key, value in normal_features.items():
        print(f"{key}: {value}")

    # ----------------------------------------
    # SYN FLOOD
    # ----------------------------------------

    attack_packets = create_syn_flood()

    attack_features = aggregate_traffic_window(
        attack_packets
    )

    print("\n[SYN FLOOD TRAFFIC]")

    for key, value in attack_features.items():
        print(f"{key}: {value}")

    # ----------------------------------------
    # BASIC VALIDATION
    # ----------------------------------------

    assert (
        attack_features["unique_source_ips"]
        > normal_features["unique_source_ips"]
    )

    assert (
        attack_features["syn_ratio"]
        > normal_features["syn_ratio"]
    )

    assert (
        attack_features["destination_concentration"]
        > 0.9
    )

    print("\n========================================")
    print("Traffic window tests passed.")
    print("========================================")


if __name__ == "__main__":
    main()
    