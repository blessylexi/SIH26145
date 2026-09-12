from scapy.all import Ether, IP, TCP

from src.features.traffic_window import (
    aggregate_traffic_window,
)

from src.detection.recon_detector import (
    detect_reconnaissance,
)


def create_normal_traffic():

    packets = []

    for port in [80, 443]:

        packet = (
            Ether()
            / IP(
                src="192.168.1.10",
                dst="192.168.1.20"
            )
            / TCP(
                sport=50000,
                dport=port,
                flags="A"
            )
        )

        packets.append(packet)

    return packets


def create_port_scan():

    packets = []

    # One source host probing many
    # destination ports on one target.

    destination_ports = [
        21, 22, 23, 25, 53,
        80, 110, 111, 135, 139,
        143, 443, 445, 993, 995,
        1433, 1521, 3306, 3389, 8080,
        8443, 9000
    ]

    for index, port in enumerate(
        destination_ports
    ):

        packet = (
            Ether()
            / IP(
                src="10.0.0.50",
                dst="10.0.0.100"
            )
            / TCP(
                sport=40000 + index,
                dport=port,
                flags="S"
            )
        )

        packets.append(packet)

    return packets


def print_result(
    title,
    features,
    result
):

    print(f"\n[{title}]")

    print("\nFeatures:")

    print(
        f"total_packets: "
        f"{features['total_packets']}"
    )

    print(
        f"unique_destination_ips: "
        f"{features['unique_destination_ips']}"
    )

    print(
        f"unique_destination_ports: "
        f"{features['unique_destination_ports']}"
    )

    print(
        f"unique_source_ports: "
        f"{features['unique_source_ports']}"
    )

    print(
        f"syn_ratio: "
        f"{features['syn_ratio']:.2f}"
    )

    print("\nDetection:")

    for key, value in result.items():

        print(f"{key}: {value}")


def main():

    print("========================================")
    print("       RECONNAISSANCE DETECTOR TEST")
    print("========================================")

    # ------------------------------------------
    # Normal traffic
    # ------------------------------------------

    normal_packets = (
        create_normal_traffic()
    )

    normal_features = (
        aggregate_traffic_window(
            normal_packets,
            window_duration=1.0
        )
    )

    normal_result = (
        detect_reconnaissance(
            normal_features
        )
    )

    print_result(
        "NORMAL TRAFFIC",
        normal_features,
        normal_result
    )

    # ------------------------------------------
    # Port scan
    # ------------------------------------------

    scan_packets = (
        create_port_scan()
    )

    scan_features = (
        aggregate_traffic_window(
            scan_packets,
            window_duration=1.0
        )
    )

    scan_result = (
        detect_reconnaissance(
            scan_features
        )
    )

    print_result(
        "PORT SCAN",
        scan_features,
        scan_result
    )

    # ------------------------------------------
    # Assertions
    # ------------------------------------------

    assert (
        normal_result["threat_class"]
        == "No Reconnaissance Detected"
    )

    assert (
        scan_result["threat_class"]
        == "Reconnaissance / Port Scan"
    )

    assert (
        scan_features[
            "unique_destination_ports"
        ]
        >= 20
    )

    assert (
        scan_result["score"]
        > normal_result["score"]
    )

    print("\n========================================")
    print(
        "Reconnaissance detector tests passed."
    )
    print("========================================")


if __name__ == "__main__":

    main()
    