from scapy.all import DNS, DNSQR, IP, UDP

from src.features.dns_features import (
    aggregate_dns_features,
)

from src.detection.dns_detector import (
    detect_dns_anomaly,
)


def create_dns_packet(
    source_ip,
    domain,
):
    return (
        IP(
            src=source_ip,
            dst="8.8.8.8",
        )
        /
        UDP(
            sport=53000,
            dport=53,
        )
        /
        DNS(
            rd=1,
            qd=DNSQR(
                qname=domain
            ),
        )
    )


def create_normal_dns_packets():

    domains = [
        "google.com",
        "youtube.com",
        "github.com",
        "microsoft.com",
        "example.com",
    ]

    packets = []

    for domain in domains:

        packets.append(
            create_dns_packet(
                "192.168.1.10",
                domain,
            )
        )

    return packets


def create_suspicious_dns_packets():

    domains = [
        "x8f92kd71m2q9z.example.com",
        "91kd8s72m3n8q1.example.com",
        "a82k91m7x3p9z.example.com",
        "7f92k81m3q8x2.example.com",
        "k92m81x73q9z4.example.com",
    ]

    packets = []

    for domain in domains:

        packets.append(
            create_dns_packet(
                "192.168.1.50",
                domain,
            )
        )

    return packets


def print_result(
    title,
    features,
    detection,
):

    print("\n========================================")
    print(title)
    print("========================================")

    print("\nExtracted DNS Features:")

    for key, value in features.items():

        if key != "queries":

            print(
                f"{key}: {value}"
            )

    print("\nDetection Result:")

    for key, value in detection.items():

        print(
            f"{key}: {value}"
        )


def run_test(
    title,
    packets,
):

    features = aggregate_dns_features(
        packets
    )

    detection = detect_dns_anomaly(
        features
    )

    print_result(
        title,
        features,
        detection,
    )

    return features, detection


def main():

    print("========================================")
    print("       DNS FULL PIPELINE TEST")
    print("========================================")

    # ------------------------------------------
    # Normal DNS traffic
    # ------------------------------------------

    normal_packets = (
        create_normal_dns_packets()
    )

    normal_features, normal_detection = (
        run_test(
            "NORMAL DNS TRAFFIC",
            normal_packets,
        )
    )

    # ------------------------------------------
    # Suspicious DNS traffic
    # ------------------------------------------

    suspicious_packets = (
        create_suspicious_dns_packets()
    )

    suspicious_features, suspicious_detection = (
        run_test(
            "SUSPICIOUS DNS TRAFFIC",
            suspicious_packets,
        )
    )

    # ------------------------------------------
    # Validation
    # ------------------------------------------

    assert (
        normal_features["dns_query_count"]
        == 5
    )

    assert (
        suspicious_features["dns_query_count"]
        == 5
    )

    assert (
        normal_detection["score"]
        < suspicious_detection["score"]
    )

    assert (
        normal_detection["threat_class"]
        == "No Suspicious DNS Behavior"
    )

    print("\n========================================")
    print("DNS full pipeline test passed.")
    print("========================================")


if __name__ == "__main__":
    main()
    