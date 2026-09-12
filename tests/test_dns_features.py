from scapy.all import Ether, IP, UDP
from scapy.layers.dns import DNS, DNSQR

from src.features.dns_features import (
    aggregate_dns_features,
    extract_dns_query_features,
)


def create_dns_packet(domain):

    return (
        Ether()
        / IP(
            src="192.168.1.10",
            dst="8.8.8.8",
        )
        / UDP(
            sport=53000,
            dport=53,
        )
        / DNS(
            rd=1,
            qd=DNSQR(
                qname=domain
            ),
        )
    )


def create_normal_dns_traffic():

    domains = [
        "google.com",
        "youtube.com",
        "github.com",
        "microsoft.com",
        "example.com",
    ]

    return [
        create_dns_packet(domain)
        for domain in domains
    ]


def create_suspicious_dns_traffic():

    domains = [
        "a8f91k2m7x4p9q1z.example.com",
        "b7d92m4n8x5r2k6p.example.com",
        "c9e83j5k1w7t4m8q.example.com",
        "d4f72n9p3x8v6k1r.example.com",
        "e6g81m3q7z2t9w5k.example.com",
    ]

    return [
        create_dns_packet(domain)
        for domain in domains
    ]


def main():

    print("========================================")
    print("          DNS FEATURE TEST")
    print("========================================")

    # ------------------------------------------
    # Normal DNS
    # ------------------------------------------

    normal_packets = (
        create_normal_dns_traffic()
    )

    normal_features = (
        aggregate_dns_features(
            normal_packets
        )
    )

    print("\n[NORMAL DNS]")

    print(
        f"dns_query_count: "
        f"{normal_features['dns_query_count']}"
    )

    print(
        f"unique_domains: "
        f"{normal_features['unique_domains']}"
    )

    print(
        f"average_query_length: "
        f"{normal_features['average_query_length']:.2f}"
    )

    print(
        f"max_label_length: "
        f"{normal_features['max_label_length']}"
    )

    print(
        f"average_domain_entropy: "
        f"{normal_features['average_domain_entropy']:.2f}"
    )

    print(
        f"average_numeric_ratio: "
        f"{normal_features['average_numeric_ratio']:.2f}"
    )

    # ------------------------------------------
    # Suspicious DNS
    # ------------------------------------------

    suspicious_packets = (
        create_suspicious_dns_traffic()
    )

    suspicious_features = (
        aggregate_dns_features(
            suspicious_packets
        )
    )

    print("\n[SUSPICIOUS-STYLE DNS]")

    print(
        f"dns_query_count: "
        f"{suspicious_features['dns_query_count']}"
    )

    print(
        f"unique_domains: "
        f"{suspicious_features['unique_domains']}"
    )

    print(
        f"average_query_length: "
        f"{suspicious_features['average_query_length']:.2f}"
    )

    print(
        f"max_label_length: "
        f"{suspicious_features['max_label_length']}"
    )

    print(
        f"average_domain_entropy: "
        f"{suspicious_features['average_domain_entropy']:.2f}"
    )

    print(
        f"average_numeric_ratio: "
        f"{suspicious_features['average_numeric_ratio']:.2f}"
    )

    # ------------------------------------------
    # Assertions
    # ------------------------------------------

    assert (
        normal_features["dns_query_count"]
        == 5
    )

    assert (
        normal_features["unique_domains"]
        == 5
    )

    assert (
        suspicious_features["dns_query_count"]
        == 5
    )

    assert (
        suspicious_features["unique_domains"]
        == 5
    )

    assert (
        suspicious_features[
            "average_query_length"
        ]
        > normal_features[
            "average_query_length"
        ]
    )

    assert (
        suspicious_features[
            "max_label_length"
        ]
        > normal_features[
            "max_label_length"
        ]
    )

    # Verify individual extraction.
    query_features = (
        extract_dns_query_features(
            suspicious_packets[0]
        )
    )

    assert query_features is not None

    assert (
        query_features["domain"]
        == "a8f91k2m7x4p9q1z.example.com"
    )

    print("\n========================================")
    print("DNS feature tests passed.")
    print("========================================")


if __name__ == "__main__":
    main()
    