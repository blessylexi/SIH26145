from src.detection.dns_detector import (
    detect_dns_anomaly,
)


def create_normal_features():

    return {
        "dns_query_count": 10,
        "unique_domains": 8,

        "average_query_length": 14.0,
        "max_query_length": 22,

        "average_label_length": 8.0,
        "max_label_length": 12,

        "average_domain_entropy": 3.0,
        "max_domain_entropy": 3.5,

        "average_numeric_ratio": 0.02,

        "repeated_long_subdomains": 0,
    }


def create_suspicious_features():

    return {
        "dns_query_count": 120,
        "unique_domains": 80,

        "average_query_length": 55.0,
        "max_query_length": 110,

        "average_label_length": 42.0,
        "max_label_length": 70,

        "average_domain_entropy": 4.8,
        "max_domain_entropy": 5.4,

        "average_numeric_ratio": 0.45,

        "repeated_long_subdomains": 12,
    }


def print_result(
    title,
    features,
    result,
):

    print(f"\n[{title}]")

    print("\nFeatures:")

    for key, value in features.items():

        print(
            f"{key}: {value}"
        )

    print("\nDetection:")

    for key, value in result.items():

        print(
            f"{key}: {value}"
        )


def main():

    print("========================================")
    print("          DNS DETECTOR TEST")
    print("========================================")

    # ------------------------------------------
    # Normal DNS
    # ------------------------------------------

    normal_features = (
        create_normal_features()
    )

    normal_result = (
        detect_dns_anomaly(
            normal_features
        )
    )

    print_result(
        "NORMAL DNS",
        normal_features,
        normal_result,
    )

    # ------------------------------------------
    # Suspicious DNS
    # ------------------------------------------

    suspicious_features = (
        create_suspicious_features()
    )

    suspicious_result = (
        detect_dns_anomaly(
            suspicious_features
        )
    )

    print_result(
        "SUSPICIOUS DNS",
        suspicious_features,
        suspicious_result,
    )

    # ------------------------------------------
    # Assertions
    # ------------------------------------------

    assert (
        normal_result["threat_class"]
        == "No Suspicious DNS Behavior"
    )

    assert (
        suspicious_result["threat_class"]
        == "Potential DGA / DNS Tunnelling"
    )

    assert (
        suspicious_result["severity"]
        == "HIGH"
    )

    assert (
        suspicious_result["score"]
        >= 10
    )

    assert (
        suspicious_result["score"]
        > normal_result["score"]
    )

    assert (
        len(
            suspicious_result["evidence"]
        )
        >= 4
    )

    print("\n========================================")
    print(
        "DNS detector tests passed."
    )
    print("========================================")


if __name__ == "__main__":
    main()
    