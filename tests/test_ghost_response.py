from src.detection.ghost_response import (
    ghost_response,
    explain_ghost_result,
)


def create_normal_behavior():

    return {
        "packets_per_second": 10.0,
        "bytes_per_second": 5000.0,
        "syn_ratio": 0.10,
        "unique_destination_ips": 3,
        "unique_destination_ports": 5,
        "destination_concentration": 0.70,
        "average_packet_size": 500.0,
        "average_inter_arrival": 0.10,
    }


def create_suspicious_behavior():

    return {
        "packets_per_second": 100.0,
        "bytes_per_second": 50000.0,
        "syn_ratio": 1.0,
        "unique_destination_ips": 20,
        "unique_destination_ports": 50,
        "destination_concentration": 0.05,
        "average_packet_size": 1200.0,
        "average_inter_arrival": 0.005,
    }


def main():

    print("========================================")
    print("       GHOST RESPONSE MODEL TEST")
    print("========================================")

    normal_result = ghost_response(
        create_normal_behavior()
    )

    print("\nNORMAL INTERACTION")
    print("-------------------")

    print(
        "Ghost consistency:",
        normal_result["ghost_consistency"],
    )

    print(
        "Counterfactual deviation:",
        normal_result["counterfactual_deviation"],
    )

    print(
        "Classification:",
        normal_result["classification"],
    )

    print(
        "Explanation:",
        explain_ghost_result(
            normal_result
        ),
    )

    suspicious_result = ghost_response(
        create_suspicious_behavior()
    )

    print("\nSUSPICIOUS INTERACTION")
    print("-----------------------")

    print(
        "Ghost consistency:",
        suspicious_result[
            "ghost_consistency"
        ],
    )

    print(
        "Counterfactual deviation:",
        suspicious_result[
            "counterfactual_deviation"
        ],
    )

    print(
        "Classification:",
        suspicious_result["classification"],
    )

    print(
        "Explanation:",
        explain_ghost_result(
            suspicious_result
        ),
    )

    print("\nGhost Evidence:")

    for item in suspicious_result[
        "evidence"
    ]:

        print(
            f"- {item['description']} "
            f"| deviation="
            f"{item['counterfactual_deviation']}"
        )

    assert (
        0.0
        <= normal_result[
            "ghost_consistency"
        ]
        <= 1.0
    )

    assert (
        0.0
        <= suspicious_result[
            "ghost_consistency"
        ]
        <= 1.0
    )

    assert (
        normal_result[
            "ghost_consistency"
        ]
        > suspicious_result[
            "ghost_consistency"
        ]
    )

    assert (
        normal_result[
            "counterfactual_deviation"
        ]
        < suspicious_result[
            "counterfactual_deviation"
        ]
    )

    assert (
        len(
            suspicious_result[
                "evidence"
            ]
        )
        > 0
    )

    print("\n========================================")
    print(
        "Ghost Response Model test passed."
    )
    print("========================================")


if __name__ == "__main__":
    main()
