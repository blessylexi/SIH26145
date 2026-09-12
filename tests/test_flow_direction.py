from scapy.all import Ether, IP, TCP

from src.flow.flow_builder import build_flows


def main():

    packets = []

    # First packet:
    # 10.0.0.10 -> 10.0.0.20
    packets.append(
        Ether()
        / IP(
            src="10.0.0.10",
            dst="10.0.0.20"
        )
        / TCP(
            sport=50000,
            dport=80,
            flags="S"
        )
    )

    # Response:
    # 10.0.0.20 -> 10.0.0.10
    packets.append(
        Ether()
        / IP(
            src="10.0.0.20",
            dst="10.0.0.10"
        )
        / TCP(
            sport=80,
            dport=50000,
            flags="SA"
        )
    )

    # Another forward packet.
    packets.append(
        Ether()
        / IP(
            src="10.0.0.10",
            dst="10.0.0.20"
        )
        / TCP(
            sport=50000,
            dport=80,
            flags="A"
        )
    )

    flows = build_flows(packets)

    assert len(flows) == 1

    flow_key, flow = next(iter(flows.items()))

    print("========================================")
    print("       FLOW DIRECTION TEST")
    print("========================================")

    print("\nFlow key:")
    print(flow_key)

    print("\nForward endpoint:")
    print(flow["forward_endpoint"])

    print("\nReverse endpoint:")
    print(flow["reverse_endpoint"])

    print("\nForward packets:")
    print(flow["forward_packets"])

    print("\nReverse packets:")
    print(flow["reverse_packets"])

    print("\nForward bytes:")
    print(flow["forward_bytes"])

    print("\nReverse bytes:")
    print(flow["reverse_bytes"])

    assert (
        flow["forward_endpoint"]
        == ("10.0.0.10", 50000)
    )

    assert (
        flow["reverse_endpoint"]
        == ("10.0.0.20", 80)
    )

    assert flow["forward_packets"] == 2
    assert flow["reverse_packets"] == 1

    print("\n========================================")
    print("Flow direction test passed.")
    print("========================================")


if __name__ == "__main__":
    main()
    