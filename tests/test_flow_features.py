from src.ingest.pcap_reader import read_pcap
from src.flow.flow_builder import build_flows
from src.features.flow_features import extract_flow_features

PCAP_FILE = "data/raw/test_traffic.pcap"


def main():
    packets = read_pcap(PCAP_FILE)
    flows = build_flows(packets)

    print()
    print("[FEATURES] Extracting flow features...")
    print()

    for flow_key, flow_data in flows.items():
        features = extract_flow_features(flow_key, flow_data)

        print("[FLOW]", flow_key)
        print("[FEATURES]")

        for key, value in features.items():
            print(f"  {key}: {value}")

        print()


if __name__ == "__main__":
    main()
    