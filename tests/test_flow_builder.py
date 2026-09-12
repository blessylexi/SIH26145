from src.ingest.pcap_reader import read_pcap
from src.flow.flow_builder import build_flows


PCAP_FILE = "data/raw/test_traffic.pcap"


def main():
    packets = read_pcap(PCAP_FILE)

    flows = build_flows(packets)

    print()
    print("[FLOW] Flows detected:", len(flows))

    for flow_key, flow_data in flows.items():
        print()
        print("[FLOW KEY]", flow_key)
        print("[FLOW DATA]", flow_data)


if __name__ == "__main__":
    main()
    