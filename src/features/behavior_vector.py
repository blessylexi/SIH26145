from statistics import mean, pvariance

from scapy.layers.inet import IP, TCP, UDP

from src.features.traffic_window import (
    aggregate_traffic_window,
)


def _safe_mean(values):
    if not values:
        return 0.0

    return mean(values)


def _safe_variance(values):
    if len(values) < 2:
        return 0.0

    return pvariance(values)


def _extract_packet_metadata(packets):
    """
    Extract lightweight packet metadata required by
    the SIH behavioral detection prototype.

    No payload inspection is performed.
    """

    timestamps = []
    packet_sizes = []

    source_ips = []
    destination_ips = []
    protocols = []

    for packet in packets:

        if not packet.haslayer(IP):
            continue

        timestamps.append(
            float(packet.time)
        )

        packet_sizes.append(
            len(packet)
        )

        source_ips.append(
            packet[IP].src
        )

        destination_ips.append(
            packet[IP].dst
        )

        if packet.haslayer(TCP):
            protocols.append("TCP")

        elif packet.haslayer(UDP):
            protocols.append("UDP")

        else:
            protocols.append(
                str(packet[IP].proto)
            )

    # ------------------------------------------
    # Inter-arrival times
    # ------------------------------------------

    inter_arrival_times = []

    if len(timestamps) >= 2:

        sorted_timestamps = sorted(
            timestamps
        )

        for index in range(
            1,
            len(sorted_timestamps),
        ):

            delta = (
                sorted_timestamps[index]
                - sorted_timestamps[index - 1]
            )

            inter_arrival_times.append(
                max(0.0, delta)
            )

    return {
        "timestamps": timestamps,
        "packet_sizes": packet_sizes,
        "source_ips": source_ips,
        "destination_ips": destination_ips,
        "protocols": protocols,
        "inter_arrival_times": (
            inter_arrival_times
        ),
    }


def build_behavior_vector(
    packets,
    window_duration=1.0,
):
    """
    Build the unified behavioral representation
    used by the SIH prototype.

    This layer combines the existing traffic-window
    features with lightweight timing and packet-size
    metadata.

    The result is intended to be consumed by:

        - baseline detector
        - Ghost Response Model
        - score fusion
        - dashboard
        - explanation engine

    Payload contents are never inspected.
    """

    traffic_features = (
        aggregate_traffic_window(
            packets,
            window_duration=window_duration,
        )
    )

    metadata = _extract_packet_metadata(
        packets
    )

    packet_sizes = metadata[
        "packet_sizes"
    ]

    inter_arrival_times = metadata[
        "inter_arrival_times"
    ]

    source_ips = metadata[
        "source_ips"
    ]

    destination_ips = metadata[
        "destination_ips"
    ]

    protocols = metadata[
        "protocols"
    ]

    # ------------------------------------------
    # Packet-size statistics
    # ------------------------------------------

    average_packet_size = (
        _safe_mean(packet_sizes)
    )

    packet_size_variance = (
        _safe_variance(packet_sizes)
    )

    minimum_packet_size = (
        min(packet_sizes)
        if packet_sizes
        else 0
    )

    maximum_packet_size = (
        max(packet_sizes)
        if packet_sizes
        else 0
    )

    # ------------------------------------------
    # Timing statistics
    # ------------------------------------------

    average_inter_arrival = (
        _safe_mean(
            inter_arrival_times
        )
    )

    inter_arrival_variance = (
        _safe_variance(
            inter_arrival_times
        )
    )

    minimum_inter_arrival = (
        min(inter_arrival_times)
        if inter_arrival_times
        else 0.0
    )

    maximum_inter_arrival = (
        max(inter_arrival_times)
        if inter_arrival_times
        else 0.0
    )

    # ------------------------------------------
    # Protocol distribution
    # ------------------------------------------

    tcp_count = protocols.count("TCP")
    udp_count = protocols.count("UDP")

    total_protocol_packets = (
        len(protocols)
    )

    if total_protocol_packets > 0:

        tcp_ratio = (
            tcp_count
            / total_protocol_packets
        )

        udp_ratio = (
            udp_count
            / total_protocol_packets
        )

    else:

        tcp_ratio = 0.0
        udp_ratio = 0.0

    # ------------------------------------------
    # Unified representation
    # ------------------------------------------

    behavior = dict(
        traffic_features
    )

    behavior.update(
        {
            # Packet metadata
            "average_packet_size": (
                average_packet_size
            ),

            "packet_size_variance": (
                packet_size_variance
            ),

            "minimum_packet_size": (
                minimum_packet_size
            ),

            "maximum_packet_size": (
                maximum_packet_size
            ),

            # Timing
            "average_inter_arrival": (
                average_inter_arrival
            ),

            "inter_arrival_variance": (
                inter_arrival_variance
            ),

            "minimum_inter_arrival": (
                minimum_inter_arrival
            ),

            "maximum_inter_arrival": (
                maximum_inter_arrival
            ),

            # Protocol
            "tcp_ratio": tcp_ratio,
            "udp_ratio": udp_ratio,

            # Explicit communication identity
            "source_ips": sorted(
                set(source_ips)
            ),

            "destination_ips": sorted(
                set(destination_ips)
            ),

            "protocols": sorted(
                set(protocols)
            ),
        }
    )

    return behavior


def get_numeric_behavior_features(
    behavior,
):
    """
    Return only numeric features.

    This is the representation that future
    baseline and Ghost models can consume.
    """

    excluded = {
        "source_ips",
        "destination_ips",
        "protocols",
    }

    return {
        key: value
        for key, value in behavior.items()
        if key not in excluded
        and isinstance(
            value,
            (int, float),
        )
    }


if __name__ == "__main__":

    print(
        "Unified behavioral feature layer ready."
    )
    