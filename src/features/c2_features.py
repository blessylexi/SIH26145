from collections import defaultdict
from statistics import mean, pstdev


def extract_c2_features(packets):
    """
    Extract behavioral features related to possible
    command-and-control (C2) beaconing.

    The analysis groups packets by:

        source IP -> destination IP -> destination port

    and measures the timing regularity of repeated
    communications.

    This is metadata-only analysis. No payload inspection
    is performed.
    """

    conversations = defaultdict(list)

    for packet in packets:

        if not packet.haslayer("IP"):
            continue

        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst

        src_port = 0
        dst_port = 0
        protocol = "OTHER"

        if packet.haslayer("TCP"):

            protocol = "TCP"

            src_port = int(packet["TCP"].sport)
            dst_port = int(packet["TCP"].dport)

        elif packet.haslayer("UDP"):

            protocol = "UDP"

            src_port = int(packet["UDP"].sport)
            dst_port = int(packet["UDP"].dport)

        timestamp = float(packet.time)

        key = (
            src_ip,
            dst_ip,
            dst_port,
            protocol
        )

        conversations[key].append(timestamp)

    # --------------------------------------------------
    # Calculate timing features for each conversation
    # --------------------------------------------------

    conversation_features = []

    for key, timestamps in conversations.items():

        timestamps.sort()

        if len(timestamps) < 3:
            continue

        intervals = []

        for index in range(1, len(timestamps)):

            interval = (
                timestamps[index]
                - timestamps[index - 1]
            )

            if interval > 0:
                intervals.append(interval)

        if len(intervals) < 2:
            continue

        average_interval = mean(intervals)

        interval_std = pstdev(intervals)

        if average_interval > 0:

            coefficient_of_variation = (
                interval_std / average_interval
            )

        else:

            coefficient_of_variation = float("inf")

        conversation_features.append(
            {
                "source_ip": key[0],
                "destination_ip": key[1],
                "destination_port": key[2],
                "protocol": key[3],

                "connection_count": len(timestamps),

                "average_interval": average_interval,

                "interval_std": interval_std,

                "coefficient_of_variation": (
                    coefficient_of_variation
                ),
            }
        )

    # --------------------------------------------------
    # Global summary
    # --------------------------------------------------

    if conversation_features:

        periodic_conversations = 0

        for conversation in conversation_features:

            # Low coefficient of variation means the
            # intervals are relatively regular.
            if (
                conversation[
                    "coefficient_of_variation"
                ] <= 0.20
            ):
                periodic_conversations += 1

        periodicity_ratio = (
            periodic_conversations
            / len(conversation_features)
        )

    else:

        periodicity_ratio = 0.0

    return {
        "conversation_count": len(
            conversation_features
        ),

        "periodic_conversations": (
            periodic_conversations
            if conversation_features
            else 0
        ),

        "periodicity_ratio": periodicity_ratio,

        "conversations": conversation_features,
    }


if __name__ == "__main__":

    print(
        "C2 behavioral feature extractor ready."
    )
    