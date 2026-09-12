from collections import Counter
from math import log2

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP


def calculate_entropy(value):
    """
    Calculate Shannon entropy for a string.

    Higher entropy generally means the characters
    are more uniformly distributed.
    """

    if not value:
        return 0.0

    counts = Counter(value)
    total = len(value)

    entropy = 0.0

    for count in counts.values():
        probability = count / total
        entropy -= probability * log2(probability)

    return entropy


def decode_dns_name(qname):
    """
    Convert a Scapy DNS qname into a normal string.
    """

    if isinstance(qname, bytes):
        qname = qname.decode("utf-8", errors="ignore")

    return str(qname).rstrip(".")


def calculate_numeric_ratio(value):
    """
    Calculate the proportion of numeric characters.
    """

    if not value:
        return 0.0

    numeric_count = sum(
        1 for character in value
        if character.isdigit()
    )

    return numeric_count / len(value)


def extract_dns_query_features(packet):
    """
    Extract behavioral metadata from a DNS query.

    Returns None when the packet is not a DNS query.

    Features include:

        - queried domain
        - query length
        - label length
        - domain entropy
        - numeric-character ratio
        - number of labels
        - source IP
        - destination IP
    """

    if not packet.haslayer(DNS):
        return None

    dns = packet[DNS]

    # DNS query must contain at least one question.
    if dns.qdcount == 0:
        return None

    if not packet.haslayer(DNSQR):
        return None

    query = packet[DNSQR]

    domain = decode_dns_name(query.qname)

    if not domain:
        return None

    labels = domain.split(".")

    # The longest label is particularly useful for
    # detecting unusually long generated/tunnel-like names.
    longest_label = max(
        labels,
        key=len,
        default=""
    )

    return {
        "domain": domain,

        "query_length": len(domain),

        "label_count": len(labels),

        "longest_label_length": len(
            longest_label
        ),

        "domain_entropy": calculate_entropy(
            domain
        ),

        "longest_label_entropy": calculate_entropy(
            longest_label
        ),

        "numeric_ratio": calculate_numeric_ratio(
            domain
        ),

        "source_ip": (
            packet[IP].src
            if packet.haslayer(IP)
            else None
        ),

        "destination_ip": (
            packet[IP].dst
            if packet.haslayer(IP)
            else None
        ),

        "query_type": int(query.qtype),
    }


def aggregate_dns_features(packets):
    """
    Aggregate DNS behavioral features across a packet collection.

    This function does not classify traffic as malicious.

    It only measures DNS behavior.
    """

    queries = []

    for packet in packets:

        features = extract_dns_query_features(
            packet
        )

        if features is not None:
            queries.append(features)

    if not queries:
        return {
            "dns_query_count": 0,
            "unique_domains": 0,
            "average_query_length": 0.0,
            "max_query_length": 0,
            "average_label_length": 0.0,
            "max_label_length": 0,
            "average_domain_entropy": 0.0,
            "max_domain_entropy": 0.0,
            "average_numeric_ratio": 0.0,
            "unique_source_ips": 0,
            "unique_destination_ips": 0,
            "repeated_long_subdomains": 0,
            "queries": [],
        }

    domains = [
        query["domain"]
        for query in queries
    ]

    query_lengths = [
        query["query_length"]
        for query in queries
    ]

    label_lengths = [
        query["longest_label_length"]
        for query in queries
    ]

    domain_entropies = [
        query["domain_entropy"]
        for query in queries
    ]

    numeric_ratios = [
        query["numeric_ratio"]
        for query in queries
    ]

    source_ips = [
        query["source_ip"]
        for query in queries
        if query["source_ip"] is not None
    ]

    destination_ips = [
        query["destination_ip"]
        for query in queries
        if query["destination_ip"] is not None
    ]

    # Long-label repetition can be useful for tunnelling
    # analysis. We count repeated labels that are
    # unusually long rather than treating every long
    # label as malicious.
    long_labels = []

    for query in queries:

        labels = query["domain"].split(".")

        for label in labels:

            if len(label) >= 20:
                long_labels.append(label)

    label_counts = Counter(long_labels)

    repeated_long_subdomains = sum(
        1
        for count in label_counts.values()
        if count > 1
    )

    return {
        "dns_query_count": len(queries),

        "unique_domains": len(
            set(domains)
        ),

        "average_query_length": (
            sum(query_lengths)
            / len(query_lengths)
        ),

        "max_query_length": max(
            query_lengths
        ),

        "average_label_length": (
            sum(label_lengths)
            / len(label_lengths)
        ),

        "max_label_length": max(
            label_lengths
        ),

        "average_domain_entropy": (
            sum(domain_entropies)
            / len(domain_entropies)
        ),

        "max_domain_entropy": max(
            domain_entropies
        ),

        "average_numeric_ratio": (
            sum(numeric_ratios)
            / len(numeric_ratios)
        ),

        "unique_source_ips": len(
            set(source_ips)
        ),

        "unique_destination_ips": len(
            set(destination_ips)
        ),

        "repeated_long_subdomains": (
            repeated_long_subdomains
        ),

        "queries": queries,
    }


if __name__ == "__main__":

    print(
        "DNS feature extractor ready."
    )
    