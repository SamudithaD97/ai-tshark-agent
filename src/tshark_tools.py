import json
import ipaddress
import os
import subprocess
from collections import Counter




PCAP_FILE = os.getenv(
    "PCAP_FILE",
    r"captures\normal.pcapng"
)


def run_tshark(arguments):
    """Run TShark against the configured PCAP file."""
    command = ["tshark", "-r", PCAP_FILE] + arguments

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"TShark failed:\n{result.stderr}"
        )

    return result.stdout


def get_dns_summary():
    """Extract and summarize DNS queries."""

    output = run_tshark([
        "-Y", "dns.flags.response == 0",
        "-T", "fields",
        "-e", "dns.qry.name"
    ])

    domains = []

    for line in output.splitlines():
        domain = line.strip()

        if domain:
            domains.append(domain)

    counts = Counter(domains)

    return {
        "total_queries": len(domains),
        "unique_domains": len(counts),
        "top_domains": [
            {
                "domain": domain,
                "count": count
            }
            for domain, count in counts.most_common(10)
        ]
    }


def get_syn_summary():
    """Extract and summarize TCP SYN attempts."""

    output = run_tshark([
        "-Y", "tcp.flags.syn == 1 && tcp.flags.ack == 0",
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.dstport"
    ])

    attempts = []
    ports = set()
    destinations = set()

    source_activity = {}

    for line in output.splitlines():
        parts = line.split("\t")

        if len(parts) >= 3:
            source = parts[0]
            destination = parts[1]
            port = parts[2]

            if not source or not destination or not port:
                continue

            attempts.append({
                "source": source,
                "destination": destination,
                "port": port
            })

            destinations.add(destination)
            ports.add(port)

            # Track activity for each source IP
            if source not in source_activity:
                source_activity[source] = {
                    "syn_attempts": 0,
                    "destinations": set(),
                    "ports": set()
                }

            source_activity[source]["syn_attempts"] += 1
            source_activity[source]["destinations"].add(
                destination
            )
            source_activity[source]["ports"].add(
                port
            )

    port_counts = Counter(
        attempt["port"]
        for attempt in attempts
    )

    # Convert source activity into JSON-friendly format
    top_sources = []

    for source, data in source_activity.items():
        top_sources.append({
            "ip": source,
            "syn_attempts": data["syn_attempts"],
            "unique_destinations": len(
                data["destinations"]
            ),
            "unique_ports": len(
                data["ports"]
            )
        })

    # Most active sources first
    top_sources.sort(
        key=lambda item: item["syn_attempts"],
        reverse=True
    )

    return {
        "total_syn_attempts": len(attempts),
        "unique_destination_ips": len(destinations),
        "unique_destination_ports": len(ports),

        "top_ports": [
            {
                "port": port,
                "count": count
            }
            for port, count
            in port_counts.most_common(10)
        ],

        "top_sources": top_sources[:10]
    }
def detect_port_scan():
    """Look for a source/target pair contacting many ports."""

    output = run_tshark([
        "-Y", "tcp.flags.syn == 1 && tcp.flags.ack == 0",
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.dstport"
    ])

    activity = {}

    for line in output.splitlines():
        parts = line.split("\t")

        if len(parts) >= 3:
            source = parts[0]
            destination = parts[1]
            port = parts[2]

            key = (source, destination)

            if key not in activity:
                activity[key] = set()

            activity[key].add(port)

    findings = []

    for (source, destination), ports in activity.items():

        # Initial project heuristic.
        if len(ports) >= 20:
            findings.append({
                "source": source,
                "destination": destination,
                "unique_ports": len(ports)
            })

    return findings


def detect_dns_anomalies():
    """Find unusually long DNS query names."""

    output = run_tshark([
        "-Y", "dns.flags.response == 0",
        "-T", "fields",
        "-e", "dns.qry.name"
    ])

    anomalies = []
    seen = set()

    for line in output.splitlines():

        domain = line.strip()

        if not domain or domain in seen:
            continue

        seen.add(domain)

        if len(domain) >= 50:
            anomalies.append({
                "domain": domain,
                "length": len(domain),
                "reason": "unusually long domain name"
            })

    return anomalies

def investigate_ip(ip_address):
    """
    Investigate activity for a specific IPv4 address.
    """

    # Validate AI-generated input before using it in TShark.
    try:
        validated_ip = ipaddress.ip_address(ip_address)

        if validated_ip.version != 4:
            return {
                "error": "Only IPv4 addresses are supported."
            }

    except ValueError:
        return {
            "error": (
                f"Invalid IPv4 address: {ip_address}. "
                "This tool only accepts IPv4 addresses, not domain names."
            )
        }

    ip_address = str(validated_ip)

    output = run_tshark([
        "-Y", f"ip.addr == {ip_address}",
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.srcport",
        "-e", "udp.dstport"
    ])

    packets_sent = 0
    packets_received = 0

    outbound_ips = set()
    inbound_ips = set()

    outbound_tcp_ports = set()
    outbound_udp_ports = set()

    for line in output.splitlines():

        parts = line.split("\t")

        # Make sure there are enough fields
        while len(parts) < 6:
            parts.append("")

        source = parts[0]
        destination = parts[1]

        tcp_dst_port = parts[3]
        udp_dst_port = parts[5]

        # -----------------------------
        # Outbound traffic
        # -----------------------------

        if source == ip_address:

            packets_sent += 1

            if destination:
                outbound_ips.add(destination)

            if tcp_dst_port:
                outbound_tcp_ports.add(tcp_dst_port)

            if udp_dst_port:
                outbound_udp_ports.add(udp_dst_port)

        # -----------------------------
        # Inbound traffic
        # -----------------------------

        elif destination == ip_address:

            packets_received += 1

            if source:
                inbound_ips.add(source)

    # -----------------------------
    # Investigate TCP SYN activity
    # specifically from this host
    # -----------------------------

    syn_output = run_tshark([
        "-Y",
        (
            f"ip.src == {ip_address} && "
            "tcp.flags.syn == 1 && "
            "tcp.flags.ack == 0"
        ),
        "-T", "fields",
        "-e", "ip.dst",
        "-e", "tcp.dstport"
    ])

    syn_attempts = 0

    syn_destinations = set()
    syn_ports = set()

    for line in syn_output.splitlines():

        parts = line.split("\t")

        if len(parts) >= 2:

            destination = parts[0]
            port = parts[1]

            syn_attempts += 1

            if destination:
                syn_destinations.add(destination)

            if port:
                syn_ports.add(port)

    return {

        "ip_address": ip_address,

        "packets_sent": packets_sent,
        "packets_received": packets_received,

        "unique_outbound_ips": len(outbound_ips),
        "unique_inbound_ips": len(inbound_ips),

        "sample_outbound_ips": sorted(
            outbound_ips
        )[:20],

        "outbound_tcp_destination_ports": sorted(
            outbound_tcp_ports
        ),

        "outbound_udp_destination_ports": sorted(
            outbound_udp_ports
        ),

        "tcp_syn_activity": {

            "syn_attempts": syn_attempts,

            "unique_syn_destinations": len(
                syn_destinations
            ),

            "unique_syn_destination_ports": len(
                syn_ports
            ),

            "syn_destination_ports": sorted(
                syn_ports
            )
        }
    }

def get_tcp_flag_summary():
    """
    Summarize TCP flag combinations in the PCAP.

    This helps the AI identify TCP probing behavior
    that may not appear as a normal SYN scan.
    """

    output = run_tshark([
        "-Y", "tcp",
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "tcp.flags",
        "-e", "tcp.flags.syn",
        "-e", "tcp.flags.ack",
        "-e", "tcp.flags.fin",
        "-e", "tcp.flags.reset"
    ])

    total_tcp = 0

    syn_only = 0
    syn_ack = 0
    ack_only = 0
    fin_packets = 0
    rst_packets = 0

    sources = Counter()
    destinations = Counter()

    ack_probe_activity = {}

    for line in output.splitlines():

        parts = line.split("\t")

        while len(parts) < 9:
            parts.append("")

        source = parts[0]
        destination = parts[1]
        destination_port = parts[3]

        # TShark returns True / False
        syn = parts[5].lower() == "true"
        ack = parts[6].lower() == "true"
        fin = parts[7].lower() == "true"
        rst = parts[8].lower() == "true"

        total_tcp += 1

        if source:
            sources[source] += 1

        if destination:
            destinations[destination] += 1

        if syn and not ack:
            syn_only += 1

        if syn and ack:
            syn_ack += 1

        if ack and not syn and not fin and not rst:
            ack_only += 1

            key = (source, destination)

            if key not in ack_probe_activity:
                ack_probe_activity[key] = {
                    "packets": 0,
                    "ports": set()
                }

            ack_probe_activity[key]["packets"] += 1

            if destination_port:
                ack_probe_activity[key]["ports"].add(
                    destination_port
                )

        if fin:
            fin_packets += 1

        if rst:
            rst_packets += 1

    ack_activity = []

    for (source, destination), data in ack_probe_activity.items():

        ack_activity.append({
            "source": source,
            "destination": destination,
            "ack_packets": data["packets"],
            "unique_destination_ports": len(
                data["ports"]
            ),
            "destination_ports": sorted(
                data["ports"]
            )
        })

    return {
        "total_tcp_packets": total_tcp,

        "tcp_flags": {
            "syn_without_ack": syn_only,
            "syn_ack": syn_ack,
            "ack_without_syn_fin_rst": ack_only,
            "fin": fin_packets,
            "rst": rst_packets
        },

        "ack_probe_activity": ack_activity,

        "top_sources": [
            {
                "ip": ip,
                "packets": count
            }
            for ip, count in sources.most_common(10)
        ],

        "top_destinations": [
            {
                "ip": ip,
                "packets": count
            }
            for ip, count in destinations.most_common(10)
        ]
    }

def analyze_pcap():
    """Run all available security analyses."""

    dns = get_dns_summary()
    syn = get_syn_summary()
    port_scan = detect_port_scan()
    dns_anomalies = detect_dns_anomalies()

    return {
        "network": {
            "dns_queries": dns["total_queries"],
            "unique_domains": dns["unique_domains"],
            "syn_attempts": syn["total_syn_attempts"],
            "unique_destination_ips": syn["unique_destination_ips"],
            "unique_destination_ports": syn["unique_destination_ports"]
        },
        "top_dns_domains": dns["top_domains"],
        "top_destination_ports": syn["top_ports"],
        "port_scan_findings": port_scan,
        "dns_anomalies": dns_anomalies
    }


if __name__ == "__main__":

    results = get_tcp_flag_summary()

    print(json.dumps(
        results,
        indent=2
    ))