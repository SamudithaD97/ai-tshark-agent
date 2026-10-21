from tshark_tools import (
    get_dns_summary,
    get_syn_summary,
    detect_port_scan,
    detect_dns_anomalies
)


def run_agent():
    print("===================================")
    print("      AI NETWORK SECURITY AGENT")
    print("===================================\n")

    print("[Agent] I need an overview of the network.")

    network = get_syn_summary()

    print("[Agent] Network information collected.")
    print(f"[Agent] SYN attempts: {network['total_syn_attempts']}")
    print(
        f"[Agent] Unique destination IPs: "
        f"{network['unique_destination_ips']}"
    )
    print(
        f"[Agent] Unique destination ports: "
        f"{network['unique_destination_ports']}"
    )

    # Agent decision
    if network["unique_destination_ports"] >= 20:

        print("\n[Agent] Many ports were contacted.")
        print("[Agent] I should investigate possible port scanning.")

        findings = detect_port_scan()

        if findings:
            print("[Agent] Possible port scanning found.")
            print(findings)
        else:
            print("[Agent] Port scan investigation found nothing.")

    else:

        print("\n[Agent] The number of destination ports is low.")
        print("[Agent] Port scanning does not appear obvious.")

    print("\n[Agent] I will now investigate DNS activity.")

    dns = get_dns_summary()

    print(
        f"[Agent] DNS queries: "
        f"{dns['total_queries']}"
    )

    print(
        f"[Agent] Unique domains: "
        f"{dns['unique_domains']}"
    )

    anomalies = detect_dns_anomalies()

    if anomalies:

        print("\n[Agent] I found potentially unusual DNS names.")

        for anomaly in anomalies:
            print(
                f"  Domain: {anomaly['domain']}"
            )
            print(
                f"  Reason: {anomaly['reason']}"
            )

    else:

        print("\n[Agent] No obvious DNS anomalies found.")

    print("\n[Agent] Investigation complete.")


if __name__ == "__main__":
    run_agent()