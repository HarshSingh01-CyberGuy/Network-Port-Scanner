def analyze_port(port, service, product, version):
    """
    Analyze an open port and assign a basic risk level.
    """

    service = service.lower()

    high_risk_ports = {
        21: "FTP may transmit data without encryption.",
        23: "Telnet is insecure and sends data in plaintext.",
        445: "SMB can be a high-risk exposed service.",
        3389: "RDP should not be unnecessarily exposed."
    }

    medium_risk_ports = {
        22: "SSH should use strong authentication and secure configuration.",
        25: "SMTP may require additional security controls.",
        3306: "MySQL should generally not be publicly exposed.",
        5432: "PostgreSQL should generally not be publicly exposed."
    }

    if port in high_risk_ports:

        risk = "HIGH"

        recommendation = high_risk_ports[port]

        reason = (
            "This service is commonly associated with "
            "increased exposure when unnecessarily accessible."
        )

    elif port in medium_risk_ports:

        risk = "MEDIUM"

        recommendation = medium_risk_ports[port]

        reason = (
            "This service can provide useful functionality "
            "but should be securely configured and restricted."
        )

    elif port == 80:

        risk = "MEDIUM"

        recommendation = (
            "HTTP traffic is unencrypted. Prefer HTTPS."
        )

        reason = (
            "HTTP does not provide encryption for normal web traffic."
        )

    elif port == 443:

        risk = "LOW"

        recommendation = (
            "HTTPS detected. Verify certificate and TLS configuration."
        )

        reason = (
            "HTTPS provides encrypted communication, but "
            "TLS configuration should still be reviewed."
        )

    else:

        risk = "LOW"

        recommendation = (
            "Review whether this service is required."
        )

        reason = (
            "The detected port is not included in the predefined "
            "higher-risk service rules."
        )

    return {
        "port": port,
        "service": service or "unknown",
        "product": product or "Unknown",
        "version": version or "Unknown",
        "risk": risk,
        "recommendation": recommendation,
        "reason": reason
    }


def analyze_scan(scanner):
    """
    Analyze all open ports returned by python-nmap.
    """

    results = []

    for host in scanner.all_hosts():

        for protocol in scanner[host].all_protocols():

            for port in sorted(
                scanner[host][protocol].keys()
            ):

                port_data = scanner[host][protocol][port]

                if port_data["state"] == "open":

                    result = analyze_port(
                        port,
                        port_data.get(
                            "name",
                            "unknown"
                        ),
                        port_data.get(
                            "product",
                            ""
                        ),
                        port_data.get(
                            "version",
                            ""
                        )
                    )

                    result["host"] = host
                    result["protocol"] = protocol

                    results.append(result)

    return results


def print_analysis(results):
    """
    Display security analysis in terminal.
    """

    print("\n" + "=" * 70)
    print("SECURITY ANALYSIS")
    print("=" * 70)

    if not results:

        print("No open ports detected.")
        return

    for result in results:

        print(
            f"\nHost           : "
            f"{result['host']}"
        )

        print(
            f"Port           : "
            f"{result['port']}"
        )

        print(
            f"Protocol       : "
            f"{result.get('protocol', 'tcp')}"
        )

        print(
            f"Service        : "
            f"{result['service']}"
        )

        print(
            f"Product        : "
            f"{result['product']}"
        )

        print(
            f"Version        : "
            f"{result['version']}"
        )

        print(
            f"Risk Level     : "
            f"{result['risk']}"
        )

        print(
            f"Reason         : "
            f"{result['reason']}"
        )

        print(
            f"Recommendation : "
            f"{result['recommendation']}"
        )

        print("-" * 70)