import nmap
from analyzer import analyze_scan, print_analysis


def scan_target(target, scan_arguments="-sV"):
    """
    Scan an authorized target using Nmap.

    Parameters:
        target (str): IP address or hostname.
        scan_arguments (str): Nmap arguments.

    Returns:
        nmap.PortScanner: Completed scanner object.
    """

    scanner = nmap.PortScanner()

    print(f"Scanning target: {target}")
    print(f"Nmap arguments: {scan_arguments}")

    scanner.scan(
        target,
        arguments=scan_arguments
    )

    return scanner


def get_raw_results(scanner):
    """
    Extract raw scan information from the Nmap scanner object.
    """

    results = []

    for host in scanner.all_hosts():

        host_state = scanner[host].state()

        for protocol in scanner[host].all_protocols():

            for port in sorted(
                scanner[host][protocol].keys()
            ):

                port_data = scanner[host][protocol][port]

                results.append(
                    {
                        "host": host,
                        "protocol": protocol,
                        "port": port,
                        "state": port_data.get(
                            "state",
                            "unknown"
                        ),
                        "service": port_data.get(
                            "name",
                            "unknown"
                        ),
                        "product": port_data.get(
                            "product",
                            ""
                        ),
                        "version": port_data.get(
                            "version",
                            ""
                        ),
                        "host_state": host_state
                    }
                )

    return results


def display_scan(scanner):
    """
    Display raw Nmap scan results in terminal.
    """

    raw_results = get_raw_results(scanner)

    if not raw_results:
        print("\nNo scan results found.")
        return

    for result in raw_results:

        print(
            f"Port: {result['port']} | "
            f"State: {result['state']} | "
            f"Service: {result['service']} | "
            f"Product: {result['product']} | "
            f"Version: {result['version']}"
        )


def main():
    """
    Run a default service/version detection scan.
    """

    target = "127.0.0.1"

    scanner = scan_target(
        target,
        "-sV"
    )

    display_scan(scanner)

    results = analyze_scan(scanner)

    print_analysis(results)


if __name__ == "__main__":
    main()