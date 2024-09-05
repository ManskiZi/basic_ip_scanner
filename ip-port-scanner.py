import nmap

#!/usr/bin/env python3


def stealth_scan_with_decoy(ip_address, decoys):
    # Initialize the nmap scanner
    nm = nmap.PortScanner()

    # Create the decoy string
    decoy_str = ",".join(decoys)

    print(f"Starting stealth scan (SYN scan) with decoys on {ip_address}...")

    try:
        # Perform the scan with SYN scan, decoys, and packet fragmentation (-f)
        scan_result = nm.scan(
            hosts=ip_address,
            arguments=f'-sS -D {decoy_str} -f -T4'
        )
    except nmap.PortScannerError as e:
        print(f"Error: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error: {e}")
        return None

    # Check if the scan result contains the IP address
    if ip_address not in nm.all_hosts():
        print(f"Error: Target IP {ip_address} cannot be scanned.")
        return None

    # Get the scanned ports
    open_ports = []
    for protocol in nm[ip_address].all_protocols():
        lport = nm[ip_address][protocol].keys()
        for port in lport:
            state = nm[ip_address][protocol][port]['state']
            if state == 'open':
                open_ports.append(port)

    return open_ports

if __name__ == '__main__':
    ip = input("Enter the IP address to scan: ")
    decoy_ips = input("Enter decoy IP addresses, separated by commas: ").split(',')

    open_ports = stealth_scan_with_decoy(ip, decoy_ips)

    if open_ports is None:
        print("Scan failed or was aborted.")
    elif open_ports:
        print(f"Open ports found on {ip}: {', '.join(map(str, open_ports))}")
    else:
        print(f"No open ports found on {ip}.")