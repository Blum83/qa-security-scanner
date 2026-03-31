"""SSRF protection — block internal/private IP addresses.

WARNING: This protection has a known limitation against DNS rebinding attacks.
The IP address is resolved once at validation time, but the actual HTTP request
made by the scanner (ZAP or Nuclei) will perform its own DNS resolution.
An attacker could use DNS rebinding — initially resolving to a public IP
(passing validation) and then changing to an internal IP when the scanner
makes the actual request.

For stronger protection, consider:
- Network-level blocking (iptables rules blocking egress to private ranges)
- A proxy that re-resolves and validates on each request
- Egress filtering at the infrastructure level
"""

import ipaddress
import socket
from urllib.parse import urlparse

# Private/internal IP ranges to block
BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),  # IPv6 localhost
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
    ipaddress.ip_network("fc00::/7"),  # IPv6 unique local
]

# Allowed schemes
ALLOWED_SCHEMES = {"http", "https"}


class SSRFError(ValueError):
    pass


def validate_url(url: str) -> str:
    """Validate that a URL is safe to scan (not internal/private).
    
    Raises SSRFError if the URL points to an internal resource.
    Returns the validated URL.
    """
    parsed = urlparse(url)
    
    # Check scheme
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise SSRFError(f"Invalid scheme '{parsed.scheme}'. Only HTTP and HTTPS are allowed.")
    
    # Check hostname exists
    hostname = parsed.hostname
    if not hostname:
        raise SSRFError("Could not parse hostname from URL.")
    
    # Resolve hostname to IP
    try:
        addr_infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        raise SSRFError(f"Could not resolve hostname: {hostname}")
    
    # Check all resolved IPs
    for family, _, _, _, sockaddr in addr_infos:
        ip_str = sockaddr[0]
        try:
            ip_addr = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        
        for network in BLOCKED_NETWORKS:
            if ip_addr in network:
                raise SSRFError(
                    f"Access to internal addresses is blocked. "
                    f"{hostname} resolves to {ip_str} which is in {network}."
                )
    
    return url
