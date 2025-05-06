# utils/ssl_checker.py

import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime

def check_ssl_certificate(url):
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        port = 443

        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        # Extract expiration date
        expires = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        issuer = dict(x[0] for x in cert['issuer'])
        subject = dict(x[0] for x in cert['subject'])

        return {
            "valid": True,
            "hostname": hostname,
            "issuer": issuer.get("organizationName", "Unknown"),
            "subject": subject.get("commonName", "Unknown"),
            "expires_on": expires.strftime("%Y-%m-%d"),
        }

    except Exception as e:
        return {
            "valid": False,
            "error": str(e)
        }
