# utils/domain_info.py

import whois

def get_domain_info(url):
    try:
        domain = whois.whois(url)
        return {
            "domain_name": domain.domain_name,
            "registrar": domain.registrar,
            "creation_date": str(domain.creation_date),
            "expiration_date": str(domain.expiration_date),
            "name_servers": domain.name_servers,
        }
    except Exception as e:
        return {
            "error": f"Domain lookup failed: {e}"
        }
