import requests
import os
from urllib.parse import urlparse

API_KEY = "Enter_Your_API_Here"

def check_virustotal(url):
    parsed = urlparse(url)
    domain = parsed.netloc

    headers = {
        "x-apikey": API_KEY
    }

    response = requests.get(
        f"https://www.virustotal.com/api/v3/domains/{domain}",
        headers=headers
    )

    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        return {
            "harmless": stats['harmless'],
            "malicious": stats['malicious'],
            "suspicious": stats['suspicious'],
            "undetected": stats['undetected']
        }
    else:
        return {
            "error": f"API request failed with status code {response.status_code}"
        }
