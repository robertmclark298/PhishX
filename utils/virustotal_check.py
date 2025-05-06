# # utils/virustotal_check.py

# import requests

# API_KEY = "7d96c7e89fc973f29cefc3955ee7b8c296a08855ae2d134ed9ddfa44f3777ff8"

# def check_virustotal(url):
#     headers = {
#         "x-apikey": API_KEY
#     }
#     params = {"url": url}
#     response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=params)

#     if response.status_code == 200:
#         analysis_url = response.json()["data"]["id"]
#         analysis_response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_url}", headers=headers)

#         if analysis_response.status_code == 200:
#             result = analysis_response.json()
#             stats = result["data"]["attributes"]["stats"]
#             return {
#                 "harmless": stats.get("harmless", 0),
#                 "malicious": stats.get("malicious", 0),
#                 "suspicious": stats.get("suspicious", 0),
#                 "undetected": stats.get("undetected", 0),
#             }

#     return {"error": "Could not analyze URL via VirusTotal"}


# utils/virustotal_check.py

import requests
import os
from urllib.parse import urlparse

API_KEY = "7d96c7e89fc973f29cefc3955ee7b8c296a08855ae2d134ed9ddfa44f3777ff8"

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
