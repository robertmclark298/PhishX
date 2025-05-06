# utils/similarity_check.py

import os
from difflib import SequenceMatcher

# List of known port forwarding / tunneling services
PORT_FORWARDING_DOMAINS = [
    "ngrok.io",
    "loca.lt",
    "replit.dev",
    "glitch.me",
    "vercel.app",
    "localtunnel.me",
    "serveo.net",
    "pagekite.me",
    "fly.dev",
    "render.com"
]

def load_trusted_domains():
    trusted_path = os.path.join(os.path.dirname(__file__), '..', 'trusted_domains.txt')
    with open(trusted_path, 'r') as file:
        return [line.strip().lower() for line in file if line.strip()]

def similarity_score(a, b):
    return SequenceMatcher(None, a, b).ratio() * 100

def check_port_forwarding(domain):
    for service in PORT_FORWARDING_DOMAINS:
        if service in domain:
            return service
    return None

def advanced_similarity_check(input_domain, threshold=80):
    trusted_domains = load_trusted_domains()
    input_domain = input_domain.lower()

    top_match = (None, 0)

    for trusted in trusted_domains:
        score = similarity_score(input_domain, trusted)
        if score > top_match[1]:
            top_match = (trusted, score)

    return {
        "status": top_match[1] >= threshold,
        "similar_domain": top_match[0],
        "score": top_match[1],
        "port_forwarding_service": check_port_forwarding(input_domain)
    }