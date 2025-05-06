import os

def load_trusted_domains():
    trusted_path = os.path.join(os.path.dirname(__file__), "..", "trusted_domains.txt")
    with open(trusted_path, 'r') as file:
        return [line.strip().lower() for line in file if line.strip()]

def is_trusted_domain(domain):
    trusted_domains = load_trusted_domains()
    return domain.lower() in trusted_domains
