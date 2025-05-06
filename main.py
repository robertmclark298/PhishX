from utils.url_expander import expand_url
from utils.ssl_checker import check_ssl_certificate
from utils.domain_info import get_domain_info
from utils.virustotal_check import check_virustotal
from utils.phishing_score import calculate_phishing_score
from utils.trusted_domains import is_trusted_domain, load_trusted_domains
from utils.similarity_check import advanced_similarity_check
from urllib.parse import urlparse
from utils.domain_similarity import is_similar_to_trusted, contains_suspicious_unicode
from utils.url_features import analyze_url_features
from utils.content_analyzer import analyze_content



import datetime


def base_domain(domain):
    parts = domain.lower().split('.')
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain

def main():
    short_url = input("Enter the short URL: ")
    if not short_url.startswith("http"):
        short_url = "https://" + short_url
    expanded_url = expand_url(short_url)

    if expanded_url == short_url:
        print("Redirection failed or URL is the same as input.")
        return

    print(f"\nExpanded URL: {expanded_url}")
    domain = expanded_url.split('/')[2]

    # Load trusted domains
    trusted_domains = load_trusted_domains()

    if is_trusted_domain(domain):
        print(f"The domain {domain} is trusted. Skipping further checks.")
        return

    # Step 1: SSL Check
    ssl_result = check_ssl_certificate(expanded_url)
    if ssl_result["valid"]:
        print("\nSSL Certificate is valid.")
        print(f"Issued to: {ssl_result['subject']}")
        print(f"Issued by: {ssl_result['issuer']}")
        print(f"Expires on: {ssl_result['expires_on']}")
    else:
        print("\nSSL Certificate is invalid or site is not using HTTPS.")
        print(f"Error: {ssl_result['error']}")

    # Step 2: Domain Info
    domain_info = get_domain_info(expanded_url)
    print(f"\nDomain Info: {domain_info}")

    # Step 3: VirusTotal
    vt_result = check_virustotal(expanded_url)
    print("\nVirusTotal Report:", vt_result)

    # Step 4: Phishing Score
    score_data = calculate_phishing_score(ssl_result, domain_info, vt_result)
    phishing_score = score_data['score']
    reasons = score_data.get('reasons', [])

    # Step 4.1: New Heuristic Checks (URL features)
    url_features = analyze_url_features(expanded_url)

    print("\nURL Features:")
    print(f"- Contains '@' symbol: {url_features['has_at_symbol']}")
    print(f"- URL length: {url_features['url_length']}")
    print(f"- Dash (-) count: {url_features['dash_count']}")
    if url_features["suspicious_tld"]:
        print(f"- Suspicious TLD: {url_features['tld']}")
    else:
        print("- TLD looks normal")

    if url_features["has_at_symbol"]:
        phishing_score += 4
        reasons.append("URL contains '@' symbol (used in obfuscation).")

    if url_features["url_length"] > 100:
        phishing_score += 3
        reasons.append("URL is very long (possible hiding tactics).")

    if url_features["dash_count"] > 3:
        phishing_score += 2
        reasons.append("URL contains too many dashes (can indicate fake subdomains).")

    if url_features["suspicious_tld"]:
        phishing_score += 5
        reasons.append(f"Suspicious TLD used: {url_features['tld']}")

    # Step 5: Advanced Similarity & Port Forwarding
    similarity_result = advanced_similarity_check(domain)
    if similarity_result["port_forwarding_service"]:
        print(f"\nDomain '{domain}' is using a port forwarding service: {similarity_result['port_forwarding_service']}")
        phishing_score += 5
        reasons.append(f"Domain uses port forwarding service: {similarity_result['port_forwarding_service']}")

    if similarity_result["status"]:
        print(f"\nDomain '{domain}' is visually similar to trusted domain '{similarity_result['similar_domain']}' (Similarity Score: {similarity_result['score']:.2f})")
        print("This could be a typosquatting or homograph attack. Proceed with caution.")
        phishing_score += 4
        reasons.append(f"Domain similar to trusted domain '{similarity_result['similar_domain']}' (score: {similarity_result['score']:.2f})")
    else:
        print(f"\nDomain '{domain}' does not closely match any trusted domain.")

    # Step 6: Always run Unicode/Homograph checks
    similar, matched_domain, similarity_score = is_similar_to_trusted(domain, trusted_domains)
    if similar:
        print(f"\nDomain '{domain}' is visually similar to trusted domain '{matched_domain}' (Similarity Score: {similarity_score})")
        phishing_score += 5
        reasons.append(f"Domain '{domain}' is visually similar to '{matched_domain}' (typosquatting/homograph).")

    if contains_suspicious_unicode(domain):
        print(f"\nDomain '{domain}' contains suspicious unicode characters.")
        phishing_score += 5
        reasons.append(f"Domain contains suspicious unicode characters (possible homograph attack).")

     # Step 7: Web Content Analysis
    print("\n[+] Analyzing webpage content...")
    content_result = analyze_content(expanded_url)

    if content_result["error"]:
        print(f"Content analysis failed: {content_result['error']}")
        reasons.append("Failed to analyze content (network or parsing error).")
    else:
        meta = content_result["meta"]
        js = content_result["js"]
        forms = content_result["forms"]

        if meta.get("has_refresh_redirect"):
            phishing_score += 3
            reasons.append("Meta refresh redirect found (possible phishing).")

        if not meta.get("has_description"):
            phishing_score += 1
            reasons.append("No meta description found.")

        if js["uses_eval"] or js["uses_obfuscation"]:
            phishing_score += 4
            reasons.append("JavaScript contains obfuscated or eval() code.")

        if js["external_scripts"] > 5:
            phishing_score += 2
            reasons.append("Too many external scripts used.")

        if forms:
            phishing_score += 3
            reasons.append(f"Page contains suspicious login/auth form(s): {forms}")   

    # Final Output
    print(f"\nPhishing Score: {phishing_score}/100")
    if reasons:
        print("\nReasons for phishing score increment:")
        for reason in reasons:
            print(f"- {reason}")

if __name__ == "__main__":
    main()
