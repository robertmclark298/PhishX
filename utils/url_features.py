from urllib.parse import urlparse

SUSPICIOUS_TLDS = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.work', '.support', '.club']

def analyze_url_features(url):
    features = {
        "has_at_symbol": "@" in url,
        "url_length": len(url),
        "dash_count": url.count("-"),
        "suspicious_tld": False,
        "tld": None
    }

    try:
        domain = urlparse(url).netloc.lower()
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                features["suspicious_tld"] = True
                features["tld"] = tld
                break
    except Exception as e:
        features["error"] = str(e)

    return features
