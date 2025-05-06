def calculate_phishing_score(ssl_result, domain_info, vt_result):
    score = 0
    reasons = []

    # SSL certificate validity
    if not ssl_result["valid"]:
        score += 10
        reasons.append("Invalid or missing SSL certificate.")

    # Domain age (new domains are suspicious)
    try:
        creation_dates = domain_info.get("creation_date", [])
        if creation_dates:
            from datetime import datetime
            domain_age_days = (datetime.now() - creation_dates[0]).days
            if domain_age_days < 90:
                score += 15
                reasons.append(f"Domain is newly registered ({domain_age_days} days old).")
    except:
        pass

    # VirusTotal result
    if isinstance(vt_result, dict):
        malicious = vt_result.get('malicious', 0)
        suspicious = vt_result.get('suspicious', 0)
        total_detections = malicious + suspicious
        if total_detections > 0:
            vt_score = min(total_detections * 5, 50)
            score += vt_score
            reasons.append(f"VirusTotal marked the link as malicious/suspicious ({total_detections} detections).")

    return {
        "score": min(score, 100),
        "reasons": reasons
    }
