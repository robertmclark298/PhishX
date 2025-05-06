import difflib
import unicodedata
import re
import idna
from urllib.parse import urlparse
from confusables import is_confusable
from Levenshtein import distance as levenshtein_distance

# Set similarity threshold (tune if needed)
SIMILARITY_THRESHOLD = 0.75

# Normalize domain to punycode and remove www
def normalize_domain(domain):
    domain = domain.lower().strip()
    domain = domain.replace("www.", "")
    try:
        domain = idna.decode(domain)
    except:
        pass
    return domain

def is_similar_to_trusted(domain, trusted_domains):
    domain = normalize_domain(domain)

    for trusted in trusted_domains:
        trusted_norm = normalize_domain(trusted)

        # Basic string ratio (difflib)
        ratio = difflib.SequenceMatcher(None, domain, trusted_norm).ratio()

        # Levenshtein visual similarity
        lev_distance = levenshtein_distance(domain, trusted_norm)
        max_len = max(len(domain), len(trusted_norm))
        visual_similarity = 1 - (lev_distance / max_len)

        # Combine similarity
        score = max(ratio, visual_similarity)

        if score >= SIMILARITY_THRESHOLD:
            return True, trusted_norm, round(score, 2)

        # Unicode confusable fallback
        if is_confusable(domain, trusted_norm):
            return True, trusted_norm, round(score, 2)

    return False, None, None

def contains_suspicious_unicode(domain):
    # If the domain has non-ASCII chars, raise a flag
    return not all(ord(char) < 128 for char in domain)
