import requests
from bs4 import BeautifulSoup

def extract_meta_signals(html):
    soup = BeautifulSoup(html, 'html.parser')
    metas = soup.find_all('meta')
    return {
        "has_refresh_redirect": any("refresh" in m.get("http-equiv", "").lower() for m in metas),
        "has_description": any("description" in m.get("name", "").lower() for m in metas),
        "has_author": any("author" in m.get("name", "").lower() for m in metas)
    }

def analyze_javascript(html):
    soup = BeautifulSoup(html, 'html.parser')
    scripts = soup.find_all('script')

    suspicious = {
        "uses_eval": False,
        "uses_obfuscation": False,
        "external_scripts": 0
    }

    for script in scripts:
        content = script.string or ""
        if "eval(" in content:
            suspicious["uses_eval"] = True
        if "atob(" in content or "unescape(" in content:
            suspicious["uses_obfuscation"] = True
        if script.get("src"):
            suspicious["external_scripts"] += 1

    return suspicious

def analyze_forms(html):
    soup = BeautifulSoup(html, 'html.parser')
    forms = soup.find_all('form')
    result = []
    for form in forms:
        action = form.get('action', '')
        if "login" in action or "auth" in action:
            result.append(action)
    return result

def analyze_content(url):
    try:
        response = requests.get(url, timeout=6)
        html = response.text

        meta = extract_meta_signals(html)
        js = analyze_javascript(html)
        forms = analyze_forms(html)

        return {
            "meta": meta,
            "js": js,
            "forms": forms,
            "error": None
        }

    except Exception as e:
        return {"error": str(e)}
