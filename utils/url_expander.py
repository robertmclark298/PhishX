# utils/url_expander.py

import time
import undetected_chromedriver as uc
from selenium.webdriver.common.by import By

def expand_url(short_url):
    options = uc.ChromeOptions()
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=1920,1080")
    options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

    driver = uc.Chrome(options=options)

    try:
        driver.get(short_url)
        time.sleep(5)  # wait for redirect to happen
        current_url = driver.current_url

        if "shorturl" in current_url:
            # Redirection didn't happen
            print("Redirection might have failed in headless mode.")
        expanded_url = current_url  # Ensure this is always returned

    except Exception as e:
        print(f"Error expanding URL {short_url}: {e}")
        expanded_url = short_url  # fallback to original URL

    finally:
        driver.quit()

    return expanded_url  # Always return the expanded URL
