import difflib
from urllib.parse import urlparse
from colorama import init, Fore
import requests
from bs4 import BeautifulSoup
import base64

# تفعيل Colorama
init(autoreset=True)

# كلمات مشبوهة قد تدل على صفحة تصيد
SUSPICIOUS_KEYWORDS = [
    "login", "account", "verify", "update", "secure", "bank", "password",
    "reset", "paypal", "signin", "confirm", "webscr", "auth", "wp", "admin"
]

# مواقع مشهورة يتم تقليدها
POPULAR_DOMAINS = [
    "facebook.com", "google.com", "paypal.com", "microsoft.com", "apple.com",
    "amazon.com", "instagram.com", "bankofamerica.com", "netflix.com", "twitter.com"
]

# قائمة نطاقات معروفة بأنها خبيثة
BLACKLISTED_DOMAINS = [
    "woershiduoqipa.cc", "1drvemail.com", "secure-paypal-login.net", "micros0ft.support"
]

# ضع مفتاح API الخاص بك من VirusTotal هنا
VT_API_KEY = "e17c8e8f44baedb47bf996b2b854785a8680a3ab09358f6527916ed58fc10a9e"


def is_suspicious_domain(domain):
    domain_clean = domain.replace('.', '')
    if len(domain_clean) < 6:
        return True
    digits = sum(c.isdigit() for c in domain_clean)
    symbols = sum(not c.isalnum() for c in domain_clean)
    digit_ratio = digits / len(domain_clean) if len(domain_clean) > 0 else 0
    symbol_ratio = symbols / len(domain_clean) if len(domain_clean) > 0 else 0
    if digit_ratio > 0.3 or symbol_ratio > 0.2:
        return True
    return False


def looks_like_legit_site(domain):
    for legit in POPULAR_DOMAINS:
        similarity = difflib.SequenceMatcher(None, domain, legit).ratio()
        if similarity > 0.75 and domain != legit:
            return True, legit
    return False, None


def has_suspicious_keywords(text):
    text_lower = text.lower()
    return any(word in text_lower for word in SUSPICIOUS_KEYWORDS)


def analyze_url(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    full_url = parsed.geturl()

    print(f"\n🔎 Analyzing URL: {Fore.CYAN}{full_url}")
    print(f"🌐 Domain: {Fore.YELLOW}{domain}")

    flagged = []

    if domain in BLACKLISTED_DOMAINS:
        flagged.append("🚫 Domain is blacklisted")

    if is_suspicious_domain(domain):
        flagged.append("⚠️ Domain structure is suspicious")

    looks_like, legit = looks_like_legit_site(domain)
    if looks_like:
        flagged.append(f"⚠️ Domain mimics popular site: {legit}")

    if has_suspicious_keywords(full_url):
        flagged.append("⚠️ URL contains phishing-related keywords")

    if flagged:
        print(f"\n{Fore.RED}❗ Potential threats detected:")
        for reason in flagged:
            print(f" - {Fore.RED}{reason}")
    else:
        print(f"{Fore.GREEN}✅ URL looks safe based on current checks.")

    return domain, full_url


def fetch_site_content(url):
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.text
        else:
            print(f"⚠️ Failed to fetch page, status code: {response.status_code}")
            return None
    except Exception as e:
        print(f"❌ Error fetching page content: {e}")
        return None


def analyze_html(html):
    soup = BeautifulSoup(html, 'html.parser')
    forms = soup.find_all('form')
    login_forms = [form for form in forms if form.find('input', {'type': 'password'})]

    if login_forms:
        print(f"\n{Fore.RED}⚠️ Found login form(s). Possible phishing attempt.")

    text = soup.get_text().lower()
    keywords_found = [word for word in SUSPICIOUS_KEYWORDS if word in text]
    if keywords_found:
        print(f"{Fore.RED}⚠️ Suspicious keywords in page content: {', '.join(keywords_found)}")
    else:
        print(f"{Fore.GREEN}✅ Page content seems normal.")


def virustotal_check(url):
    headers = {"x-apikey": VT_API_KEY}
    api_url = "https://www.virustotal.com/api/v3/urls"

    try:
        url_bytes = url.encode()
        encoded_url = base64.urlsafe_b64encode(url_bytes).decode().strip("=")
        full_api_url = f"{api_url}/{encoded_url}"
        response = requests.get(full_api_url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)

            print(f"\n{Fore.MAGENTA}🔬 VirusTotal Analysis:")
            print(f" Harmless: {harmless}")
            print(f" Malicious: {malicious}")
            print(f" Suspicious: {suspicious}")
            print(f" Undetected: {undetected}")

            if malicious > 0 or suspicious > 0:
                print(f"{Fore.RED}❗ VirusTotal reports this URL as potentially dangerous.")
            else:
                print(f"{Fore.GREEN}✅ VirusTotal reports this URL as safe.")
        else:
            print(f"{Fore.YELLOW}⚠️ VirusTotal API request failed with status {response.status_code}")
    except Exception as e:
        print(f"{Fore.YELLOW}⚠️ VirusTotal API error: {e}")


if __name__ == "__main__":
    url = input("🔗 Enter a URL to check: ")
    domain, full_url = analyze_url(url)
    html = fetch_site_content(url)
    if html:
        analyze_html(html)
    virustotal_check(url)
