from urllib.parse import urlparse, urljoin
import re
import requests
from bs4 import BeautifulSoup
import datetime
import whois


def extract_url_features(url: str) -> list:
    features = []

    domain = urlparse(url).netloc
    scheme = urlparse(url).scheme
    path = urlparse(url).path
    query = urlparse(url).query

    features.append(1 if re.match(r"^(http[s]?://)?\d{1,3}(\.\d{1,3}){3}", url) else 0)

    features.append(1 if len(url) > 75 else 0)

    shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co', 'is.gd', 'buff.ly', 'adf.ly']
    features.append(1 if any(short in url for short in shorteners) else 0)

    features.append(1 if "@" in url else 0)

    features.append(1 if "//" in path else 0)

    features.append(1 if "-" in domain else 0)

    features.append(domain.count("."))

    features.append(1 if scheme == "https" else 0)

    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date and isinstance(creation_date, datetime.datetime):
            age = (datetime.datetime.now() - creation_date).days / 365
            features.append(1 if age >= 1 else 0)
        else:
            features.append(0)
    except Exception:
        features.append(0)

    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")
        favicon = soup.find("link", rel="shortcut icon")
        if favicon and "href" in favicon.attrs:
            favicon_url = urljoin(url, favicon["href"])
            favicon_domain = urlparse(favicon_url).netloc
            features.append(1 if favicon_domain != domain else 0)
        else:
            features.append(0)
    except Exception:
        features.append(0)

    port = urlparse(url).port
    if port is None:
        features.append(0)
    else:
        features.append(1 if port not in [80, 443] else 0)

    features.append(1 if "https" in domain else 0)

    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")
        total_resources = len(soup.find_all(['img', 'script', 'link']))
        external_resources = 0
        for tag in soup.find_all(['img', 'script', 'link']):
            src = tag.get('src') or tag.get('href')
            if src:
                src_domain = urlparse(urljoin(url, src)).netloc
                if src_domain and src_domain != domain:
                    external_resources += 1
        percent_external = (external_resources / total_resources) * 100 if total_resources > 0 else 0
        features.append(1 if percent_external > 50 else 0)
    except Exception:
        features.append(0)

    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")
        anchors = soup.find_all('a')
        total_anchors = len(anchors)
        external_anchors = 0
        for a in anchors:
            href = a.get('href')
            if href:
                href_domain = urlparse(urljoin(url, href)).netloc
                if href_domain and href_domain != domain:
                    external_anchors += 1
        percent_external_anchors = (external_anchors / total_anchors) * 100 if total_anchors > 0 else 0
        features.append(1 if percent_external_anchors > 50 else 0)
    except Exception:
        features.append(0)

    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")
        scripts = soup.find_all('script')
        total_scripts = len(scripts)
        links_in_scripts = 0
        for script in scripts:
            if script.string:
                links_in_scripts += len(re.findall(r'http[s]?://', script.string))
        percent_links_in_scripts = (links_in_scripts / total_scripts) * 100 if total_scripts > 0 else 0
        features.append(1 if percent_links_in_scripts > 50 else 0)
    except Exception:
        features.append(0)

    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")
        forms = soup.find_all('form')
        suspicious_forms = 0
        total_forms = len(forms)
        for form in forms:
            action = form.get('action')
            if not action or action == "" or (urlparse(action).netloc != "" and urlparse(action).netloc != domain):
                suspicious_forms += 1
        features.append(1 if total_forms > 0 and (suspicious_forms / total_forms) > 0.5 else 0)
    except Exception:
        features.append(0)

    try:
        r = requests.get(url, timeout=5)
        if "mailto:" in r.text.lower():
            features.append(1)
        else:
            features.append(0)
    except Exception:
        features.append(0)

    features.append(1 if len(url) > 75 or "@" in url else 0)

    try:
        response = requests.get(url, timeout=5)
        features.append(1 if len(response.history) > 2 else 0)
    except Exception:
        features.append(0)

    features.append(0)

    features.append(0)

    features.append(0)

    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")
        iframes = soup.find_all('iframe')
        suspicious_iframes = 0
        for iframe in iframes:
            src = iframe.get('src')
            if src:
                src_domain = urlparse(urljoin(url, src)).netloc
                if src_domain != domain:
                    suspicious_iframes += 1
        features.append(1 if len(iframes) > 0 and (suspicious_iframes / len(iframes)) > 0.5 else 0)
    except Exception:
        features.append(0)

    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date and isinstance(creation_date, datetime.datetime):
            age_months = (datetime.datetime.now() - creation_date).days / 30
            features.append(1 if age_months > 6 else 0)
        else:
            features.append(0)
    except Exception:
        features.append(0)

    try:
        w = whois.whois(domain)
        features.append(1 if w.domain_name else 0)
    except Exception:
        features.append(0)

    features.append(0)

    features.append(0)

    features.append(0)

    features.append(0)

    features.append(0)

    return features

