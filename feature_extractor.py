# feature_extractor.py
# This module contains all logic for converting a URL into a feature vector.

import re
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup, Comment

# This is the definitive
# feature order for the production model, based on feature importance.
FEATURE_ORDER = [
    'PctExtHyperlinks',
    'PctExtNullSelfRedirectHyperlinksRT',
    'FrequentDomainNameMismatch',
    'PctNullSelfRedirectHyperlinks',
    'PctExtResourceUrls',
    'NumDash',
    'InsecureForms',
    'NumNumericChars',
    'PathLevel',
    'SubmitInfoToEmail',
    'ExtMetaScriptLinkRT',
    'NumQueryComponents',
    'NumDots',
    'NumSensitiveWords'
]

# --- Part 1: URL-Based Feature Extractors ---

def get_num_dash(url):
    """Counts the total number of hyphens '-' in the URL."""
    return url.count('-')

def get_num_dots(url):
    """Counts the total number of dots '.' in the URL."""
    return url.count('.')

def get_num_numeric_chars(url):
    """Counts the total number of numeric characters (0-9) in the URL."""
    return sum(c.isdigit() for c in url)

def get_path_level(parsed_url):
    """Calculates the number of levels in the URL's path."""
    path = parsed_url.path.strip('/')
    return path.count('/') + 1 if path else 0

def get_num_query_components(parsed_url):
    """Counts the number of components in the query string."""
    if not parsed_url.query:
        return 0
    return parsed_url.query.count('&') + 1

# --- Part 2: HTML Content-Based Feature Extractors ---

def get_pct_ext_hyperlinks(soup, domain):
    """Percentage of <a> tags pointing to a different domain. Range: 0.0 to 1.0"""
    total_links = 0
    external_links = 0
    page_url = f"https://{domain}"
    
    for a in soup.find_all('a', href=True):
        total_links += 1
        href = a['href'].strip()
        if not href:
            continue

        absolute_href = urljoin(page_url, href)
        parsed_href = urlparse(absolute_href)
        
        if parsed_href.netloc and parsed_href.netloc != domain:
            external_links += 1
            
    return (external_links / total_links) if total_links > 0 else 0.0

def get_pct_ext_resource_urls(soup, domain):
    """Percentage of resource URLs (img, script, link) from an external domain. Range: 0.0 to 1.0"""
    total_resources = 0
    external_resources = 0
    page_url = f"https://{domain}"

    for tag in soup.find_all(['img', 'script', 'link'], src=True) + soup.find_all('link', href=True):
        attr = 'src' if tag.has_attr('src') else 'href'
        url = tag.get(attr, '').strip()
        if not url:
            continue
            
        total_resources += 1
        absolute_url = urljoin(page_url, url)
        parsed_resource_url = urlparse(absolute_url)
        
        if parsed_resource_url.netloc and parsed_resource_url.netloc != domain:
            external_resources += 1
            
    return (external_resources / total_resources) if total_resources > 0 else 0.0

def get_pct_null_self_redirect_hyperlinks(soup):
    """Percentage of <a> tags that are null or self-redirecting. Range: 0.0 to 1.0"""
    total_links = 0
    null_links = 0
    for a in soup.find_all('a', href=True):
        total_links += 1
        href = a['href'].strip()
        if not href or href == '#' or href.lower().startswith('javascript:void(0)'):
            null_links += 1
            
    return (null_links / total_links) if total_links > 0 else 0.0

def get_frequent_domain_name_mismatch(soup, domain):
    """Checks if the page's domain appears infrequently as anchor text in hyperlinks."""
    total_links_with_text = 0
    domain_in_anchor_count = 0
    domain_base = domain.replace('www.', '').split('.')[0]

    for a in soup.find_all('a', href=True, string=True):
        total_links_with_text += 1
        if domain_base in a.string.lower():
            domain_in_anchor_count += 1

    if total_links_with_text == 0:
        return 0
        
    match_ratio = (domain_in_anchor_count / total_links_with_text)
    return 1 if match_ratio < 0.20 else 0

def get_insecure_forms(soup, domain):
    """Checks if any <form> submits to an external domain or over insecure HTTP."""
    page_url = f"https://{domain}"
    for form in soup.find_all('form', action=True):
        action = form['action']
        absolute_action = urljoin(page_url, action)
        parsed_action = urlparse(absolute_action)
        
        if parsed_action.scheme == 'http' or (parsed_action.netloc and parsed_action.netloc != domain):
            return 1
    return 0

def get_submit_info_to_email(soup):
    """Checks if any <form> action submits data to a 'mailto:' address."""
    for form in soup.find_all('form', action=True):
        if form['action'].lower().startswith('mailto:'):
            return 1
    return 0

def get_num_sensitive_words(soup):
    """Counts the occurrence of sensitive words in the page's text content."""
    sensitive_words = ["login", "password", "verify", "account", "update", "secure", "signin", "banking", "confirm"]
    
    for script_or_style in soup(["script", "style", "head", "title", "meta", "[document]"]):
        script_or_style.extract()
    
    text = soup.get_text(separator=' ', strip=True).lower()
    count = 0
    for word in sensitive_words:
        count += text.count(word)
    return count

def get_pct_ext_null_self_redirect_hyperlinks_rt(pct_null_href):
    """Risk-tiered version based on PctNullSelfRedirectHyperlinks. Thresholds are 0.0 to 1.0."""
    if pct_null_href > 0.31:
        return 1  # High Risk
    elif 0.15 <= pct_null_href <= 0.31:
        return 0  # Medium Risk
    else:
        return -1 # Low Risk

def get_ext_meta_script_link_rt(soup, domain):
    """Risk-tiered feature based on the percentage of external <script> and <link> tags. Thresholds are 0.0 to 1.0."""
    total_resources = 0
    external_resources = 0
    page_url = f"https://{domain}"

    for tag in soup.find_all(['script', 'link'], src=True) + soup.find_all('link', href=True):
        attr = 'src' if tag.has_attr('src') else 'href'
        url = tag.get(attr, '').strip()
        if not url:
            continue
            
        total_resources += 1
        absolute_url = urljoin(page_url, url)
        parsed_resource_url = urlparse(absolute_url)
        
        if parsed_resource_url.netloc and parsed_resource_url.netloc != domain:
            external_resources += 1

    ratio = (external_resources / total_resources) if total_resources > 0 else 0.0

    if ratio >= 0.8125:
        return 1  # High Risk
    elif 0.61 <= ratio < 0.8125:
        return 0  # Medium Risk
    else:
        return -1 # Low Risk

# --- Main Orchestrator Function ---

def extract_features(url, html_content):
    """
    Extracts the 14 required features from a URL and its HTML content.
    """
    features = {}
    
    try:
        parsed_url = urlparse(url)
        # Defensive check to ensure domain is always extracted correctly.
        domain = parsed_url.netloc
        if not domain:
            return [0] * len(FEATURE_ORDER) # Return default on parsing failure

        soup = BeautifulSoup(html_content, 'html.parser')

        # --- Part 1: URL-Based Feature Extraction ---
        features['NumDash'] = get_num_dash(url)
        features['NumDots'] = get_num_dots(url)
        features['NumNumericChars'] = get_num_numeric_chars(url)
        features['PathLevel'] = get_path_level(parsed_url)
        features['NumQueryComponents'] = get_num_query_components(parsed_url)

        # --- Part 2: HTML-Based Feature Extraction ---
        features['PctExtHyperlinks'] = get_pct_ext_hyperlinks(soup, domain)
        features['PctExtResourceUrls'] = get_pct_ext_resource_urls(soup, domain)
        
        pct_null_href = get_pct_null_self_redirect_hyperlinks(soup)
        features['PctNullSelfRedirectHyperlinks'] = pct_null_href
        
        features['FrequentDomainNameMismatch'] = get_frequent_domain_name_mismatch(soup, domain)
        features['InsecureForms'] = get_insecure_forms(soup, domain)
        features['SubmitInfoToEmail'] = get_submit_info_to_email(soup)
        features['NumSensitiveWords'] = get_num_sensitive_words(soup)
        
        # Risk-tiered features
        features['PctExtNullSelfRedirectHyperlinksRT'] = get_pct_ext_null_self_redirect_hyperlinks_rt(pct_null_href)
        features['ExtMetaScriptLinkRT'] = get_ext_meta_script_link_rt(soup, domain)
        
    except Exception as e:
        print(f"Error during feature extraction for {url}: {e}")
        return [0] * len(FEATURE_ORDER)

    return [features.get(f, 0) for f in FEATURE_ORDER]
