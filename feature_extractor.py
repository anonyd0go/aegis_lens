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

# --- IMPROVEMENT 1: Trusted Domain Allowlist ---
# Major legitimate sites that should have relaxed feature extraction
TRUSTED_DOMAINS = {
    # Search engines and major platforms
    'google.com', 'www.google.com', 'accounts.google.com', 'mail.google.com',
    'youtube.com', 'www.youtube.com',
    'bing.com', 'www.bing.com',
    
    # Social media
    'facebook.com', 'www.facebook.com', 'm.facebook.com',
    'twitter.com', 'www.twitter.com', 'x.com', 'www.x.com',
    'linkedin.com', 'www.linkedin.com',
    'instagram.com', 'www.instagram.com',
    
    # E-commerce and payment
    'amazon.com', 'www.amazon.com',
    'ebay.com', 'www.ebay.com',
    'paypal.com', 'www.paypal.com',
    'stripe.com', 'www.stripe.com',
    
    # Banking (major US banks)
    'chase.com', 'www.chase.com',
    'bankofamerica.com', 'www.bankofamerica.com',
    'wellsfargo.com', 'www.wellsfargo.com',
    'citi.com', 'www.citi.com',
    
    # Tech companies
    'microsoft.com', 'www.microsoft.com', 'login.microsoftonline.com',
    'apple.com', 'www.apple.com', 'appleid.apple.com',
    'github.com', 'www.github.com',
    'gitlab.com', 'www.gitlab.com',
    
    # Email providers
    'gmail.com', 'mail.google.com',
    'outlook.com', 'outlook.live.com', 'login.live.com',
    'yahoo.com', 'mail.yahoo.com',
    
    # Cloud services
    'dropbox.com', 'www.dropbox.com',
    'box.com', 'www.box.com',
    'drive.google.com',
    'onedrive.live.com',
}

def is_trusted_domain(domain):
    """Check if a domain is in our trusted allowlist."""
    return domain.lower() in TRUSTED_DOMAINS

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
    """
    IMPROVED: Checks if the page's domain appears infrequently as anchor text in hyperlinks.
    Now accounts for icon-based navigation and trusted domains.
    """
    # For trusted domains, we expect less text-based navigation
    if is_trusted_domain(domain):
        return 0
    
    total_links_with_text = 0
    domain_in_anchor_count = 0
    domain_base = domain.replace('www.', '').split('.')[0]

    # Also check for aria-label and title attributes (common in icon navigation)
    for a in soup.find_all('a', href=True):
        link_text = ""
        
        # Check actual text content
        if a.string:
            link_text = a.string.lower()
            total_links_with_text += 1
        # Check aria-label
        elif a.get('aria-label'):
            link_text = a.get('aria-label', '').lower()
            total_links_with_text += 1
        # Check title attribute
        elif a.get('title'):
            link_text = a.get('title', '').lower()
            total_links_with_text += 1
            
        if link_text and domain_base in link_text:
            domain_in_anchor_count += 1

    if total_links_with_text == 0:
        return 0
        
    match_ratio = (domain_in_anchor_count / total_links_with_text)
    # Increased threshold for modern sites with icon navigation
    return 1 if match_ratio < 0.10 else 0

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

def get_num_sensitive_words(soup, domain):
    """
    IMPROVED: Now returns density (sensitive words / total words) instead of raw count.
    Also adjusts for trusted domains.
    """
    sensitive_words = ["login", "password", "verify", "account", "update", "secure", "signin", "banking", "confirm"]
    
    # For trusted domains, use a more specific set of suspicious phrases
    if is_trusted_domain(domain):
        # These are more indicative of phishing on trusted domains
        sensitive_words = ["suspended", "locked", "verify immediately", "urgent action", "click here immediately",
                          "confirm identity", "unusual activity", "temporary suspension"]
    
    # Remove script, style, and metadata
    for script_or_style in soup(["script", "style", "head", "title", "meta", "[document]"]):
        script_or_style.extract()
    
    text = soup.get_text(separator=' ', strip=True).lower()
    words = text.split()
    total_words = len(words)
    
    if total_words == 0:
        return 0
    
    # Count occurrences
    count = 0
    for word in sensitive_words:
        count += text.count(word)
    
    # Return density instead of raw count
    # Cap at 1.0 to maintain expected range
    density = min(count / total_words, 1.0)
    
    # For model compatibility, scale to similar range as before
    # Average legitimate page might have 5-10 sensitive words in 500-1000 words
    # So multiply by 100 to get similar scale to raw count
    return density * 100

def get_pct_ext_null_self_redirect_hyperlinks_rt(pct_null_href, domain):
    """
    IMPROVED: Risk-tiered version with relaxed thresholds for trusted domains.
    """
    if is_trusted_domain(domain):
        # Trusted domains often have more JS-based navigation
        if pct_null_href > 0.5:  # Much higher threshold
            return 1  # High Risk
        elif 0.3 <= pct_null_href <= 0.5:
            return 0  # Medium Risk
        else:
            return -1 # Low Risk
    else:
        # Original thresholds for unknown domains
        if pct_null_href > 0.31:
            return 1  # High Risk
        elif 0.15 <= pct_null_href <= 0.31:
            return 0  # Medium Risk
        else:
            return -1 # Low Risk

def get_ext_meta_script_link_rt(soup, domain):
    """
    IMPROVED: Risk-tiered feature with consideration for CDN usage by trusted domains.
    """
    total_resources = 0
    external_resources = 0
    page_url = f"https://{domain}"
    
    # Common legitimate CDNs
    legitimate_cdns = {
        'googleapis.com', 'gstatic.com', 'cloudflare.com', 'jsdelivr.net',
        'unpkg.com', 'cdnjs.cloudflare.com', 'maxcdn.bootstrapcdn.com',
        'ajax.googleapis.com', 'fonts.googleapis.com', 'fontawesome.com',
        'jquery.com', 'bootstrapcdn.com', 'cloudfront.net'
    }

    for tag in soup.find_all(['script', 'link'], src=True) + soup.find_all('link', href=True):
        attr = 'src' if tag.has_attr('src') else 'href'
        url = tag.get(attr, '').strip()
        if not url:
            continue
            
        total_resources += 1
        absolute_url = urljoin(page_url, url)
        parsed_resource_url = urlparse(absolute_url)
        
        if parsed_resource_url.netloc and parsed_resource_url.netloc != domain:
            # Check if it's from a legitimate CDN
            is_cdn = any(cdn in parsed_resource_url.netloc for cdn in legitimate_cdns)
            if not is_cdn or not is_trusted_domain(domain):
                external_resources += 1

    ratio = (external_resources / total_resources) if total_resources > 0 else 0.0
    
    # Adjusted thresholds for trusted domains
    if is_trusted_domain(domain):
        if ratio >= 0.9:  # Very high threshold for trusted domains
            return 1  # High Risk
        else:
            return -1 # Low Risk for trusted domains
    else:
        # Original thresholds for unknown domains
        if ratio >= 0.8125:
            return 1  # High Risk
        elif 0.61 <= ratio < 0.8125:
            return 0  # Medium Risk
        else:
            return -1 # Low Risk

# --- Main Orchestrator Function ---

def extract_features(url, html_content):
    """
    IMPROVED: Extracts features with consideration for trusted domains to reduce false positives.
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
        features['NumSensitiveWords'] = get_num_sensitive_words(soup, domain)
        
        # Risk-tiered features (now domain-aeare)
        features['PctExtNullSelfRedirectHyperlinksRT'] = get_pct_ext_null_self_redirect_hyperlinks_rt(pct_null_href, domain)
        features['ExtMetaScriptLinkRT'] = get_ext_meta_script_link_rt(soup, domain)
        
    except Exception as e:
        print(f"Error during feature extraction for {url}: {e}")
        return [0] * len(FEATURE_ORDER)

    return [features.get(f, 0) for f in FEATURE_ORDER]
