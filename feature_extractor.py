# feature_extractor.py
# This module contains all logic for converting a URL into a feature vector.

import re
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup, Comment

# This is the definitive feature order for the production model, based on feature importance.
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

# --- Trusted Domain Allowlist ---
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

# Known brand names that phishers target
TARGETED_BRANDS = {
    'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
    'netflix', 'ebay', 'chase', 'wellsfargo', 'bankofamerica', 'citi',
    'dropbox', 'linkedin', 'twitter', 'instagram', 'whatsapp', 'spotify',
    'adobe', 'office365', 'outlook', 'allegro', 'alibaba', 'aliexpress'
}

# AGGRESSIVE: Expanded list of suspicious TLDs
SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.click', '.download', '.review',
    '.work', '.date', '.men', '.loan', '.racing', '.win', '.bid',
    '.trade', '.webcam', '.science', '.party', '.kim', '.country',
    '.stream', '.gdn', '.mom', '.xin', '.gq', '.cc', '.pw', '.top',
    '.club', '.buzz', '.biz', '.rocks', '.space', '.site', '.online',
    '.website', '.press', '.fun', '.host', '.store', '.cfd', '.sbs',
    '.rest', '.quest', '.cyou', '.icu', '.uno', '.shop', '.fit',
    '.lat', '.vip', '.live', '.life', '.today', '.world', '.tech'
}

def is_trusted_domain(domain):
    """Check if a domain is in our trusted allowlist."""
    return domain.lower() in TRUSTED_DOMAINS

def get_url_suspicion_score(url, domain):
    """
    Calculate a suspicion score based on URL patterns.
    This helps catch phishing even with empty content.
    """
    score = 0
    url_lower = url.lower()
    domain_lower = domain.lower()
    
    # Check for brand spoofing in domain
    for brand in TARGETED_BRANDS:
        if brand in domain_lower and not is_trusted_domain(domain):
            # Brand name in untrusted domain
            if f'{brand}.com' not in domain_lower and f'www.{brand}.com' not in domain_lower:
                score += 50  # AGGRESSIVE: Increased from 30
    
    # Check for suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if domain_lower.endswith(tld):
            score += 30  # AGGRESSIVE: Increased from 15
            break
    
    # Enhanced: Check for random-looking domains
    domain_parts = domain_lower.split('.')
    if len(domain_parts) >= 2:
        main_domain = domain_parts[0]
        # Check if domain looks random (mix of letters and numbers, short length)
        if len(main_domain) <= 8 and re.search(r'[0-9]', main_domain) and re.search(r'[a-z]', main_domain):
            # Contains both letters and numbers in short domain
            score += 40  # AGGRESSIVE: Increased from 20
        # Check for excessive numbers in domain
        if sum(c.isdigit() for c in main_domain) >= len(main_domain) * 0.4:
            score += 30  # AGGRESSIVE: Increased from 15
        # Very short domains
        if len(main_domain) <= 6 and not is_trusted_domain(domain):
            score += 25  # AGGRESSIVE: New penalty
    
    # Enhanced: Check for suspicious path patterns (like /5qjfdrqj/oViueb/7)
    path = urlparse(url).path
    if path and path != '/':
        path_parts = [p for p in path.split('/') if p]
        for part in path_parts:
            # Random-looking path segments
            if 5 <= len(part) <= 12 and re.search(r'[0-9]', part) and re.search(r'[a-z]', part.lower()):
                score += 15  # AGGRESSIVE: Increased from 10

    # AGGRESSIVE: No subdomain penalty (most legitimate sites use www or nothing)
    if len(domain_parts) > 2 and not any(part in ['www', 'mail', 'accounts'] for part in domain_parts[:-2]):
        score += 20

    # Check for suspicious patterns
    suspicious_patterns = [
        r'[0-9]{5,}',  # Long numbers (like pl-oferta95642)
        r'-[a-z]+[0-9]+\.',  # Pattern like -oferta95642.
        r'[a-z]+-[a-z]+-[a-z]+',  # Multiple hyphens
        r'secure.*update',  # secure-update patterns
        r'verify.*account',  # verify-account patterns
        r'confirm.*identity',  # confirm-identity patterns
        r'account.*suspended',  # account-suspended patterns
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, url_lower):
            score += 10
    
    # Check for homograph attacks (similar looking characters)
    homograph_chars = ['0' in domain_lower and 'o' in brand for brand in TARGETED_BRANDS]
    if any(homograph_chars):
        score += 10
    
    # Subdomain abuse (e.g., paypal.fake-site.com)
    parts = domain_lower.split('.')
    if len(parts) > 2:  # Has subdomains
        for brand in TARGETED_BRANDS:
            if brand in '.'.join(parts[:-2]):  # Brand in subdomain
                score += 20
    
    # IP address in URL
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
        score += 40  # AGGRESSIVE: Increased from 25
    
    # AGGRESSIVE: Generic/meaningless domain names
    generic_suspicious = ['secure', 'update', 'verify', 'confirm', 'account', 'service', 'support']
    for word in generic_suspicious:
        if word in domain_lower and not is_trusted_domain(domain):
            score += 15
    
    # URL shortener patterns
    if len(domain) < 10 and '.' in domain and not is_trusted_domain(domain):
        score += 10
    
    return score

def is_protection_page(html_content):
    """Check if this is a protection/blocking page instead of actual content"""
    content_lower = html_content.lower()
    
    protection_indicators = [
        # Cloudflare
        'attention required! | cloudflare',
        'please enable cookies',
        'you have been blocked',
        'ray id:',
        'cloudflare ray id',
        'cf-ray',
        # Other protection services
        'access denied',
        'security check',
        'checking your browser',
        'ddos protection',
        'bot detection',
        'please verify you are human',
        'captcha',
        'challenge-form',
        # Generic blocking
        'blocked by security',
        '403 forbidden',
        'error 1020'
    ]
    
    for indicator in protection_indicators:
        if indicator in content_lower:
            return True
    
    return False

def is_suspiciously_empty(html_content, domain):
    """Check if the content is suspiciously empty for a non-trusted domain"""
    if is_trusted_domain(domain):
        return False
    
    # Check if it's a protection page
    if is_protection_page(html_content):
        return True

    # Completely empty or just basic tags
    if len(html_content) < 100:
        return True

    # Just whitespace and basic HTML structure
    soup = BeautifulSoup(html_content, 'html.parser')
    text_content = soup.get_text(strip=True)

    if len(text_content) < 20:  # AGGRESSIVE: Increased threshold
        return True
    
    # Check for minimal content pages
    if len(text_content) < 100 and not soup.find('form'):
        return True

    # Check for "loading" pages that might be waiting for JS
    loading_indicators = ['loading', 'please wait', 'redirecting', 'one moment']
    if any(indicator in text_content.lower() for indicator in loading_indicators) and len(text_content) < 50:
        return True

    return False

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

# ENHANCED: Detect suspicious patterns even in minimal content
def get_suspicious_patterns(soup, domain, full_text):
    """Detect suspicious patterns that might indicate phishing"""
    suspicious_count = 0
    
    # 1. Check for mismatched branding
    brand_keywords = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'bank', 'chase', 'wells fargo']
    domain_lower = domain.lower()
    
    for brand in brand_keywords:
        if brand in full_text and brand not in domain_lower:
            suspicious_count += 5  # High weight for brand spoofing
    
    # 2. Check for urgency words
    urgency_words = ['urgent', 'immediate', 'expire', 'suspend', 'deadline', 'limited time', 
                    'act now', 'verify now', 'confirm now']
    for word in urgency_words:
        if word in full_text:
            suspicious_count += 2
    
    # 3. Check for data-harvesting inputs
    sensitive_inputs = soup.find_all('input', {'type': ['password', 'tel', 'email']})
    suspicious_count += len(sensitive_inputs) * 2
    
    # 4. Check for suspicious form attributes
    for form in soup.find_all('form'):
        # Forms posting to different domain
        action = form.get('action', '')
        if action and action.startswith('http'):
            form_domain = urlparse(action).netloc
            if form_domain and form_domain != domain:
                suspicious_count += 10
    
    # 5. Check for hidden elements that might contain phishing content
    hidden_elements = soup.find_all(style=re.compile(r'display:\s*none|visibility:\s*hidden'))
    if len(hidden_elements) > 3:
        suspicious_count += 3
    
    return suspicious_count

# --- Part 2: HTML Content-Based Feature Extractors ---

def get_pct_ext_hyperlinks(soup, domain):
    """Enhanced to detect JavaScript-based redirects"""
    total_links = 0
    external_links = 0
    page_url = f"https://{domain}"
    
    for a in soup.find_all('a', href=True):
        total_links += 1
        href = a['href'].strip()
        
        # Check for JavaScript redirects
        if 'javascript:' in href.lower() and 'location' in href.lower():
            external_links += 1
            continue
            
        if not href:
            continue

        absolute_href = urljoin(page_url, href)
        parsed_href = urlparse(absolute_href)
        
        if parsed_href.netloc and parsed_href.netloc != domain:
            external_links += 1
    
    # Also check for meta refresh redirects
    meta_refresh = soup.find('meta', attrs={'http-equiv': 'refresh'})
    if meta_refresh:
        content = meta_refresh.get('content', '')
        if 'url=' in content.lower():
            total_links += 1
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

def get_frequent_domain_name_mismatch(soup, domain, url, html_content):
    """
    AGGRESSIVE: Flag suspicious domains even with no content
    """
    # If page is empty/blocked but URL is suspicious, flag it
    if (is_suspiciously_empty(html_content, domain) or is_protection_page(html_content)):
        url_suspicion = get_url_suspicion_score(url, domain)
        if url_suspicion > 30:  # AGGRESSIVE: Lower threshold
            return 1
    
    # For URLs trying to spoof brands
    for brand in TARGETED_BRANDS:
        if brand in domain.lower() and not is_trusted_domain(domain):
            return 1
    
    # Original logic for non-empty pages
    total_links_with_text = 0
    domain_in_anchor_count = 0
    domain_base = domain.replace('www.', '').split('.')[0]

    for a in soup.find_all('a', href=True):
        link_text = ""
        
        if a.string:
            link_text = a.string.lower()
            total_links_with_text += 1
        elif a.get('aria-label'):
            link_text = a.get('aria-label', '').lower()
            total_links_with_text += 1
        elif a.get('title'):
            link_text = a.get('title', '').lower()
            total_links_with_text += 1
            
        if link_text and domain_base in link_text:
            domain_in_anchor_count += 1

    if total_links_with_text == 0:
        return 0
        
    match_ratio = (domain_in_anchor_count / total_links_with_text)
    
    if is_trusted_domain(domain):
        return 1 if match_ratio < 0.10 else 0
    else:
        return 1 if match_ratio < 0.20 else 0

def get_insecure_forms(soup, domain):
    """ENHANCED: Detect forms even with evasion techniques"""
    page_url = f"https://{domain}"
    
    # Check traditional forms
    for form in soup.find_all('form'):
        action = form.get('action', '')
        if not action:  # Empty action is suspicious
            return 1
        
        absolute_action = urljoin(page_url, action)
        parsed_action = urlparse(absolute_action)
        
        if parsed_action.scheme == 'http' or (parsed_action.netloc and parsed_action.netloc != domain):
            return 1
    
    # Check for input fields without forms (common evasion)
    password_inputs = soup.find_all('input', {'type': 'password'})
    if password_inputs and not soup.find('form'):
        return 1  # Password field without form is suspicious
    
    # Check for AJAX-style data collection
    scripts = soup.find_all('script')
    for script in scripts:
        if script.string:
            # Look for AJAX calls to external domains
            if 'XMLHttpRequest' in script.string or 'fetch(' in script.string:
                if any(domain not in script.string and 'http' in script.string 
                      for domain in [domain, 'googleapis.com', 'jquery.com']):
                    return 1
    
    return 0

def get_submit_info_to_email(soup):
    """Checks if any <form> action submits data to a 'mailto:' address."""
    for form in soup.find_all('form', action=True):
        if form['action'].lower().startswith('mailto:'):
            return 1
    return 0

def get_num_sensitive_words(soup, domain, url, html_content):
    """
    AGGRESSIVE: Much higher penalties for suspicious URLs with blocked content
    """
    # First, get URL suspicion score
    url_suspicion = get_url_suspicion_score(url, domain)
    
    # AGGRESSIVE: If page is blocked/empty AND URL is suspicious, heavy penalty
    if (is_suspiciously_empty(html_content, domain) or is_protection_page(html_content)) and url_suspicion > 0:
        # Base penalty of 50 for any blocked suspicious page, plus URL suspicion
        return 50 + url_suspicion
    
    # Extract text
    for script_or_style in soup(["script", "style", "head", "title", "meta", "[document]"]):
        script_or_style.extract()
    
    text = soup.get_text(separator=' ', strip=True).lower()
    
    if is_trusted_domain(domain):
        # For trusted domains, look for specific phishing indicators
        phishing_phrases = [
            "suspended", "locked", "verify immediately", "urgent action", 
            "click here immediately", "confirm identity", "unusual activity", 
            "temporary suspension", "verify your account", "update payment",
            "security alert", "account verification required"
        ]
        count = sum(1 for phrase in phishing_phrases if phrase in text)
        return count * 5
    else:
        # For non-trusted domains
        sensitive_words = [
            "login", "password", "verify", "account", "update", 
            "secure", "signin", "sign in", "log in", "banking", 
            "confirm", "credential", "username", "email", "phone", 
            "ssn", "social security", "credit card", "cvv", "pin",
            "authenticate", "validation", "expires", "suspended"
        ]
        
        count = 0
        for word in sensitive_words:
            count += text.count(word)
        
        # AGGRESSIVE: Always add URL suspicion for untrusted domains
        count += url_suspicion
        
        # AGGRESSIVE: Minimal content penalty
        if len(text) < 200 and url_suspicion > 20:
            count += 30
        
        return count

# AGGRESSIVE: Add penalties to risk-tiered features for suspicious domains
def get_pct_ext_null_self_redirect_hyperlinks_rt(pct_null_href, domain):
    """Risk-tiered version - penalize empty suspicious domains"""
    if is_trusted_domain(domain):
        if pct_null_href > 0.5:
            return 1
        elif 0.3 <= pct_null_href <= 0.5:
            return 0
        else:
            return -1
    else:
        # AGGRESSIVE: If no links at all on suspicious domain, that's suspicious
        if pct_null_href == 0 and get_url_suspicion_score("", domain) > 30:
            return 1
        # Original thresholds
        if pct_null_href > 0.31:
            return 1
        elif 0.15 <= pct_null_href <= 0.31:
            return 0
        else:
            return -1

def get_ext_meta_script_link_rt(soup, domain):
    """Risk-tiered external resources - penalize suspicious domains with no resources"""
    total_resources = 0
    external_resources = 0
    page_url = f"https://{domain}"
    
    legitimate_cdns = {
        'googleapis.com', 'gstatic.com', 'cloudflare.com', 'jsdelivr.net',
        'unpkg.com', 'cdnjs.cloudflare.com', 'maxcdn.bootstrapcdn.com',
        'ajax.googleapis.com', 'fonts.googleapis.com', 'fontawesome.com',
        'jquery.com', 'bootstrapcdn.com', 'cloudfront.net', 'akamaihd.net'
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
            if is_trusted_domain(domain):
                is_cdn = any(cdn in parsed_resource_url.netloc for cdn in legitimate_cdns)
                if not is_cdn:
                    external_resources += 1
            else:
                external_resources += 1

    # AGGRESSIVE: No resources on suspicious domain is suspicious
    if total_resources == 0 and not is_trusted_domain(domain) and get_url_suspicion_score("", domain) > 30:
        return 1
    
    ratio = (external_resources / total_resources) if total_resources > 0 else 0.0
    
    if is_trusted_domain(domain):
        if ratio >= 0.9:
            return 1
        else:
            return -1
    else:
        if ratio >= 0.61:
            return 1
        elif 0.31 <= ratio < 0.61:
            return 0
        else:
            return -1

# --- Main Orchestrator Function ---

def extract_features(url, html_content):
    """
    Enhanced feature extraction that handles empty pages and URL patterns
    """
    features = {}

    # Add minimal content detection
    if len(html_content.strip()) < 100:
        print(f"WARNING: Minimal HTML content ({len(html_content)} chars) for {url}")
    
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        if not domain:
            return [0] * len(FEATURE_ORDER)

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
        
        features['FrequentDomainNameMismatch'] = get_frequent_domain_name_mismatch(soup, domain, url, html_content)
        features['InsecureForms'] = get_insecure_forms(soup, domain)
        features['SubmitInfoToEmail'] = get_submit_info_to_email(soup)
        features['NumSensitiveWords'] = get_num_sensitive_words(soup, domain, url, html_content)
        
        # Risk-tiered features (now domain-aware)
        features['PctExtNullSelfRedirectHyperlinksRT'] = get_pct_ext_null_self_redirect_hyperlinks_rt(pct_null_href, domain)
        features['ExtMetaScriptLinkRT'] = get_ext_meta_script_link_rt(soup, domain)
        
    except Exception as e:
        print(f"Error during feature extraction for {url}: {e}")
        return [0] * len(FEATURE_ORDER)

    return [features.get(f, 0) for f in FEATURE_ORDER]
