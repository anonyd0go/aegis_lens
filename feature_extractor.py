# feature_extractor.py
# This module contains the logic for converting a raw URL string into a
# feature vector that can be fed into the AegisLens machine learning model.

import re
from urllib.parse import urlparse
import numpy as np

# --- Feature Order ---
# This list defines the exact order of features required by the trained model.
# The `extract_features` function will return the feature vector in this order.
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

# ==============================================================================
# I. URL-BASED FEATURE EXTRACTION
# These functions parse the URL string itself. They are safe and do not
# make any external network requests.
# ==============================================================================

def get_num_dash(url: str) -> int:
    """Counts the number of hyphens '-' in the URL."""
    return url.count('-')

def get_num_dots(url: str) -> int:
    """Counts the number of dots '.' in the URL."""
    return url.count('.')

def get_num_numeric_chars(url: str) -> int:
    """Counts the number of numeric characters in the URL."""
    return len(re.findall(r'[0-9]', url))

def get_path_level(url: str) -> int:
    """Calculates the depth of the URL path."""
    try:
        path = urlparse(url).path
        # Count the number of slashes, excluding a trailing slash if present
        return path.count('/') - (1 if path.endswith('/') and len(path) > 1 else 0)
    except Exception:
        return 0

def get_num_query_components(url: str) -> int:
    """Counts the number of components in the URL query string."""
    try:
        query = urlparse(url).query
        if not query:
            return 0
        # Count ampersands and add 1 for the initial component
        return query.count('&') + 1
    except Exception:
        return 0

# ==============================================================================
# II. HTML CONTENT-BASED FEATURE EXTRACTION (MVP SIMULATION)
# As per our MVP strategy, we will NOT fetch live HTML content to avoid
# security risks. This function simulates the HTML analysis based on
# patterns in the URL string itself to return plausible feature values.
# ==============================================================================

def get_mocked_html_features(url: str) -> dict:
    """
    Simulates the extraction of HTML-based features.

    Instead of fetching the URL, this function looks for suspicious patterns
    in the URL string to generate a realistic but mocked set of feature values.
    This is a security measure for the MVP.

    Returns:
        A dictionary containing the 9 simulated HTML-based features.
    """
    # Baseline "medium risk" feature set
    mocked_features = {
        'PctExtHyperlinks': 0.50,
        'PctExtResourceUrls': 0.65,
        'PctNullSelfRedirectHyperlinks': 0.20,
        'FrequentDomainNameMismatch': 0,
        'InsecureForms': 0,
        'SubmitInfoToEmail': 0,
        'NumSensitiveWords': 2,
        'PctExtNullSelfRedirectHyperlinksRT': 0,
        'ExtMetaScriptLinkRT': 0
    }

    # Simulate higher risk if suspicious terms are in the URL
    url_lower = url.lower()
    suspicious_terms = ['login', 'verify', 'account', 'update', 'secure', 'signin']
    if any(term in url_lower for term in suspicious_terms):
        mocked_features['NumSensitiveWords'] = 5
        mocked_features['FrequentDomainNameMismatch'] = 1
        mocked_features['InsecureForms'] = 1
        mocked_features['PctExtHyperlinks'] = 0.85
        mocked_features['ExtMetaScriptLinkRT'] = 1 # High risk tier
        mocked_features['PctExtNullSelfRedirectHyperlinksRT'] = 1 # High risk tier


    # Simulate risk if URL uses an IP address
    # (A simple regex to check for IP-like structure)
    if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', url):
        mocked_features['FrequentDomainNameMismatch'] = 1
        mocked_features['ExtMetaScriptLinkRT'] = 1

    return mocked_features

# ==============================================================================
# III. ORCHESTRATOR
# This is the main public function for this module.
# ==============================================================================

def extract_features(url: str) -> np.ndarray:
    """
    Extracts all 14 features from a URL string and returns them as a
    NumPy array in the correct order for the model.

    Args:
        url: The URL string to analyze.

    Returns:
        A NumPy array of shape (1, 14) containing the feature vector.
    """
    # 1. Initialize a dictionary to hold all feature values
    all_features = {}

    # 2. Extract URL-based features
    all_features['NumDash'] = get_num_dash(url)
    all_features['NumDots'] = get_num_dots(url)
    all_features['NumNumericChars'] = get_num_numeric_chars(url)
    all_features['PathLevel'] = get_path_level(url)
    all_features['NumQueryComponents'] = get_num_query_components(url)

    # 3. Get the simulated HTML-based features
    html_features = get_mocked_html_features(url)
    all_features.update(html_features)

    # 4. Assemble the feature vector in the correct order
    feature_vector = [all_features[feature_name] for feature_name in FEATURE_ORDER]

    # 5. Return as a NumPy array suitable for the model's predict method
    return np.array(feature_vector).reshape(1, -1)

# --- Example Usage (for testing) ---
if __name__ == '__main__':
    # Example of a potentially malicious URL
    test_url_phishing = "http://123.45.67.8/login-secure-update/index.html?user=test"
    features_phishing = extract_features(test_url_phishing)
    print(f"Testing a suspicious URL: {test_url_phishing}")
    print(f"Feature Vector ({features_phishing.shape}):\n{features_phishing}")
    print("-" * 20)
    for name, value in zip(FEATURE_ORDER, features_phishing[0]):
        print(f"{name}: {value}")

    print("\n" + "="*50 + "\n")

    # Example of a legitimate URL
    test_url_legit = "https://www.google.com/search?q=machine+learning"
    features_legit = extract_features(test_url_legit)
    print(f"Testing a legitimate URL: {test_url_legit}")
    print(f"Feature Vector ({features_legit.shape}):\n{features_legit}")
    print("-" * 20)
    for name, value in zip(FEATURE_ORDER, features_legit[0]):
        print(f"{name}: {value}")
