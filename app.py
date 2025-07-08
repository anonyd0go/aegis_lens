# app.py
# Main Streamlit application file for AegisLens.
# IMPROVED VERSION: Includes allowlist fast path for trusted domains

import streamlit as st
from streamlit_shap import st_shap
import requests
import pandas as pd
from bs4 import BeautifulSoup
import os
import shap
from urllib.parse import urlparse
from feature_extractor import extract_features, FEATURE_ORDER, TRUSTED_DOMAINS
from model_loader import load_model, load_explainer

# --- Page Configuration and Styling ---
st.set_page_config(
    page_title="AegisLens Phishing Detector",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="auto"
)

# --- Asset Loading with Caching ---
@st.cache_resource
def load_assets():
    """Loads the model and explainer using caching."""
    model = load_model()
    explainer = load_explainer()
    return model, explainer

try:
    model, explainer = load_assets()
except FileNotFoundError:
    st.error("Model or explainer assets not found. Ensure 'models/url_model_ds114.joblib' and 'models/url_explainer_ds114.joblib' exist.")
    st.stop()

# --- Configuration for Disco.Cloud ---
CLOUDFLARE_WORKER_URL = os.getenv("CF_WORKER_URL")

if not CLOUDFLARE_WORKER_URL:
    st.error("The CF_WORKER_URL environment variable is not set. The application cannot perform live analysis.")
    st.info("Please set the CF_WORKER_URL environment variable in your Disco.Cloud application settings.")
    st.stop()

# --- Helper Functions ---
def normalize_url(url):
    """Normalize URL by adding https:// if no scheme is present."""
    url = url.strip()
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url
    return url

def check_allowlist(url):
    """Check if the URL's domain is in our trusted allowlist."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        return domain in TRUSTED_DOMAINS
    except:
        return False

# --- UI Elements ---
st.title("🛡️ AegisLens Phishing Detector")
st.write("Enter a URL to analyze its content and structure for phishing threats. Our AI will provide a verdict and explain its reasoning.")

# Add an info box about trusted domains
with st.expander("About Trusted Domains"):
    st.info("""
    AegisLens recognizes major legitimate websites and applies adjusted analysis rules to reduce false positives. 
    Trusted domains include major search engines, social media platforms, banks, and tech companies.
    
    This doesn't mean these sites can't be spoofed - always verify the URL carefully!
    """)

# Create two columns for input options
col1, col2 = st.columns([3, 1])

with col1:
    user_url = st.text_input("URL to Analyze:", placeholder="https://example.com")

with col2:
    st.write(" ")  # Spacing
    st.write(" ")  # Spacing
    force_detailed = st.checkbox("Force detailed analysis", 
                                help="Check this to run full analysis even on trusted domains")

if st.button("Analyze URL"):
    if not user_url:
        st.warning("Please enter a URL.")
    else:
        # Normalize the URL
        normalized_url = normalize_url(user_url)
        
        # Check if it's a trusted domain and detailed analysis is not forced
        if check_allowlist(normalized_url) and not force_detailed:
            st.success(f"**Verdict: Legitimate** (Trusted Domain)")
            st.info(f"✅ This domain is recognized as a major legitimate website. While AegisLens trusts this domain, always verify you're on the correct URL and not a lookalike domain.")
            st.write("**Tip:** To see the detailed AI analysis for this trusted domain, check the 'Force detailed analysis' box above and click Analyze again.")
        else:
            # Perform full analysis
            with st.spinner(f"Securely fetching and analyzing {normalized_url}..."):
                try:
                    # Step 1: Call the secure Cloudflare Worker
                    payload = {'url': normalized_url}
                    response = requests.post(CLOUDFLARE_WORKER_URL, json=payload, timeout=20)
                    response.raise_for_status()

                    result = response.json()
                    html_content = result.get('html')

                    if not html_content:
                        st.error("Could not retrieve content. The site may be down, blocking requests, or returned empty content.")
                        st.stop()

                    # Step 2: Check for suspiciously empty content
                    if len(html_content.strip()) < 100:
                        st.warning("⚠️ The page returned minimal content. This is often a sign of:")
                        st.write("• Anti-analysis techniques by phishing sites")
                        st.write("• JavaScript-rendered content")  
                        st.write("• The site detecting automated access")
                        
                    # Step 3: Extract features
                    feature_vector = extract_features(normalized_url, html_content)
                    features_df = pd.DataFrame([feature_vector], columns=FEATURE_ORDER)

                    # Step 4: Get prediction and explanation
                    prediction_proba = model.predict_proba(features_df)[0]
                    prediction = model.predict(features_df)[0]
                    
                    shap_values = explainer(features_df)
                    
                    # --- Display Results ---
                    st.subheader("Analysis Results")
                    
                    # If it's a trusted domain being analyzed in detail, show that context
                    if check_allowlist(normalized_url) and force_detailed:
                        st.info("📝 **Note:** This is a trusted domain. The analysis below shows what the AI model sees, which may include false positive indicators due to legitimate security features.")

                    st.info("**Important**: This tool is still in deveopment. Data used to train the model cuts off at 2017.  Modern phishing sites are complex and more sophisticated evasio techniques.")
                    st.info("Categorization of a false positive = categorized as Phishing when it is not.\nFalse negative = categorized as Legitimate when it is not.\nMake sure to doublecheck the link. Do not click it if you do not trust it.")

                    if prediction == 1:
                        if check_allowlist(normalized_url):
                            st.warning(f"**Model Output: Phishing** (Confidence: {prediction_proba[1]:.2%})")
                            st.success("**Override: Legitimate** (This is a trusted domain)")
                            st.write("This demonstrates why we maintain a trusted domain list - legitimate sites often have features that can trigger false positives.")
                        else:
                            st.error(f"**Verdict: Phishing** (Confidence: {prediction_proba[1]:.2%})")
                            st.warning("⚠️ This website shows characteristics commonly associated with phishing sites. Exercise extreme caution!")
                    else:
                        st.success(f"**Verdict: Legitimate** (Confidence: {prediction_proba[0]:.2%})")
                        if not check_allowlist(normalized_url):
                            st.info("✅ This website appears to be legitimate based on our analysis. However, always verify the URL matches your expectations.")

                    st.subheader("Explanation of Verdict")
                    st.write("This force plot shows which features pushed the prediction towards 'Phishing' (red) or 'Legitimate' (blue).")
                    
                    st_shap(shap.plots.force(shap_values[0, :, 1]))

                    # Feature details
                    with st.expander("Show Features"):
                        st.write("The following are the raw feature values fed to the model:")
                        
                        # Add feature descriptions
                        feature_descriptions = {
                            'NumDash': 'Number of hyphens in URL',
                            'NumDots': 'Number of dots in URL',
                            'NumNumericChars': 'Number of numeric characters',
                            'PathLevel': 'Depth of URL path',
                            'NumQueryComponents': 'Number of query parameters',
                            'PctExtHyperlinks': '% of external links',
                            'PctExtResourceUrls': '% of external resources',
                            'PctNullSelfRedirectHyperlinks': '% of null/self links',
                            'FrequentDomainNameMismatch': 'Domain mismatch in anchors',
                            'InsecureForms': 'Forms submit externally/insecurely',
                            'SubmitInfoToEmail': 'Forms use mailto',
                            'NumSensitiveWords': 'Sensitive word density',
                            'PctExtNullSelfRedirectHyperlinksRT': 'Risk tier: null links',
                            'ExtMetaScriptLinkRT': 'Risk tier: external scripts'
                        }
                        
                        # Create a more informative dataframe
                        features_display = pd.DataFrame({
                            'Feature': FEATURE_ORDER,
                            'Value': feature_vector,
                            'Description': [feature_descriptions.get(f, '') for f in FEATURE_ORDER]
                        })
                        st.dataframe(features_display)

                except requests.exceptions.Timeout:
                    st.error("The request timed out. The target website might be slow or unresponsive.")
                except requests.exceptions.RequestException as e:
                    st.error(f"Failed to connect to the secure fetching service. Error: {e}")
                except Exception as e:
                    st.error(f"An unexpected error occurred during the analysis: {e}")

# Add footer with additional information
st.markdown("---")
st.markdown(
    """
    <div style='text-align: center; color: #8892B0; font-size: 0.9em;'>
    AegisLens uses machine learning and explainable AI to detect phishing attempts. 
    Always verify URLs carefully, especially for sensitive accounts.
    <br>
    <a href='https://github.com/anonyd0go/aegis_lens' style='color: #4A90E2;'>Learn more about our technology</a>
    </div>
    """,
    unsafe_allow_html=True
)
