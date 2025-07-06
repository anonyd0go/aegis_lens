# app.py
# Main Streamlit application file for AegisLens.
# IMPROVED VERSION: Includes allowlist fast path for trusted domains

import streamlit as st
from streamlit_shap import st_shap
import requests
import pandas as pd
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
with st.expander("ℹ️ About Trusted Domains"):
    st.info("""
    AegisLens recognizes major legitimate websites and applies adjusted analysis rules to reduce false positives. 
    Trusted domains include major search engines, social media platforms, banks, and tech companies.
    
    This doesn't mean these sites can't be spoofed - always verify the URL carefully!
    """)

user_url = st.text_input("URL to Analyze:", placeholder="https://example.com")

if st.button("Analyze URL"):
    if not user_url:
        st.warning("Please enter a URL.")
    else:
        # Normalize the URL
        normalized_url = normalize_url(user_url)
        
        # --- IMPROVEMENT: Fast path for allowlisted domains ---
        if check_allowlist(normalized_url):
            st.success(f"**Verdict: Legitimate** (Trusted Domain)")
            st.info(f"✅ This domain is recognized as a major legitimate website. While AegisLens trusts this domain, always verify you're on the correct URL and not a lookalike domain.")
            
            # Still offer detailed analysis
            if st.checkbox("Show detailed analysis anyway"):
                with st.spinner(f"Performing detailed analysis of {normalized_url}..."):
                    try:
                        # Fetch and analyze as normal
                        payload = {'url': normalized_url}
                        response = requests.post(CLOUDFLARE_WORKER_URL, json=payload, timeout=20)
                        response.raise_for_status()
                        
                        result = response.json()
                        html_content = result.get('html')
                        
                        if html_content:
                            feature_vector = extract_features(normalized_url, html_content)
                            features_df = pd.DataFrame([feature_vector], columns=FEATURE_ORDER)
                            
                            prediction_proba = model.predict_proba(features_df)[0]
                            prediction = model.predict(features_df)[0]
                            
                            shap_values = explainer(features_df)
                            
                            st.subheader("Detailed Analysis (for educational purposes)")
                            st.write("Note: This is a trusted domain, but here's what our model sees:")
                            
                            st_shap(shap.plots.force(shap_values[0, :, 1]))
                            
                            with st.expander("Show Features"):
                                st.write("Raw feature values:")
                                st.dataframe(features_df.T.rename(columns={0: 'Value'}))
                    except Exception as e:
                        st.error(f"Could not perform detailed analysis: {e}")
        else:
            # Normal analysis for non-allowlisted domains
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

                    # Step 2: Extract features
                    feature_vector = extract_features(normalized_url, html_content)
                    features_df = pd.DataFrame([feature_vector], columns=FEATURE_ORDER)

                    # Step 3: Get prediction and explanation
                    prediction_proba = model.predict_proba(features_df)[0]
                    prediction = model.predict(features_df)[0]
                    
                    shap_values = explainer(features_df)
                    
                    # --- Display Results ---
                    st.subheader("Analysis Results")
                    
                    if prediction == 1:
                        st.error(f"**Verdict: Phishing** (Confidence: {prediction_proba[1]:.2%})")
                        st.warning("⚠️ This website shows characteristics commonly associated with phishing sites. Exercise extreme caution!")
                    else:
                        st.success(f"**Verdict: Legitimate** (Confidence: {prediction_proba[0]:.2%})")
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
    <a href='https://github.com/anonyd0go/aegislens' style='color: #4A90E2;'>Learn more about our technology</a>
    </div>
    """,
    unsafe_allow_html=True
)
