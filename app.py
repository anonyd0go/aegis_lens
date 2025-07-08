# app.py
# Main Streamlit application file for AegisLens.
# STATELESS VERSION: No session state, no data storage

import streamlit as st
from streamlit_shap import st_shap
import requests
import pandas as pd
import os
import shap
from urllib.parse import urlparse
from feature_extractor import extract_features, FEATURE_ORDER, TRUSTED_DOMAINS, get_url_suspicion_score
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

def is_protection_or_error_page(html_content):
    """Detect protection services and error pages"""
    content_lower = html_content.lower()
    
    # Protection services
    protection_indicators = [
        ('cloudflare', ['attention required! | cloudflare', 'cloudflare ray id', 'cf-ray']),
        ('security', ['you have been blocked', 'security check', 'ddos protection']),
        ('access', ['403 forbidden', 'access denied', 'access to this resource']),
        ('error', ['404 not found', 'page not found', 'dns_probe'])
    ]
    
    for category, indicators in protection_indicators:
        if any(ind in content_lower for ind in indicators):
            return True, category
    
    return False, None

def get_risk_level(prediction_proba, url_suspicion_score, is_blocked):
    """Determine risk level based on multiple factors"""
    phishing_prob = prediction_proba[1]
    
    # If blocked/protected with suspicious URL
    if is_blocked and url_suspicion_score > 30:
        return "HIGH", "🔴"
    
    # High confidence phishing
    if phishing_prob > 0.7:
        return "HIGH", "🔴"
    
    # Medium risk scenarios
    if phishing_prob > 0.5 or (phishing_prob > 0.4 and url_suspicion_score > 40):
        return "MEDIUM", "🟡"
    
    # Low confidence legitimate (suspicious)
    if phishing_prob > 0.3 and phishing_prob < 0.5:
        return "UNCERTAIN", "⚪"
    
    # High confidence legitimate
    return "LOW", "🟢"

# --- UI Elements ---
st.title("🛡️ AegisLens Phishing Detector")
st.write("Enter a URL to analyze its content and structure for phishing threats. Our AI will provide a verdict and explain its reasoning.")

st.info("**Important**: This tool is still in deveopment. Data used to train the model cuts off at 2017.  Modern phishing sites are complex and more sophisticated evasio techniques.  Some legitimate sites can be categorized as Phishing")
# Warning box
st.warning("""
⚠️ **Important Limitations**: Modern phishing sites often use protection services  
or serve empty pages to evade detection. When this happens, our analysis relies primarily on URL patterns, 
which may not be sufficient for accurate detection. Always verify URLs carefully, especially for sensitive accounts.
""")

# Info expander
with st.expander("ℹ️ Understanding Our Analysis"):
    st.info("""
    **How AegisLens Works:**
    - Analyzes 14 different features from the URL and webpage content
    - Uses machine learning to identify phishing patterns
    - Provides explainable AI visualizations
    
    **Known Limitations:**
    - Cannot analyze JavaScript-rendered content
    - Protection services (Cloudflare, etc.) block content analysis
    - Some phishing sites serve different content to automated tools
    - Low confidence scores (40-60%) indicate uncertainty
    - Certain legitimate sites may be categorized as Phishing
    
    **Trust Indicators:**
    - 🟢 Low Risk: High confidence legitimate
    - ⚪ Uncertain: Low confidence, manual verification recommended  
    - 🟡 Medium Risk: Suspicious patterns detected
    - 🔴 High Risk: Strong phishing indicators
    """)

# Create two columns for input options
col1, col2 = st.columns([3, 1])

with col1:
    user_url = st.text_input("URL to Analyze:", placeholder="https://example.com")

with col2:
    st.write(" ")  # Spacing
    st.write(" ")  # Spacing
    force_detailed = st.checkbox("Force analysis", 
                                help="Analyze even trusted domains in detail")

if st.button("Analyze URL", type="primary"):
    if not user_url:
        st.warning("Please enter a URL.")
    else:
        # Normalize the URL
        normalized_url = normalize_url(user_url)
        
        # Check if it's a trusted domain and detailed analysis is not forced
        if check_allowlist(normalized_url) and not force_detailed:
            st.success(f"**Verdict: Trusted Domain**")
            st.info(f"This is a recognized legitimate website. However, always verify the exact URL matches what you expect.")
            st.write("**Tip:** To see the detailed AI analysis for this trusted domain, check the 'Force detailed analysis' box above and click Analyze again.")
        else:
            # Perform full analysis
            with st.spinner(f"Analyzing {normalized_url}..."):
                try:
                    # Step 1: Call the secure Cloudflare Worker
                    payload = {'url': normalized_url}
                    response = requests.post(CLOUDFLARE_WORKER_URL, json=payload, timeout=30)
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
                    
                    # Check for protection/error pages
                    is_blocked, block_type = is_protection_or_error_page(html_content)
                    
                    # Get URL suspicion score
                    domain = urlparse(normalized_url).netloc
                    url_suspicion = get_url_suspicion_score(normalized_url, domain)
                        
                    # Step 3: Extract features
                    feature_vector = extract_features(normalized_url, html_content)
                    features_df = pd.DataFrame([feature_vector], columns=FEATURE_ORDER)

                    # Step 4: Get prediction and explanation
                    prediction_proba = model.predict_proba(features_df)[0]
                    prediction = model.predict(features_df)[0]
                    
                    shap_values = explainer(features_df)

                    # Get Risk level
                    risk_level, risk_icon = get_risk_level(prediction_proba, url_suspicion, is_blocked)
                    
                    # Display results
                    st.subheader("Analysis Results")
                    
                    # Show protection warning if applicable
                    if is_blocked:
                        st.warning(f"""
                        ⚠️ **Content Blocked**: This site is behind {block_type} protection.
                        Analysis is based primarily on URL patterns, which may be less reliable.
                        """)
                    
                    # Risk assessment box
                    risk_color = {
                        "HIGH": "danger",
                        "MEDIUM": "warning", 
                        "UNCERTAIN": "secondary",
                        "LOW": "success"
                    }[risk_level]
                    
                    # Main verdict
                    col1, col2 = st.columns([2, 1])
                    
                    with col1:
                        if risk_level == "HIGH":
                            st.error(f"{risk_icon} **HIGH RISK - Likely Phishing**")
                            st.write(f"Confidence: {prediction_proba[1]:.0%} phishing")
                        elif risk_level == "MEDIUM":
                            st.warning(f"{risk_icon} **MEDIUM RISK - Suspicious**")
                            st.write(f"Confidence: {prediction_proba[1]:.0%} phishing")
                        elif risk_level == "UNCERTAIN":
                            st.info(f"{risk_icon} **UNCERTAIN - Manual Verification Needed**")
                            st.write(f"Model confidence is low ({prediction_proba[0]:.0%} legitimate, {prediction_proba[1]:.0%} phishing)")
                        else:
                            st.success(f"{risk_icon} **LOW RISK - Likely Legitimate**")
                            st.write(f"Confidence: {prediction_proba[0]:.0%} legitimate")
                    
                    with col2:
                        st.metric("URL Suspicion", f"{url_suspicion}", 
                                 help="Based on domain patterns, TLD, and structure")
                    
                    # Recommendations
                    if risk_level in ["HIGH", "MEDIUM", "UNCERTAIN"]:
                        st.error("⚠️ **Recommendations:**")
                        recommendations = []
                        
                        if risk_level == "HIGH":
                            recommendations.extend([
                                "Do NOT enter any personal information",
                                "Do NOT login or provide passwords",
                                "Report this URL to PhishTank if confirmed phishing"
                            ])
                        elif risk_level == "MEDIUM":
                            recommendations.extend([
                                "Verify the domain carefully",
                                "Check for HTTPS and valid certificates",
                                "Look for spelling errors or unusual domains"
                            ])
                        else:  # UNCERTAIN
                            recommendations.extend([
                                "The analysis is inconclusive",
                                "Manually verify the website's legitimacy",
                                "Check if this is the official domain you expect"
                            ])
                        
                        for rec in recommendations:
                            st.write(f"• {rec}")
                    
                    # Technical details
                    with st.expander("🔍 Technical Analysis"):
                        # SHAP visualization
                        st.subheader("AI Explanation")
                        st.write("Features pushing toward Phishing (red) vs Legitimate (blue):")
                        shap_values = explainer(features_df)
                        st_shap(shap.plots.force(shap_values[0, :, 1]))
                        
                        # Feature breakdown
                        st.subheader("Feature Analysis")
                        
                        # Highlight key features
                        key_features = {
                            'NumSensitiveWords': features_df['NumSensitiveWords'].iloc[0],
                            'URL Suspicion Score': url_suspicion,
                            'Domain Mismatch': features_df['FrequentDomainNameMismatch'].iloc[0],
                            'External Links %': features_df['PctExtHyperlinks'].iloc[0] * 100
                        }
                        
                        cols = st.columns(len(key_features))
                        for i, (name, value) in enumerate(key_features.items()):
                            with cols[i]:
                                if name == 'Domain Mismatch':
                                    st.metric(name, "Yes" if value == 1 else "No")
                                elif name == 'External Links %':
                                    st.metric(name, f"{value:.0f}%")
                                else:
                                    st.metric(name, f"{value:.0f}")
                        
                        # All features table
                        with st.expander("Show all features"):
                            feature_descriptions = {
                                'NumDash': 'Hyphens in URL',
                                'NumDots': 'Dots in URL',
                                'NumNumericChars': 'Numbers in URL',
                                'PathLevel': 'URL path depth',
                                'NumQueryComponents': 'Query parameters',
                                'PctExtHyperlinks': 'External links ratio',
                                'PctExtResourceUrls': 'External resources ratio',
                                'PctNullSelfRedirectHyperlinks': 'Null/self links ratio',
                                'FrequentDomainNameMismatch': 'Domain mismatch flag',
                                'InsecureForms': 'Insecure forms flag',
                                'SubmitInfoToEmail': 'Mailto forms flag',
                                'NumSensitiveWords': 'Sensitive words + URL score',
                                'PctExtNullSelfRedirectHyperlinksRT': 'Null links risk tier',
                                'ExtMetaScriptLinkRT': 'External scripts risk tier'
                            }
                            
                            features_display = pd.DataFrame({
                                'Feature': FEATURE_ORDER,
                                'Value': feature_vector,
                                'Description': [feature_descriptions.get(f, '') for f in FEATURE_ORDER]
                            })
                            st.dataframe(features_display)
                
                except requests.exceptions.Timeout:
                    st.error("Analysis timed out. The website may be slow or unresponsive.")
                except Exception as e:
                    st.error(f"Analysis failed: {str(e)}")

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
