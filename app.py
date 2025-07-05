# app.py
# Main Streamlit application file for AegisLens.

import streamlit as st
from streamlit_shap import st_shap
import requests
import pandas as pd
import os
import shap
# Matplotlib is no longer needed for the force plot
from feature_extractor import extract_features, FEATURE_ORDER
from model_loader import load_model, load_explainer

# --- Page Configuration and Styling ---
# Set page config once at the top of the script.
st.set_page_config(
    page_title="AegisLens Phishing Detector",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="auto"
)

# Function to load and inject CSS for styling.
#def load_css(file_name):
#    """Loads a CSS file and injects it into the Streamlit app."""
#    try:
#        with open(file_name) as f:
#            st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)
#    except FileNotFoundError:
#        st.warning(f"CSS file not found: {file_name}. Using default styles.")
#
# Apply the custom CSS from your project.
#load_css("styles/style.css")


# --- Asset Loading with Caching ---
# Use st.cache_resource to load the model and explainer only once.
# This significantly improves performance.
@st.cache_resource
def load_assets():
    """Loads the model and explainer using caching."""
    model = load_model()
    explainer = load_explainer()
    return model, explainer

try:
    model, explainer = load_assets()
except FileNotFoundError:
    st.error("Model or explainer assets not found. Ensure 'models/url_model.joblib' and 'models/url_explainer.joblib' exist.")
    st.stop()


# --- Configuration for Disco.Cloud ---
# Use os.getenv() to read the environment variable.
CLOUDFLARE_WORKER_URL = os.getenv("CF_WORKER_URL")

if not CLOUDFLARE_WORKER_URL:
    st.error("The CF_WORKER_URL environment variable is not set. The application cannot perform live analysis.")
    st.info("Please set the CF_WORKER_URL environment variable in your Disco.Cloud application settings.")
    st.stop()

# --- UI Elements ---
st.title("🛡️ AegisLens Phishing Detector")
st.write("Enter a URL to analyze its content and structure for phishing threats. Our AI will provide a verdict and explain its reasoning.")

user_url = st.text_input("URL to Analyze:", placeholder="https://example.com")

if st.button("Analyze URL"):
    if not user_url:
        st.warning("Please enter a URL.")
    else:
        # Use a spinner to provide feedback during the network call.
        # --- NEW: URL Normalization Step ---
        # Prepend 'https://' if the URL does not have a scheme.
        # This makes the input robust to variations like 'google.com'.
        normalized_url = user_url.strip()
        if not normalized_url.startswith('http://') and not normalized_url.startswith('https://'):
            normalized_url = 'https://' + normalized_url

        with st.spinner(f"Securely fetching and analyzing {user_url}..."):
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

                # Step 2: Extract features. The extractor returns a list.
                feature_vector = extract_features(normalized_url, html_content)
                
                # Create a Pandas DataFrame to preserve feature names for the explainer.
                features_df = pd.DataFrame([feature_vector], columns=FEATURE_ORDER)

                # Step 3: Get prediction and explanation
                prediction_proba = model.predict_proba(features_df)[0]
                prediction = model.predict(features_df)[0]
                
                # The explainer is configured to explain the "Phishing" class output.
                shap_values = explainer(features_df)
                
                # --- Display Results ---
                st.subheader("Analysis Results")
                
                if prediction == 1:
                    st.error(f"**Verdict: Phishing** (Confidence: {prediction_proba[1]:.2%})")
                else:
                    st.success(f"**Verdict: Legitimate** (Confidence: {prediction_proba[0]:.2%})")

                st.subheader("Explanation of Verdict")
                st.write("This force plot shows which features pushed the prediction towards 'Phishing' (red) or 'Legitimate' (blue). Features with larger impact are shown closer to the center.  The center line and value is the probability of the link being phishing (the closer to 1 the higher the probability).")
                
                # --- Consistent Force Plot using the modern SHAP API ---
                # CORRECTED: The most robust method is to use the explainer to generate a full
                # Explanation object, then select the first sample from it for plotting.
                st_shap(shap.plots.force(shap_values[0, :, 1]))

                # --- NEW: Debugging Expander ---
                with st.expander("Show Features"):
                    st.write("The following are the raw feature values fed to the model:")
                    st.dataframe(features_df.T.rename(columns={0: 'Value'}))


            except requests.exceptions.Timeout:
                st.error("The request to the fetching service timed out. The target website might be slow or unresponsive.")
            except requests.exceptions.RequestException as e:
                st.error(f"Failed to connect to the secure fetching service. Error: {e}")
            except Exception as e:
                st.error(f"An unexpected error occurred during the analysis: {e}")