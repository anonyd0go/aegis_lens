# app.py
# Main Streamlit application file for AegisLens.

import streamlit as st
import requests
import pandas as pd
import os
import shap
import matplotlib.pyplot as plt
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
def load_css(file_name):
    """Loads a CSS file and injects it into the Streamlit app."""
    try:
        with open(file_name) as f:
            st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)
    except FileNotFoundError:
        st.warning(f"CSS file not found: {file_name}. Using default styles.")

# Apply the custom CSS from your project.
load_css("styles/style.css")


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
        with st.spinner(f"Securely fetching and analyzing {user_url}..."):
            try:
                # Step 1: Call the secure Cloudflare Worker
                payload = {'url': user_url}
                response = requests.post(CLOUDFLARE_WORKER_URL, json=payload, timeout=20)
                response.raise_for_status()

                result = response.json()
                html_content = result.get('html')

                if not html_content:
                    st.error("Could not retrieve content. The site may be down, blocking requests, or returned empty content.")
                    st.stop()

                # Step 2: Extract features. The extractor returns a list.
                feature_vector = extract_features(user_url, html_content)
                
                # Create a Pandas DataFrame to preserve feature names for the explainer.
                features_df = pd.DataFrame([feature_vector], columns=FEATURE_ORDER)

                # Step 3: Get prediction and explanation
                prediction_proba = model.predict_proba(features_df)[0]
                prediction = model.predict(features_df)[0]
                
                # For binary classifiers, shap_values is a list of two arrays:
                # one for class 0 (Legitimate) and one for class 1 (Phishing).
                shap_values = explainer.shap_values(features_df)
                
                # --- Display Results ---
                st.subheader("Analysis Results")
                
                if prediction == 1:
                    st.error(f"**Verdict: Phishing** (Confidence: {prediction_proba[1]:.2%})")
                else:
                    st.success(f"**Verdict: Legitimate** (Confidence: {prediction_proba[0]:.2%})")

                st.subheader("Explanation of Verdict")
                st.write("This force plot shows which features pushed the prediction towards 'Phishing' (red) or 'Legitimate' (blue). Features with larger impact are shown closer to the center.")
                
                # --- Consistent Force Plot ---
                # To ensure consistency, we ALWAYS explain the prediction for the "Phishing" class (class 1).
                # This means red arrows always indicate a feature increases the phishing score.
                # We select the expected_value and shap_values for class 1.
                expected_value_phishing = explainer.expected_value[1]
                shap_values_phishing = shap_values[1][0]

                fig, ax = plt.subplots(figsize=(10, 3))
                shap.force_plot(
                    expected_value_phishing,
                    shap_values_phishing,
                    features_df.iloc[0], # The feature values for our single prediction
                    matplotlib=True,
                    show=False
                )
                st.pyplot(fig, bbox_inches='tight', pad_inches=0.1)
                plt.close(fig) # Close the plot to free up memory

            except requests.exceptions.Timeout:
                st.error("The request to the fetching service timed out. The target website might be slow or unresponsive.")
            except requests.exceptions.RequestException as e:
                st.error(f"Failed to connect to the secure fetching service. Error: {e}")
            except Exception as e:
                st.error(f"An unexpected error occurred during the analysis: {e}")
