# app.py
# Main Streamlit application file for AegisLens.

import streamlit as st
import numpy as np
import shap
import streamlit.components.v1 as components

# Import our custom modules
import model_loader
import feature_extractor

# --- Page Configuration ---
# Set the page title, icon, and layout.
st.set_page_config(
    page_title="AegisLens - Explainable Phishing Detector",
    page_icon="🛡️",
    layout="wide"
)

# --- Function to load external CSS ---
def load_css(file_name):
    """
    Loads an external CSS file and injects it into the Streamlit app.
    """
    try:
        with open(file_name) as f:
            st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)
    except FileNotFoundError:
        st.error(f"CSS file not found: {file_name}. Make sure the 'styles' directory and 'style.css' file exist.")


# --- Asset Loading ---
@st.cache_resource
def load_assets():
    """
    Loads the ML model and SHAP explainer using streamlit's cache
    to prevent reloading on every interaction.
    """
    model = model_loader.load_model()
    explainer = model_loader.load_explainer()
    return model, explainer

# --- Backend Analysis Function ---
def run_analysis(url, model, explainer):
    """
    Performs the full analysis pipeline on a given URL.
    
    Args:
        url (str): The URL to analyze.
        model: The trained machine learning model.
        explainer: The SHAP explainer object.
        
    Returns:
        A dictionary containing all results needed for display.
    """
    # 1. Extract features from the URL.
    feature_vector = feature_extractor.extract_features(url)

    # 2. Predict using the model's predict_proba method.
    prediction_proba = model.predict_proba(feature_vector)
    confidence = prediction_proba[0][1]  # Probability of being phishing
    prediction = 1 if confidence > 0.5 else 0

    # 3. Generate SHAP explanation for the prediction.
    shap_values = explainer.shap_values(feature_vector)
    
    # We are interested in the "phishing" class (index 1).
    shap_values_for_phishing = shap_values[0, :, 1]
    base_value_for_phishing = explainer.expected_value[1]

    return {
        "prediction": prediction,
        "confidence": confidence,
        "feature_vector": feature_vector[0],
        "shap_values": shap_values_for_phishing,
        "base_value": base_value_for_phishing,
        "feature_names": feature_extractor.FEATURE_ORDER,
    }

# --- UI Display Function ---
def display_results_area(results):
    """
    Renders the analysis results in the UI.
    
    Args:
        results (dict): The dictionary returned by run_analysis.
    """
    st.markdown("---")
    st.header("Analysis Results")

    col1, col2 = st.columns([1, 2])

    with col1:
        # Display verdict based on prediction
        if results["prediction"] == 1:  # Phishing
            st.markdown(
                '<div class="verdict-container verdict-phishing">'
                '<p class="verdict-text" style="color:#E01E5A;">Phishing Detected</p>'
                f'<p class="confidence-text" style="color:#FFFFFF;">Confidence: {results["confidence"]:.2%}</p>'
                '</div>',
                unsafe_allow_html=True
            )
        else:  # Legitimate
            st.markdown(
                '<div class="verdict-container verdict-safe">'
                '<p class="verdict-text" style="color:#4A90E2;">Looks Safe</p>'
                f'<p class="confidence-text" style="color:#8892B0;">Phishing Confidence: {results["confidence"]:.2%}</p>'
                '</div>',
                unsafe_allow_html=True
            )

    with col2:
        st.info(
            "**How to read the plot below:**\n"
            "- **Features in red** pushed the prediction towards 'Phishing'.\n"
            "- **Features in blue** pushed it towards 'Safe'.\n"
            "- The **length of the bar** shows the magnitude of the feature's impact."
        )
    
    st.subheader("Prediction Explanation")
    # Create the SHAP force plot object
    force_plot = shap.force_plot(
        base_value=results["base_value"],
        shap_values=results["shap_values"],
        features=results["feature_vector"],
        feature_names=results["feature_names"]
    )
    # Render the plot using a wrapper function
    shap_html = f"<head>{shap.getjs()}</head><body>{force_plot.html()}</body>"
    components.html(shap_html, height=150, scrolling=True)

# --- Main Application ---

# Load CSS and Machine Learning assets
load_css("styles/style.css")
model, explainer = load_assets()

# Initialize session state to store results
if 'analysis_results' not in st.session_state:
    st.session_state['analysis_results'] = None

# --- Sidebar UI ---
with st.sidebar:
    st.image("assets/logo.png", width=150) # Placeholder logo
    st.title("AegisLens")
    st.info(
        "This application uses a Random Forest model to detect phishing URLs "
        "and SHAP to explain its predictions."
    )
    st.markdown("---")
    st.header("Privacy Notice")
    st.success(
        "**Your data is safe.** We do not store or log any URLs you analyze. "
        "The analysis is performed in-memory and is stateless."
    )

# --- Main Page UI ---
st.markdown('<p class="title">AegisLens</p>', unsafe_allow_html=True)
st.markdown('<p class="tagline">Beyond Detection. True Understanding.</p>', unsafe_allow_html=True)

# Use a form for the input to prevent reruns on every key press
with st.form("url_analysis_form"):
    url_to_check = st.text_input(
        "Enter the URL you want to analyze:",
        placeholder="e.g., https://www.example.com"
    )
    submitted = st.form_submit_button("Analyze URL")

# Logic to run when the form is submitted
if submitted:
    if url_to_check and url_to_check.strip() and (model and explainer):
        with st.spinner('Extracting features and analyzing...'):
            # Store results in session state
            st.session_state['analysis_results'] = run_analysis(url_to_check, model, explainer)
    elif not (model and explainer):
         st.error("Model or SHAP explainer not loaded. Please check the logs.")
         st.session_state['analysis_results'] = None # Clear previous results
    else:
        st.error("Please enter a URL to analyze.")
        st.session_state['analysis_results'] = None # Clear previous results

# Display the results if they exist in the session state
if st.session_state['analysis_results']:
    display_results_area(st.session_state['analysis_results'])
