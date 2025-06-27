# app.py
# Main Streamlit application file for AegisLens.

import streamlit as st
import numpy as np
import shap
import matplotlib.pyplot as plt # Import matplotlib
import streamlit.components.v1 as components # Import components

# Import our custom modules
import model_loader
import feature_extractor

# --- Page Configuration ---
# Set the page title, icon, and layout. The layout "wide" is good for dashboards.
st.set_page_config(
    page_title="AegisLens - Explainable Phishing Detector",
    page_icon="🛡️",
    layout="wide"
)

# --- Asset Loading ---
# Use Streamlit's caching to load the model and explainer only once,
# which improves performance.

@st.cache_resource
def load_assets():
    """Loads the ML model and SHAP explainer."""
    model = model_loader.load_model()
    explainer = model_loader.load_explainer()
    return model, explainer

model, explainer = load_assets()

# --- Custom CSS for Styling ---
# Inject custom CSS to align with the AegisLens brand identity.
st.markdown("""
<style>
    /* Main App Background */
    .stApp {
        background-color: #0A192F;
    }
    /* Main Title Style */
    .title {
        font-size: 3rem;
        font-weight: bold;
        color: #FFFFFF; /* Brighter for title */
        padding-bottom: 10px;
    }
    /* Subheader/Tagline Style */
    .tagline {
        font-size: 1.25rem;
        color: #8892B0;
        padding-bottom: 30px;
    }
    /* Custom button styling */
    .stButton>button {
        border-color: #4A90E2;
        color: #4A90E2;
        border-radius: 5px;
    }
    .stButton>button:hover {
        border-color: #FFFFFF;
        color: #FFFFFF;
        background-color: #4A90E2;
    }
    /* Styling for the results containers */
    .verdict-container {
        padding: 20px;
        border-radius: 10px;
        text-align: center;
        margin-bottom: 20px;
    }
    .verdict-safe {
        background-color: #1a3b5f; /* A darker shade of safe blue */
    }
    .verdict-phishing {
        background-color: #5c2c41; /* A darker shade of threat red */
    }
    .verdict-text {
        font-size: 2rem;
        font-weight: bold;
    }
    .confidence-text {
        font-size: 1.1rem;
    }
</style>
""", unsafe_allow_html=True)


# --- UI Layout ---

# Sidebar for information
with st.sidebar:
    st.image("https://i.imgur.com/71444j0.png", width=100) # Placeholder logo
    st.title("AegisLens")
    st.info(
        "This application uses a Random Forest model to detect phishing URLs "
        "and SHAP (SHapley Additive exPlanations) to explain its predictions."
    )
    st.markdown("---")
    st.header("Privacy Notice")
    st.success(
        "**Your data is safe.** We do not store or log any URLs you analyze. "
        "The analysis is performed in-memory and is stateless."
    )

# Main content
st.markdown('<p class="title">AegisLens</p>', unsafe_allow_html=True)
st.markdown('<p class="tagline">Beyond Detection. True Understanding.</p>', unsafe_allow_html=True)

# URL Input Box
url_to_check = st.text_input(
    "Enter the URL you want to analyze:",
    placeholder="e.g., https://www.example.com"
)

# Analyze Button
if st.button("Analyze URL"):
    # --- Input Validation ---
    if not url_to_check or not url_to_check.strip():
        st.error("Please enter a URL to analyze.")
    elif model is None or explainer is None:
        st.error("Model or SHAP explainer not loaded. Please check the logs.")
    else:
        with st.spinner('Extracting features and analyzing...'):
            # --- Backend Logic ---
            # 1. Extract features from the URL. Returns shape (1, 14).
            feature_vector = feature_extractor.extract_features(url_to_check)

            # 2. Predict using the model
            # predict_proba gives [prob_legitimate, prob_phishing]
            prediction_proba = model.predict_proba(feature_vector)
            confidence = prediction_proba[0][1] # Probability of being phishing
            prediction = 1 if confidence > 0.5 else 0

            # 3. Generate SHAP explanation for the prediction.
            # Output is a list of two arrays [class_0_values, class_1_values],
            # each with shape (1, 14) for our single prediction.
            shap_values = explainer.shap_values(feature_vector)

            # --- Display Results ---
            st.markdown("---")
            st.header("Analysis Results")

            # Create columns for a cleaner layout
            col1, col2 = st.columns(2)

            with col1:
                if prediction == 1: # Phishing
                    st.markdown(
                        '<div class="verdict-container verdict-phishing">'
                        '<p class="verdict-text" style="color:#E01E5A;">Phishing Detected</p>'
                        f'<p class="confidence-text" style="color:#FFFFFF;">Confidence: {confidence:.2%}</p>'
                        '</div>',
                        unsafe_allow_html=True
                    )
                else: # Legitimate
                    st.markdown(
                        '<div class="verdict-container verdict-safe">'
                        '<p class="verdict-text" style="color:#4A90E2;">Looks Safe</p>'
                        f'<p class="confidence-text" style="color:#8892B0;">Phishing Confidence: {confidence:.2%}</p>'
                        '</div>',
                        unsafe_allow_html=True
                    )

            with col2:
                st.info(
                    "**How to read the plot below:**\n"
                    "- **Red bars** show features that pushed the prediction towards 'Phishing'.\n"
                    "- **Blue bars** show features that pushed it towards 'Safe'.\n"
                    "- The **length of the bar** shows the impact of that feature."
                )
            
            # --- Function to render SHAP Force Plot ---
            # This function generates the plot as HTML and renders it.
            def st_shap(plot, height=None):
                shap_html = f"<head>{shap.getjs()}</head><body>{plot.html()}</body>"
                components.html(shap_html, height=height)

            # Display the SHAP force plot for the "phishing" class
            st.subheader("Prediction Explanation")
            
            # For a single prediction, we need to pass 1D arrays to the force_plot.
            # We select the values for the "phishing" class (index 1) and the first sample (index 0).
            shap_values_for_phishing = shap_values[0, :, 1]
            
            # The base value for the "phishing" class.
            base_value_for_phishing = explainer.expected_value[1]
            
            # The actual feature values for our single sample.
            feature_values_instance = feature_vector[0]


            # Create the force plot object
            force_plot = shap.force_plot(
                base_value=base_value_for_phishing,
                shap_values=shap_values_for_phishing,
                features=feature_values_instance,
                feature_names=feature_extractor.FEATURE_ORDER
            )

            # Render the plot using our custom function
            st_shap(force_plot, 150)
