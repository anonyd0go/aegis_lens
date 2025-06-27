# AegisLens
AegisLens is a modern, AI-powered analytical tool designed to classify URLs as either legitimate or phishing. Its key differentiator is its emphasis on **Explainable AI (XAI)**, transforming the tool from a "black box" classifier into a trustworthy and educational security utility. It provides not just a verdict but also a clear, visual explanation for its decisions using the SHAP (SHapley Additive exPlanations) framework.

This project was developed as a Minimum Viable Product (MVP) over a four-week agile sprint plan.

### **📸 Live Demo Screenshot**

(Placeholder for a screenshot of the running Streamlit application)

### **Key Features**

* **High-Accuracy Classification:** Utilizes a tuned RandomForestClassifier model to predict whether a URL is legitimate or malicious.  
* **Explainable Predictions:** Integrates SHAP to generate force plots that visualize the specific impact of each feature on the model's final decision.  
* **Intuitive Web Interface:** A clean and professional UI built with Streamlit for easy analysis.  
* **Stateless & Secure by Design:** No user-submitted URLs are stored or logged, ensuring user privacy. The MVP uses a secure, simulated feature extraction process.

### **🛠️ Technology Stack**

* **Backend:** Python 3.12  
* **Web Framework:** Streamlit  
* **Machine Learning:** Scikit-learn, SHAP  
* **Numerical Operations:** NumPy, Pandas  
* **Model/Asset Serialization:** Joblib

### **Installation & Setup**

To run AegisLens on your local machine, please follow these steps. It is highly recommended to use a Python virtual environment.

**1\. Clone the Repository:**

git clone https://github.com/\[YourUsername\]/AegisLens.git  
cd AegisLens

**2\. Create and Activate a Virtual Environment (Recommended):**

\# For Unix/macOS  
python3 \-m venv .venv  
source .venv/bin/activate

\# For Windows  
python \-m venv .venv  
.\\.venv\\Scripts\\activate

3\. Install Dependencies:  
The project's dependencies are listed in the requirements.txt file. Install them using pip:  
pip install \-r requirements.txt

### **Running the Application**

Once the setup is complete, you can launch the Streamlit application with the following command:

streamlit run app.py

This will start the web server and open the AegisLens application in your default web browser.

### **Project Structure**

The project is organized into a modular structure for clarity and maintainability:

aegis\_lens/  
│  
├── app.py                  \# Main Streamlit application file (UI & Orchestration)  
├── feature\_extractor.py    \# Extracts feature vectors from URLs (MVP: simulated HTML features)  
├── model\_loader.py         \# Loads the serialized model and SHAP explainer  
├── requirements.txt        \# Project dependencies  
│  
└── models/  
    ├── url\_model\_ds114.joblib     \# The serialized, trained RandomForest model  
    └── url\_explainer\_ds114.joblib \# The serialized SHAP explainer object

### **🧠 The Model**

The predictive engine is a RandomForestClassifier trained on the "Phishing Websites" dataset. Through an explainability analysis using SHAP, the initial feature set of 48 was reduced to **14 key features** with a negligible impact on performance (\~0.3% drop in accuracy). This significantly improves the efficiency of the model for live inference. The analysis and final model training can be found in the [xai_analysis_feature_comp.ipynb](/xai_analysis_feature_comp.ipynb) notebook.

### **🛡️ Security Considerations**

Security is a primary concern for an application that handles potentially malicious URLs.

* **MVP Approach (Current):** To ensure safety during development, the nine features that require analyzing a page's HTML content are **simulated**. The [feature_extractor.py](/feature_extractor.py) module does *not* make any live web requests. Instead, it generates plausible feature values based on patterns in the URL string itself.  
* **Production-Ready Vision (Future Work):** A production version would delegate URL fetching to an isolated, ephemeral service (e.g., a serverless function running a headless browser in a Docker container). This **sandboxing** approach ensures that any malicious code from a URL cannot affect the core application infrastructure.
