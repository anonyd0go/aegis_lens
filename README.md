# **AegisLens: An Explainable AI Phishing Detector**

**"Beyond Detection. True Understanding."**

AegisLens is a web-based analytical tool that uses machine learning to classify URLs as either legitimate or phishing. Its core feature is its commitment to **Explainable AI (XAI)** with **transparent risk communication**. Instead of just providing a "black box" verdict, AegisLens shows you *why* a decision was made by visualizing the most influential features, and communicates confidence levels through a four-tier risk system.

### **Live Application**

**The AegisLens application is deployed and publicly accessible.**

You can use the live tool here: [**https://aegislens.holbie.dev.pr/**](https://aegislens.holbie.dev.pr/)

### **Key Features**

* **High-Accuracy Classification:** Utilizes a Random Forest model trained on a dataset of over 10,000 URLs with enhanced feature extraction for modern phishing tactics.
* **SHAP-Powered Explanations:** Integrates the SHAP (SHapley Additive exPlanations) framework to generate intuitive force plots, making the model's reasoning transparent.
* **Four-Tier Risk System:** Beyond binary classification - provides HIGH 🔴, MEDIUM 🟡, UNCERTAIN ⚪, and LOW 🟢 risk assessments with confidence percentages.
* **URL Pattern Analysis:** Advanced detection of suspicious domains, random patterns, and brand spoofing attempts even when content is blocked.
* **Protection Page Detection:** Recognizes when sites are behind protection services and adjusts analysis accordingly.
* **Stateless and Secure:** No user-submitted data is ever stored. URL content is fetched in a secure, isolated sandbox environment.
* **Transparent Limitations:** Clearly communicates when JavaScript rendering or protection services limit analysis capabilities.

### **Technology Stack**

* **Backend & ML:** Python, Scikit-learn, Pandas, NumPy  
* **Explainable AI:** SHAP  
* **Web Framework:** Streamlit  
* **Deployment:** Docker, Disco.Cloud  
* **Secure Fetching:** Cloudflare Workers + Browserless.io

### **Project Structure**

The project is organized into a modular structure for clarity and maintainability:
```
    aegis_lens/  
    │  
    ├── app.py                  # Main Streamlit application with risk-tier UI
    ├── feature_extractor.py    # Enhanced feature extraction with URL pattern analysis
    ├── model_loader.py         # Loads the serialized model and SHAP explainer  
    ├── requirements.txt        # Project dependencies  
    ├── Dockerfile              # Container configuration
    ├── disco.json              # Disco.Cloud deployment config
    │  
    ├── models/  
    │   ├── url_model_ds114.joblib     # The serialized RandomForest model  
    │   └── url_explainer_ds114.joblib # The serialized SHAP explainer
    │
    ├── aegis-fetcher/
    │   └── index.js            # Cloudflare Worker for secure HTML fetching
    │
    └── debug_phishing_comprehensive.py  # Debugging tool for analysis
```

### **The Model**

The predictive engine is a RandomForestClassifier trained on the [Phishing Websites](https://www.kaggle.com/datasets/shashwatwork/phishing-dataset-for-machine-learning) dataset. Through explainability analysis using SHAP, the feature set was optimized to **14 key features**:

**URL-Based Features:**
- Number of hyphens, dots, and numeric characters
- URL path depth and query parameters

**Content-Based Features:**
- External link percentages
- Form security analysis  
- Domain mismatch detection
- **Enhanced sensitive word detection with URL suspicion scoring**

### **Enhancements**

* **Aggressive URL Pattern Detection:** Identifies suspicious patterns like random domains (`0ajh77.lat`), brand spoofing, and suspicious TLDs (`.cfd`, `.tk`, `.lat`)
* **Protection Service Handling:** Detects and handles protection services, 403 errors, and other blocking mechanisms
* **URL Suspicion Scoring:** Quantifies domain suspiciousness (0-100+) based on multiple heuristics
* **Enhanced Risk Communication:** Clear warnings about limitations and specific recommendations for each risk level

### **Security Architecture**

* **No Direct URL Access:** The application never directly fetches potentially malicious URLs
* **Sandboxed Fetching:** Cloudflare Workers act as a secure proxy layer
* **Browserless.io Integration:** URLs are rendered in isolated browser environments
* **Stateless Design:** No user data or URLs are stored anywhere
* **Environment Variable Protection:** Sensitive API keys are never exposed

### **Known Limitations**

AegisLens is transparent about its limitations:

* **Cannot analyze JavaScript-rendered content** - Static HTML analysis only
* **Protection services may block analysis** - Relies more heavily on URL patterns when content is inaccessible
* **Some sophisticated phishing may evade detection** - Especially sites using advanced cloaking
* **Low confidence on some protected legitimate sites** - When security measures prevent full analysis

### **Performance Metrics**

* **False Positives on Major Sites:** 0% (via trusted domain list)
* **Detection of Protected Phishing:** ~70% (via URL pattern analysis)
* **Average Analysis Time:** 3-5 seconds
* **Model Accuracy:** ~98% on original test set

### **Contributing**

While this is primarily an educational project, suggestions and feedback are welcome. Please note that any model improvements would require retraining on an expanded dataset.

### **Acknowledgments**

- Dataset: [Phishing Websites Dataset](https://www.kaggle.com/datasets/shashwatwork/phishing-dataset-for-machine-learning) on Kaggle
- SHAP library for making AI explainable
- Cloudflare Workers and Browserless.io for secure content fetching

---

**Remember:** AegisLens is a tool to assist in phishing detection, not a replacement for security awareness. When in doubt, don't risk it - verify URLs through official channels.