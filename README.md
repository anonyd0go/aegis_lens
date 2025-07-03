# **AegisLens: An Explainable AI Phishing Detector**

**"Beyond Detection. True Understanding."**

AegisLens is a web-based analytical tool that uses machine learning to classify URLs as either legitimate or phishing. Its core feature is its commitment to **Explainable AI (XAI)**. Instead of just providing a "black box" verdict, AegisLens shows you *why* a decision was made by visualizing the most influential features, fostering trust and providing deeper insights for security analysts and end-users alike.

### **Live Application**

**The AegisLens application is deployed and publicly accessible.**

You can use the live tool here: [**https://aegislens.disco.site**](https://www.google.com/search?q=https://aegislens.disco.site) *(Note: This URL is a placeholder until the initial deployment is complete.)*

### **Key Features**

* **High-Accuracy Classification:** Utilizes a Random Forest model trained on a dataset of over 10,000 URLs to deliver reliable predictions.  
* **SHAP-Powered Explanations:** Integrates the SHAP (SHapley Additive exPlanations) framework to generate intuitive force plots, making the model's reasoning transparent.  
* **Stateless and Secure:** No user-submitted data is ever stored. URL content is fetched in a secure, isolated sandbox environment to protect the application and its users.  
* **Polished UI:** A clean and professional user interface built with Streamlit, designed according to the AegisLens brand identity.

### **Technology Stack**

* **Backend & ML:** Python, Scikit-learn, Pandas, NumPy  
* **Explainable AI:** SHAP  
* **Web Framework:** Streamlit  
* **Deployment:** Docker, Disco.Cloud  
* **Secure Fetching:** Cloudflare Workers

### **Project Structure**

The project is organized into a modular structure for clarity and maintainability:
```
    aegis_lens/  
    │  
    ├── app.py                  # Main Streamlit application file (UI & Orchestration)  
    ├── feature_extractor.py    # Extracts feature vectors from URLs (MVP: simulated HTML features)  
    ├── model_loader.py         # Loads the serialized model and SHAP explainer  
    ├── requirements.txt        # Project dependencies  
    │  
    └── models/  
        ├── url_model_ds114.joblib     # The serialized, trained RandomForest model  
        └── url_explainer_ds114.joblib # The serialized SHAP explainer object
```

### **The Model**

The predictive engine is a RandomForestClassifier trained on the [Phishing Websites](https://www.kaggle.com/datasets/shashwatwork/phishing-dataset-for-machine-learning) dataset. Through an explainability analysis using SHAP, the initial feature set of 48 was reduced to **14 key features** with a negligible impact on performance (\~0.3% drop in accuracy). This significantly improves the efficiency of the model for live inference. The analysis and final model training can be found in the [xai_analysis_feature_comp.ipynb](/xai_analysis_feature_comp.ipynb) notebook.

### **Security Considerations**

Security is a primary concern for an application that handles potentially malicious URLs.

* **MVP Approach (Current):** To ensure safety during development, the nine features that require analyzing a page's HTML content are **simulated**. The [feature_extractor.py](/feature_extractor.py) module does *not* make any live web requests. Instead, it generates plausible feature values based on patterns in the URL string itself.  
* **Production-Ready Vision (In Process):** A production version would delegate URL fetching to an isolated, ephemeral service (e.g., a serverless function running a headless browser in a Docker container or Cloudflare AI workers). This **sandboxing** approach ensures that any malicious code from a URL cannot affect the core application infrastructure.
