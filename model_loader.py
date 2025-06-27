# model_loader.py
# This module is responsible for loading the pre-trained, serialized machine
# learning assets (the model and the SHAP explainer) from disk into memory.

import joblib
import os
from sklearn.ensemble import RandomForestClassifier
import shap

# --- Constants for Model Paths ---
# We define the paths as constants to make them easy to update in one place.
# These paths are relative to the project's root directory.
MODEL_DIR = "models"
MODEL_PATH = os.path.join(MODEL_DIR, "url_model_ds114.joblib")
EXPLAINER_PATH = os.path.join(MODEL_DIR, "url_explainer_ds114.joblib")

# ==============================================================================
# I. Public API Functions
# ==============================================================================

def load_model(path: str = MODEL_PATH) -> RandomForestClassifier | None:
    """
    Loads the serialized RandomForestClassifier model from the specified path.

    Args:
        path (str): The file path to the serialized .joblib model file.

    Returns:
        The loaded, ready-to-use scikit-learn RandomForestClassifier object.
        Returns None if the file is not found.
    """
    try:
        model = joblib.load(path)
        print(f"Model successfully loaded from: {path}")
        return model
    except FileNotFoundError:
        print(f"Error: Model file not found at '{path}'.")
        print("Please ensure you have run the 'xai_analysis_feature_comp.ipynb' notebook to generate the model file.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred while loading the model: {e}")
        return None

def load_explainer(path: str = EXPLAINER_PATH) -> shap.TreeExplainer | None:
    """
    Loads the serialized SHAP TreeExplainer object from the specified path.

    Args:
        path (str): The file path to the serialized .joblib explainer file.

    Returns:
        The loaded, ready-to-use SHAP TreeExplainer object.
        Returns None if the file is not found.
    """
    try:
        explainer = joblib.load(path)
        print(f"SHAP explainer successfully loaded from: {path}")
        return explainer
    except FileNotFoundError:
        print(f"Error: Explainer file not found at '{path}'.")
        print("Please ensure you have run the 'xai_analysis_feature_comp.ipynb' notebook to generate the explainer file.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred while loading the explainer: {e}")
        return None

# --- Example Usage (for testing) ---
# This block allows us to run this file directly to test the loading functions.
if __name__ == '__main__':
    print("--- Testing Asset Loading ---")

    # Test loading the model
    print("\nAttempting to load the model...")
    loaded_model = load_model()
    if loaded_model:
        print(f"Successfully loaded a '{type(loaded_model).__name__}' object.")
        # inspect the model's parameters
        print("Model parameters:", loaded_model.get_params())

    print("\n" + "="*50 + "\n")

    # Test loading the SHAP explainer
    print("Attempting to load the SHAP explainer...")
    loaded_explainer = load_explainer()
    if loaded_explainer:
        print(f"Successfully loaded a '{type(loaded_explainer).__name__}' object.")
        # Inspect the explainer's attributes
        print("Explainer expected value:", loaded_explainer.expected_value)

    print("\n--- Testing Complete ---")
