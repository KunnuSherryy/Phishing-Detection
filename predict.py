import pandas as pd
import joblib
from extract_features import extract_features_from_url  # your own function

# === Load the model and features once ===
model_data = joblib.load('utils/scaled_model.joblib')
model = model_data['model']
top_20_features = model_data['features']

# === Define min-max values for manual scaling ===
min_max_values = {
    'directory_length': (-1, 1286), 'time_domain_activation': (-1, 17775),
    'qty_comma_directory': (-1, 5), 'file_length': (-1, 1232),
    'qty_slash_directory': (-1, 22), 'qty_asterisk_directory': (-1, 60),
    'length_url': (4, 4165), 'qty_underline_directory': (-1, 17),
    'qty_slash_url': (0, 44), 'qty_plus_file': (-1, 19),
    'qty_and_directory': (-1, 26), 'qty_and_file': (-1, 3),
    'ttl_hostname': (-1, 604800), 'time_response': (-1.0, 38.402411),
    'asn_ip': (-1, 395754), 'time_domain_expiration': (-1, 22574),
    'qty_dot_directory': (-1, 19), 'qty_asterisk_file': (-1, 60),
    'qty_exclamation_directory': (-1, 9), 'qty_hyphen_file': (-1, 21)
}

# === Define prediction function ===
def predict_url_phishing_status(url: str) -> int:
    # Extract features
    features_dict = extract_features_from_url(url)

    # Ensure all expected features are present
    for col in top_20_features:
        if col not in features_dict:
            features_dict[col] = 0

    # Manual min-max normalization
    scaled_features = {}
    for feature in top_20_features:
        value = features_dict[feature]
        min_val, max_val = min_max_values[feature]
        if max_val == min_val:
            scaled = 0.0
        else:
            scaled = (value - min_val) / (max_val - min_val)
        scaled_features[feature] = scaled

    # Predict
    df_test = pd.DataFrame([scaled_features])
    prediction = model.predict(df_test)[0]

    return int(prediction)  # 1 = Phishing, 0 = Legitimate
