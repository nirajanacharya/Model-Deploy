import streamlit as st
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
import tensorflow as tf  # Add this import
import joblib
from urllib.parse import urlparse
import ipaddress
import re

try:
    # Load the pre-trained model and scaler
    # best_model = tf.keras.models.load_model('Final_GA_Best_Model.h5')  # Load Keras model
    best_model = tf.keras.models.load_model('Final_GA_Best_Model.h5')
    scaler = joblib.load('minmax_scaler.pkl')  # Load scaler with joblib
except Exception as e:
    st.error(f"Error loading model files: {str(e)}")
    st.stop()

# Define feature extraction functions
def contains_ip_address(url):
    try:
        result = urlparse(url)
        hostname = result.hostname
        if hostname is None:
            return 0
        ipaddress.ip_address(hostname)
        return 1
    except ValueError:
        return 0
    except Exception:
        return 0

def hostname_length(url):
    try:
        return len(urlparse(url).netloc)
    except:
        return 0

def path_length(url):
    try:
        return len(urlparse(url).path)
    except:
        return 0

def first_directory_length(url):
    try:
        directories = urlparse(url).path.split('/')
        for directory in directories:
            if directory:
                return len(directory)
        return 0
    except:
        return 0

def digit_count(url):
    return sum(c.isdigit() for c in url)

def domain_name_length(url):
    try:
        return len(urlparse(url).netloc)
    except:
        return 0

def no_of_dir(url):
    try:
        return urlparse(url).path.count('/')
    except:
        return 0

def letter_count(url):
    try:
        return sum(c.isalpha() for c in url)
    except:
        return 0

def check_double_slash(url):
    try:
        return 1 if url.startswith(('http://', 'https://')) else 0
    except:
        return 0

def check_shortening_service(url):
    shortening_services = [
        r"shorte\.st", r"go2l\.ink", r"x\.co", r"tinyurl", r"tr\.im", r"is\.gd", r"cli\.gs",
        r"yfrog\.com", r"migre\.me", r"ff\.im", r"tiny\.cc", r"url4\.eu", r"twit\.ac", r"su\.pr",
        r"twurl\.nl", r"snipurl\.com", r"short\.to", r"BudURL\.com", r"ping\.fm", r"post\.ly",
        r"Just\.as", r"bkite\.com", r"snipr\.com", r"fic\.kr", r"loopt\.us", r"doiop\.com",
        r"short\.ie", r"kl\.am", r"wp\.me", r"rubyurl\.com", r"om\.ly", r"to\.ly", r"bit\.do",
        r"lnkd\.in", r"db\.tt", r"qr\.ae", r"adf\.ly", r"goo\.gl", r"bitly\.com", r"cur\.lv",
        r"ity\.im", r"q\.gs", r"po\.st", r"bc\.vc", r"twitthis\.com", r"u\.to", r"j\.mp",
        r"buzurl\.com", r"cutt\.us", r"u\.bb", r"yourls\.org", r"prettylinkpro\.com",
        r"scrnch\.me", r"filoops\.info", r"vzturl\.com", r"qr\.net", r"1url\.com", r"tweez\.me",
        r"v\.gd", r"link\.zip\.net"
    ]
    return 1 if any(re.search(service, url, re.IGNORECASE) for service in shortening_services) else 0

# Streamlit app

st.markdown("""
    <div style='text-align: right; margin-bottom: 20px;'>
        <a href='https://urlphisingdetection.vercel.app/' target='_blank' 
           style='background-color: #0e1117; color: white; 
                  padding: 8px 16px; border-radius: 4px; 
                  text-decoration: none; font-weight: bold;'>
            🏠 Back to Homepage
        </a>
    </div>
""", unsafe_allow_html=True)
st.title("Surakshit Web: URL Safety Checker")
# Add styled home link

url_input = st.text_input("Enter URL")

if st.button("Predict"):
    new_data = pd.DataFrame({'url': [url_input]})
    new_data['contains_ip'] = new_data['url'].apply(contains_ip_address)
    new_data['hostname_length'] = new_data['url'].apply(hostname_length)
    new_data['path_length'] = new_data['url'].apply(path_length)
    new_data['fd_length'] = new_data['url'].apply(first_directory_length)
    new_data['url_length'] = new_data['url'].apply(len)
    new_data['count@'] = new_data['url'].apply(lambda i: i.count('@'))
    new_data['count?'] = new_data['url'].apply(lambda i: i.count('?'))
    new_data['count%'] = new_data['url'].apply(lambda i: i.count('%'))
    new_data['count='] = new_data['url'].apply(lambda i: i.count('='))
    new_data['count-'] = new_data['url'].apply(lambda i: i.count('-'))
    new_data['count.'] = new_data['url'].apply(lambda i: i.count('.'))
    new_data['count#'] = new_data['url'].apply(lambda i: i.count('#'))
    new_data['count&'] = new_data['url'].apply(lambda i: i.count('&'))
    new_data['count+'] = new_data['url'].apply(lambda i: i.count('+'))
    new_data['count$'] = new_data['url'].apply(lambda i: i.count('$'))
    new_data['count-www'] = new_data['url'].apply(lambda i: i.count('www'))
    new_data['count-digits'] = new_data['url'].apply(digit_count)
    new_data['domain_name_length'] = new_data['url'].apply(domain_name_length)
    new_data['count_dir'] = new_data['url'].apply(no_of_dir)
    new_data['count-letters'] = new_data['url'].apply(letter_count)
    new_data['http(s)-double_slash'] = new_data['url'].apply(check_double_slash)
    new_data['hyphen'] = new_data['url'].str.contains('-').astype(int)
    new_data['shortening_service'] = new_data['url'].apply(check_shortening_service)
    new_data['http_https'] = new_data['url'].apply(check_double_slash)
    
    columns_to_scale = [
        'contains_ip', 'hostname_length', 'path_length', 'fd_length', 'url_length', 'count@', 'count?', 'count%',
        'count=', 'count-', 'count.', 'count#', 'count&', 'count+', 'count$', 'count-www', 'count-digits',
        'domain_name_length', 'count_dir', 'count-letters', 'http(s)-double_slash', 'hyphen',
        'shortening_service'
    ]
    new_data[columns_to_scale] = scaler.transform(new_data[columns_to_scale])
    features_new = new_data.drop(columns=['url']).to_numpy()
    prediction = best_model.predict(features_new)
    
    # Add threshold classification and display results
    threshold = 0.5
    prediction_percentage = prediction[0][0] * 100
    is_malicious = prediction[0][0] >= threshold
    
    # Display prediction results
    st.write("---")
    st.write("### Prediction Results")
    if is_malicious:
        st.error(f"⚠️ This URL is classified as MALICIOUS (Confidence: {prediction_percentage:.2f}%)")
    else:
        st.success(f"✅ This URL is classified as Safe (Confidence: {100-prediction_percentage:.2f}%)")
    
    # Display important features
    st.write("### URL Analysis")
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**Basic URL Properties:**")
        st.write(f"- URL Length: {len(url_input)}")
        st.write(f"- Domain Length: {domain_name_length(url_input)}")
        st.write(f"- Contains IP Address: {'Yes' if contains_ip_address(url_input) else 'No'}")
        st.write(f"- Uses URL Shortener: {'Yes' if check_shortening_service(url_input) else 'No'}")
        st.write(f"- Uses HTTPS: {'Yes' if url_input.startswith('https://') else 'No'}")
    
    with col2:
        st.write("**Special Character Count:**")
        st.write(f"- @ symbols: {url_input.count('@')}")
        st.write(f"- Dots (.): {url_input.count('.')}")
        st.write(f"- Hyphens (-): {url_input.count('-')}")
        st.write(f"- Numbers: {sum(c.isdigit() for c in url_input)}")
        st.write(f"- Special chars: {sum(not c.isalnum() for c in url_input)}")
    
    # Display warning signs if present
    suspicious_features = []
    if contains_ip_address(url_input):
        suspicious_features.append("Contains IP address instead of domain name")
    if check_shortening_service(url_input):
        suspicious_features.append("Uses URL shortening service")
    if url_input.count('@') > 0:
        suspicious_features.append("Contains @ symbol")
    if len(url_input) > 75:
        suspicious_features.append("Unusually long URL")
    
    if suspicious_features:
        st.write("### ⚠️ Warning Signs Detected")
        for feature in suspicious_features:
            st.warning(feature)