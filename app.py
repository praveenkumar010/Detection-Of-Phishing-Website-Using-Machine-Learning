from flask import Flask, request, render_template, jsonify
import joblib
import numpy as np
import re
from urllib.parse import urlparse
from tld import get_tld

app = Flask(__name__)

# Load your saved Random Forest model
model = joblib.load('random_forest_model.pkl')

# Feature extraction function
def extract_features(url):
    def having_ip_address(url):
        match = re.search(
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'
            '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)|'
            '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)
        return 1 if match else 0

    def abnormal_url(url):
        hostname = urlparse(url).hostname
        hostname = str(hostname)
        match = re.search(hostname, url)
        return 1 if match else 0

    def count_dot(url):
        return url.count('.')

    def count_www(url):
        return url.count('www')

    def count_atrate(url):
        return url.count('@')

    def no_of_dir(url):
        return urlparse(url).path.count('/')

    def no_of_embed(url):
        return urlparse(url).path.count('//')

    def shortening_service(url):
        match = re.search(
            'bit\.ly|goo\.gl|shorte\.st|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|yfrog\.com|su\.pr|u\.to|buzurl\.com|'
            'qr\.net|tinyurl\.com|ow\.ly|ity\.im|v\.gd|tr\.im|link\.zip\.net', url)
        return 1 if match else 0

    def count_https(url):
        return url.count('https')

    def count_http(url):
        return url.count('http')

    def count_per(url):
        return url.count('%')

    def count_ques(url):
        return url.count('?')

    def count_hyphen(url):
        return url.count('-')

    def count_equal(url):
        return url.count('=')

    def url_length(url):
        return len(url)

    def hostname_length(url):
        return len(urlparse(url).netloc)

    def suspicious_words(url):
        match = re.search('PayPal|login|signin|bank|account|update|free|service|ebayisapi', url)
        return 1 if match else 0

    def digit_count(url):
        return sum(c.isdigit() for c in url)

    def letter_count(url):
        return sum(c.isalpha() for c in url)

    def fd_length(url):
        urlpath = urlparse(url).path
        try:
            return len(urlpath.split('/')[1])
        except IndexError:
            return 0

    def tld_length(url):
        tld = get_tld(url, fail_silently=True)
        return len(tld) if tld else 0

    # Combine all features into a list
    features = [
        having_ip_address(url),
        abnormal_url(url),
        count_dot(url),
        count_www(url),
        count_atrate(url),
        no_of_dir(url),
        no_of_embed(url),
        shortening_service(url),
        count_https(url),
        count_http(url),
        count_per(url),
        count_ques(url),
        count_hyphen(url),
        count_equal(url),
        url_length(url),
        hostname_length(url),
        suspicious_words(url),
        digit_count(url),
        letter_count(url),
        fd_length(url),
        tld_length(url),
    ]
    return features

@app.route('/')
def index():
    return render_template('example.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': 'Invalid input or missing URL'}), 400

    url = data['url']
    features = np.array(extract_features(url)).reshape(1, -1)
    prediction = model.predict(features)
    result = "SAFE" if prediction[0] == 0 else "PHISHING"
    return jsonify({'prediction': result})

if __name__ == '__main__':
    app.run(debug=True)
