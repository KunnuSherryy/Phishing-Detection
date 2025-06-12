from flask import Flask, redirect, url_for, render_template, request
import joblib
from predict import predict_url_phishing_status

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check', methods=['POST'])  # ✅ Fix: 'methods' not 'method'
def check():
    url = request.form['url']
    result = 'Phishing Website' if predict_url_phishing_status(url) == 1 else 'Legitimate Website'
    return render_template('index.html', result=result)


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=10000)

