from flask import Flask, jsonify, request
from flask_cors import CORS
import main  # your existing main.py logic

app = Flask(__name__)
CORS(app)  # allows your dashboard to talk to this server

@app.route('/run-scan', methods=['POST'])
def run_scan():
    data = request.json
    # pass config from dashboard to your scanner
    results = main.run(data)
    return jsonify(results)

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "running"})

if __name__ == '__main__':
    app.run(port=5000)