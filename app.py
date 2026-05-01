# app.py
# Firewall Log Analyzer Backend (Flask API)

from flask import Flask, request, jsonify
from flask_cors import CORS
from log_parser import parse_logs

app = Flask(__name__)

# Enable CORS so your frontend (localhost:5500) can call backend (localhost:5000)
CORS(app)

# Limit upload size to 10MB
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024


@app.route('/analyze', methods=['POST'])
def analyze():
    """
    Endpoint: POST /analyze

    Accepts:
        file (multipart/form-data)

    Returns:
        {
            total_logs: int,
            blocked: int,
            top_ips: [{ip, count}]
        }
    """

    # Check if file exists in request
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded (use 'file' field)"}), 400

    file = request.files['file']

    # Check filename
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400

    # Check file type (basic safety)
    if not (file.filename.endswith('.log') or file.filename.endswith('.txt')):
        return jsonify({"error": "Only .log or .txt files allowed"}), 400

    try:
        # Read file
        content = file.read().decode('utf-8', errors='ignore')

        # Parse logs
        result = parse_logs(content)

        # Validate output structure
        return jsonify({
            "total_logs": result.get("total_logs", 0),
            "blocked": result.get("blocked", 0),
            "top_ips": result.get("top_ips", [])
        })

    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route('/', methods=['GET'])
def home():
    return jsonify({
        "status": "running",
        "message": "Firewall Log Analyzer API ready",
        "endpoint": "/analyze (POST)"
    })


# Run server
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)