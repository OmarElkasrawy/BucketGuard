from flask import Flask, request, jsonify
from flask import make_response
from detection import detect_misconfigurations
from remediation import remediate_issue
from flask_cors import CORS
import boto3

app = Flask(__name__)

CORS(app, resources={r"/*": {"origins": "http://localhost:8080"}}, supports_credentials=True)

s3 = boto3.client('s3')

app = Flask(__name__)

@app.route('/detect', methods=['GET'])
def detect():
    """Detect misconfigurations in a selected bucket."""
    bucket_name = request.args.get('bucket')
    print(f"🔍 DEBUG: Received bucket name -> {bucket_name}")  # ✅ Debugging

    if not bucket_name:
        return jsonify({"error": "Bucket name is required"}), 400

    detected_issues = detect_misconfigurations(bucket_name)  # Call detection function
    
    # ✅ Add explicit CORS headers to allow Vue requests
    response = jsonify({"bucket": bucket_name, "issues": detected_issues})
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response

@app.route('/remediate', methods=['POST', 'OPTIONS'])  # ✅ Allow OPTIONS for preflight checks
def remediate():
    """Remediate a selected misconfiguration."""
    if request.method == 'OPTIONS':  # ✅ Handle preflight requests
        response = jsonify({"message": "CORS preflight passed"})
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        return response

    data = request.get_json()
    bucket_name = data.get('bucket')
    issue = data.get('issue')

    if not bucket_name or not issue:
        return jsonify({"error": "Bucket name and issue are required"}), 400

    remediation_result = remediate_issue(bucket_name, issue)  # Call remediation function

    # ✅ Ensure the response includes CORS headers
    response = jsonify({"message": remediation_result})
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response


@app.route('/buckets', methods=['GET'])
def list_buckets():
    """Lists all available S3 buckets."""
    try:
        response = s3.list_buckets()
        buckets = [bucket['Name'] for bucket in response['Buckets']]
        print(f"🔍 DEBUG: Found Buckets -> {buckets}")  # ✅ Debug print

        # ✅ Add headers to fix CORS
        res = make_response(jsonify({"buckets": buckets}))
        res.headers["Access-Control-Allow-Origin"] = "*"
        res.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        res.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        return res
    except Exception as e:
        print(f"❌ ERROR: {e}")  # ✅ Print error
        return jsonify({"error": str(e)}), 500

@app.route('/add-machine', methods=['POST', 'OPTIONS'])  # Allow OPTIONS
def add_machine():
    if request.method == 'OPTIONS':
        response = jsonify({"message": "CORS preflight passed"})
        response.headers["Access-Control-Allow-Origin"] = "http://localhost:8080"
        response.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        return response

    data = request.get_json()
    access_key = data.get('access_key')
    secret_key = data.get('secret_key')

    if not access_key or not secret_key:
        return jsonify({"error": "Access key and secret key are required"}), 400

    try:
        # Initialize boto3 session with provided credentials
        session = boto3.session.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key
        )
        global s3
        s3 = session.client('s3')
        response = jsonify({"message": "Machine added successfully"})
        response.headers["Access-Control-Allow-Origin"] = "http://localhost:8080"
        return response
    except Exception as e:
        response = jsonify({"error": str(e)})
        response.headers["Access-Control-Allow-Origin"] = "http://localhost:8080"
        return response, 500



if __name__ == '__main__':
    app.run(debug=True)

