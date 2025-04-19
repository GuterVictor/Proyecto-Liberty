import ssl
import socket
import OpenSSL
from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})  # Allow all origins for development (change for production)

def get_ssl_certificate(domain):
    try:
        # Establish SSL connection
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.settimeout(5)
        conn.connect((domain, 443))
        ssl_info = conn.getpeercert(True)
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, ssl_info)

        # Extract commonName and organizationName
        subject = dict(cert.get_subject().get_components())
        issuer = dict(cert.get_issuer().get_components())

        common_name = subject.get(b'CN', b'').decode('utf-8')
        organization_name = issuer.get(b'O', b'').decode('utf-8')

        return {"commonName": common_name, "organizationName": organization_name}
    except Exception as e:
        # Handle connection or certificate errors
        print(f"Error retrieving certificate for {domain}: {e}")
        return {"error": "Failed to retrieve certificate information"}

@app.route('/<domain>', methods=['GET'])
def get_ssl_info(domain):
    cert_info = get_ssl_certificate(domain)

    if "error" not in cert_info:
        return jsonify(cert_info), 200
    else:
        return jsonify(cert_info), 404  # Use 404 for missing certificate

if __name__ == '__main__':
    app.run()