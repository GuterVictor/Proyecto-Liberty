import ssl
import socket
import OpenSSL
import os
from flask import Flask, jsonify
from flask_cors import CORS
from datetime import datetime

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

def get_ssl_certificate(domain, port=443):
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.settimeout(5)
        conn.connect((domain, port))
        ssl_info = conn.getpeercert(True)
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, ssl_info)

        subject = dict(cert.get_subject().get_components())
        issuer = dict(cert.get_issuer().get_components())

        not_before = datetime.strptime(cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
        not_after = datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
        now = datetime.utcnow()

        valid_days = (not_after - not_before).days
        days_to_expire = (not_after - now).days

        ext_count = cert.get_extension_count()
        subject_alt_names = []
        for i in range(ext_count):
            ext = cert.get_extension(i)
            if ext.get_short_name().decode() == 'subjectAltName':
                san = str(ext)
                subject_alt_names = [x.strip().split(':')[1] for x in san.split(',') if ':' in x]

        is_self_signed = (subject == issuer)

        org_name = issuer.get(b'O', b'').decode('utf-8')
        subj_cn = subject.get(b'CN', b'').decode('utf-8')
        issuer_cn = issuer.get(b'CN', b'').decode('utf-8')

        return {
            "commonName": subj_cn,
            "subjectCommonName": subj_cn,
            "issuerCommonName": issuer_cn,
            "organizationName": org_name,
            "hasOrganizationName": bool(org_name.strip()),
            "usesLetsEncrypt": "Let's Encrypt" in org_name,
            "isSelfSigned": is_self_signed,
            "issuer": {k.decode(): v.decode() for k, v in issuer.items()},
            "subject": {k.decode(): v.decode() for k, v in subject.items()},
            "subjectAltNames": subject_alt_names,
            "suspiciousSANCount": len(subject_alt_names) <= 1,
            "serialNumber": cert.get_serial_number(),
            "notBefore": not_before.isoformat(),
            "notAfter": not_after.isoformat(),
            "daysToExpire": days_to_expire,
            "validDays": valid_days,
            "version": cert.get_version(),
            "signatureAlgorithm": cert.get_signature_algorithm().decode()
        }

    except Exception as e:
        print(f"[❌ Error al obtener certificado]: {e}")
        return {"error": str(e)}

@app.route('/<path:domain>', methods=['GET'])
def get_ssl_info(domain):
    if ':' in domain:
        host, port = domain.split(':')
        port = int(port)
    else:
        host = domain
        port = 443

    cert_info = get_ssl_certificate(host, port)
    status_code = 200 if "error" not in cert_info else 404
    return jsonify(cert_info), status_code

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
