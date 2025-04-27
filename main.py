import ssl
import socket
import re
from urllib.parse import urlparse
from datetime import datetime, timezone
import OpenSSL
import requests
import whois
from bs4 import BeautifulSoup
from flask import Flask, jsonify
from flask_cors import CORS
import tldextract
import difflib

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# ==================== FUNCIONES CORE ====================

def get_full_cert_data(host):
    contexto = ssl.create_default_context()

    with socket.create_connection((host, 443), timeout=5) as sock:
        with contexto.wrap_socket(sock, server_hostname=host) as ssock:
            raw_cert = ssock.getpeercert(True)
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, raw_cert)

    issuer = dict(x509.get_issuer().get_components())
    subject = dict(x509.get_subject().get_components())

    not_before = datetime.strptime(x509.get_notBefore().decode('ascii'), "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
    not_after = datetime.strptime(x509.get_notAfter().decode('ascii'), "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)

    valid_days = (not_after - not_before).days
    days_to_expire = (not_after - datetime.now(timezone.utc)).days

    alt_names = []
    for i in range(x509.get_extension_count()):
        ext = x509.get_extension(i)
        if ext.get_short_name().decode() == 'subjectAltName':
            san = str(ext)
            alt_names = [x.strip().split(":")[1] for x in san.split(",") if ":" in x]

    is_self_signed = issuer == subject
    org_name = issuer.get(b'O', b'').decode()
    sig_alg = x509.get_signature_algorithm().decode()
    suspicious_san_count = len(alt_names) <= 2

    return {
        "commonName": subject.get(b'CN', b'').decode(),
        "organizationName": org_name,
        "hasOrganizationName": bool(org_name),
        "issuer": {k.decode(): v.decode() for k, v in issuer.items()},
        "isSelfSigned": is_self_signed,
        "signatureAlgorithm": sig_alg,
        "subjectAltNames": alt_names,
        "validDays": valid_days,
        "daysToExpire": days_to_expire,
        "suspiciousSANCount": suspicious_san_count,
        "usesLetsEncrypt": 'let\'s encrypt' in org_name.lower() if org_name else False
    }

def fetch_html_content(domain):
    try:
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
            )
        }
        res = requests.get(f"http://{domain}", headers=headers, timeout=6)
        return res.text if res.status_code == 200 else None
    except Exception:
        return None

def evaluar_certificado(cert, dominio):
    score = 0
    breakdown = []

    trusted_orgs = ["DigiCert", "Google Trust Services", "Amazon", "Cloudflare", "GoDaddy", "Sectigo", "GlobalSign"]
    phishing_keywords = [
        "login", "secure", "verify", "account", "wallet", "crypto",
        "exchange", "update", "signin", "bank", "alert", "security"
    ]
    weak_algorithms = ["md5", "sha1"]
    domain_len = len(dominio)
    lower_domain = dominio.lower()

    # ✅ Reglas positivas
    if cert.get("hasOrganizationName"): score -= 1; breakdown.append("✅ Tiene nombre de organización (-1)")
    if not cert.get("isSelfSigned"): score -= 1; breakdown.append("✅ No es autofirmado (-1)")
    if any(org.lower() in cert.get("organizationName", "").lower() for org in trusted_orgs):
        score -= 1; breakdown.append("✅ Organización reconocida (-1)")
    if cert.get("validDays", 0) > 180: score -= 1; breakdown.append("✅ Duración válida > 180 días (-1)")
    if len(cert.get("subjectAltNames", [])) > 5: score -= 1; breakdown.append("✅ Muchos SANs (>5) (-1)")

    # ❌ Reglas negativas
    if cert.get("isSelfSigned"): score += 2; breakdown.append("❌ Autofirmado (+2)")
    if cert.get("usesLetsEncrypt"): score += 1; breakdown.append("❌ Usa Let's Encrypt (+1)")
    if not cert.get("hasOrganizationName"): score += 1; breakdown.append("❌ Sin nombre de organización (+1)")
    if cert.get("validDays", 0) <= 90: score += 2; breakdown.append("❌ Certificado de corta duración (<= 90d) (+2)")
    if len(cert.get("subjectAltNames", [])) <= 2: score += 1; breakdown.append("❌ Pocos SANs (<= 2) (+1)")
    if cert.get("suspiciousSANCount"): score += 2; breakdown.append("❌ SAN sospechoso (+2)")

    if domain_len > 30: score += 1; breakdown.append("❌ Dominio largo (+1)")
    if dominio.count('.') > 3: score += 1; breakdown.append("❌ Subdominios excesivos (>3) (+1)")
    if any(k in lower_domain for k in phishing_keywords): score += 2; breakdown.append("❌ Palabra sospechosa (+2)")
    if any(alg in cert.get("signatureAlgorithm", "").lower() for alg in weak_algorithms):
        score += 2; breakdown.append("❌ Algoritmo débil (+2)")
    if re.search(r"([bcdfghjklmnpqrstvwxyz]{4,}){2,}", dominio.replace(".", "")):
        score += 1; breakdown.append("❌ Dominio aleatorio sospechoso (+1)")

    # WHOIS extra
    try:
        whois_data = whois.whois(dominio)
        if whois_data and not whois_data.get("org"):
            score += 1; breakdown.append("❌ WHOIS sin organización (+1)")
    except:
        pass

    # HTML extra
    html = fetch_html_content(dominio)
    if html:
        soup = BeautifulSoup(html, 'html.parser')
        if "bitcoin" in soup.get_text().lower():
            score += 2; breakdown.append("❌ Contenido sospechoso: 'bitcoin' detectado (+2)")

    # Levenshtein contra bancos
    bancos_reales = ["bbva.com", "banorte.com", "santander.com.mx", "banamex.com.mx"]
    extra = tldextract.extract(dominio)
    full_domain = f"{extra.domain}.{extra.suffix}"
    for real in bancos_reales:
        ratio = difflib.SequenceMatcher(None, full_domain, real).ratio()
        if ratio >= 0.85 and full_domain != real:
            score += 2
            breakdown.append(f"❌ Muy similar a {real} (Levenshtein +2)")
            break

    # Clasificación final
    if score <= -3: nivel = "muy_confiable"
    elif score <= -1: nivel = "confiable"
    elif score <= 1: nivel = "neutral"
    elif score <= 3: nivel = "moderado"
    elif score <= 5: nivel = "sospechoso"
    else: nivel = "peligroso"

    return {
        "dominio": dominio,
        "nivel": nivel,
        "score": score,
        "detalles": breakdown
    }

# ==================== FLASK ROUTE ====================

@app.route('/analizar/<host>', methods=['GET'])
def analizar_dominio(host):
    try:
        cert_data = get_full_cert_data(host)
        evaluacion = evaluar_certificado(cert_data, host)

        return jsonify({
            "certificado": cert_data,
            "evaluacion": evaluacion
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==================== MAIN ====================
if __name__ == '__main__':
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
