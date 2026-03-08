from flask import Flask, jsonify, request
import hashlib
import base64
import secrets
import random
import os

app = Flask(__name__)
API_KEY = "caca"

DEVICES = [
    "SM-A136", "SM-X200", "SM-X205", "SM-A032", "SM-E426", "SM-M526",
    "SM-M225", "SM-M326", "SM-A037", "SM-A528", "SM-E225", "SM-M325",
    "SM-A226", "SM-A225", "SM-T730", "SM-T220", "SM-T225", "SM-E526",
    "SM-M426", "SM-E025", "SM-F127", "SM-A725", "SM-A526", "SM-A525",
    "SM-A325", "SM-M625"
]

CLIENTS = [
    "QmofH7P73vSvG7H1lJqo",
    "8KZt4ch3WEvOmslO1Zh8"
]

FILE = '/tmp/codes.txt'

# ─── Génération des codes ───────────────────────────────────────────
def generate_codes():
    codes = [str(i).zfill(5) for i in range(100000)]
    random.shuffle(codes)
    with open(FILE, 'w') as f:
        f.write('\n'.join(codes))
    print("✅ 100 000 codes générés dans /tmp/codes.txt")

# Génère les codes au démarrage si le fichier n'existe pas
if not os.path.exists(FILE) or os.path.getsize(FILE) == 0:
    print("📦 Génération des codes au démarrage...")
    generate_codes()

# ─── Auth ────────────────────────────────────────────────────────────
def check_api_key():
    if request.headers.get('X-API-Key') != API_KEY:
        return jsonify({'error': 'Unauthorized'}), 401
    return None

# ─── Routes existantes ───────────────────────────────────────────────
@app.route('/pkce', methods=['GET'])
def generate_pkce():
    auth = check_api_key()
    if auth: return auth
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode('utf-8')).digest()
    ).decode('utf-8').rstrip('=')
    return jsonify({
        'code_verifier': code_verifier,
        'code_challenge': code_challenge,
        'state': secrets.token_urlsafe(32),
        'nonce': secrets.token_urlsafe(32)
    })

@app.route('/device', methods=['GET'])
def generate_device():
    auth = check_api_key()
    if auth: return auth
    return jsonify({
        'device': random.choice(DEVICES),
        'client': random.choice(CLIENTS)
    })

@app.route('/all', methods=['GET'])
def generate_all():
    auth = check_api_key()
    if auth: return auth
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode('utf-8')).digest()
    ).decode('utf-8').rstrip('=')
    return jsonify({
        'code_verifier': code_verifier,
        'code_challenge': code_challenge,
        'state': secrets.token_urlsafe(32),
        'nonce': secrets.token_urlsafe(32),
        'device': random.choice(DEVICES),
        'client': random.choice(CLIENTS)
    })

# ─── Nouvelles routes codes ──────────────────────────────────────────
@app.route('/code', methods=['GET'])
def get_code():
    auth = check_api_key()
    if auth: return auth

    with open(FILE, 'r') as f:
        content = f.read().strip()

    if not content:
        return jsonify({'error': 'Plus aucun code disponible.'}), 410

    lines = content.split('\n')
    code = lines.pop(0)

    with open(FILE, 'w') as f:
        f.write('\n'.join(lines))

    return jsonify({
        'code': code,
        'restants': len(lines)
    })

@app.route('/code/reset', methods=['POST'])
def reset_codes():
    auth = check_api_key()
    if auth: return auth
    generate_codes()
    return jsonify({'message': '✅ Codes régénérés !', 'total': 100000})

@app.route('/code/count', methods=['GET'])
def count_codes():
    auth = check_api_key()
    if auth: return auth
    with open(FILE, 'r') as f:
        content = f.read().strip()
    count = len(content.split('\n')) if content else 0
    return jsonify({'restants': count})

# ─── Health ──────────────────────────────────────────────────────────
@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    app.run()
