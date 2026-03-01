from flask import Flask, jsonify, request
import hashlib
import base64
import secrets
import random

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

def check_api_key():
    if request.headers.get('X-API-Key') != API_KEY:
        return jsonify({'error': 'Unauthorized'}), 401
    return None

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

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    app.run()
