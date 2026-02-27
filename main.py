from flask import Flask, jsonify, request
import hashlib
import base64
import secrets

app = Flask(__name__)

API_KEY = "caca"

@app.route('/pkce', methods=['GET'])
def generate_pkce():
    if request.headers.get('X-API-Key') != API_KEY:
        return jsonify({'error': 'Unauthorized'}), 401

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

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    app.run()
