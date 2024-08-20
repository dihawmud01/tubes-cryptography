import os
from flask import Flask, jsonify, Response, request, render_template
from flask_cors import CORS
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

app = Flask(__name__)
CORS(app)

class BlockCipherModes:
    def __init__(self, key):
        self.key = key

    def ecb_encrypt(self, plaintext):
        cipher = AES.new(self.key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        return base64.b64encode(ciphertext).decode()

    def ecb_decrypt(self, ciphertext):
        cipher = AES.new(self.key, AES.MODE_ECB)
        plaintext = unpad(cipher.decrypt(base64.b64decode(ciphertext)), AES.block_size)
        return plaintext.decode()

    def cbc_encrypt(self, plaintext):
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ciphertext = iv + cipher.encrypt(pad(plaintext, AES.block_size))
        return base64.b64encode(ciphertext).decode()

    def cbc_decrypt(self, ciphertext):
        ciphertext = base64.b64decode(ciphertext)
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)
        return plaintext.decode()

    def cfb_encrypt(self, plaintext):
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CFB, iv)
        ciphertext = iv + cipher.encrypt(plaintext)
        return base64.b64encode(ciphertext).decode()

    def cfb_decrypt(self, ciphertext):
        ciphertext = base64.b64decode(ciphertext)
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CFB, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.decode()

    def ofb_encrypt(self, plaintext):
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_OFB, iv)
        ciphertext = iv + cipher.encrypt(plaintext)
        return base64.b64encode(ciphertext).decode()

    def ofb_decrypt(self, ciphertext):
        ciphertext = base64.b64decode(ciphertext)
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_OFB, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.decode()

    def ctr_encrypt(self, plaintext):
        cipher = AES.new(self.key, AES.MODE_CTR)
        ciphertext = cipher.nonce + cipher.encrypt(plaintext)
        return base64.b64encode(ciphertext).decode()

    def ctr_decrypt(self, ciphertext):
        ciphertext = base64.b64decode(ciphertext)
        nonce = ciphertext[:AES.block_size//2]
        cipher = AES.new(self.key, AES.MODE_CTR, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext[AES.block_size//2:])
        return plaintext.decode()

@app.errorhandler(500)
def internal_server_error(e):
    return 'It works! Tapi Error', 500

@app.errorhandler(404)
def resource_not_found(e):
    return jsonify(error=str(e)), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify(error=str(e)), 405

@app.errorhandler(401)
def unauthorized(e):
    return Response("API Key required.", 401)

@app.route('/ping')
def ping():
    return 'pong'

@app.route('/', methods=['GET', 'POST'])
def home():
    result = None
    if request.method == 'POST':
        message = request.form['message']
        key = request.form['key']
        mode = request.form['mode']
        action = request.form['action']
        cipher = BlockCipherModes(key.encode())
        
        try:
            if action == 'encrypt':
                result = cipher.ecb_encrypt(message.encode()) if mode == 'ECB' else \
                         cipher.cbc_encrypt(message.encode()) if mode == 'CBC' else \
                         cipher.cfb_encrypt(message.encode()) if mode == 'CFB' else \
                         cipher.ofb_encrypt(message.encode()) if mode == 'OFB' else \
                         cipher.ctr_encrypt(message.encode()) if mode == 'CTR' else "Invalid mode"
            elif action == 'decrypt':
                result = cipher.ecb_decrypt(message) if mode == 'ECB' else \
                         cipher.cbc_decrypt(message) if mode == 'CBC' else \
                         cipher.cfb_decrypt(message) if mode == 'CFB' else \
                         cipher.ofb_decrypt(message) if mode == 'OFB' else \
                         cipher.ctr_decrypt(message) if mode == 'CTR' else "Invalid mode"
        except ValueError as e:
            result = str(e)
            
    return render_template('index.html', result=result)

@app.route('/api', methods=['POST'])
def api():
    data = request.json
    key = data['key'].encode()
    mode = data['mode']
    action = data['action']
    input_text = data['inputText'].encode()

    cipher = BlockCipherModes(key)

    try:
        if action == 'encrypt':
            if mode == 'ECB':
                output = cipher.ecb_encrypt(input_text)
            elif mode == 'CBC':
                output = cipher.cbc_encrypt(input_text)
            elif mode == 'CFB':
                output = cipher.cfb_encrypt(input_text)
            elif mode == 'OFB':
                output = cipher.ofb_encrypt(input_text)
            elif mode == 'CTR':
                output = cipher.ctr_encrypt(input_text)
        elif action == 'decrypt':
            if mode == 'ECB':
                output = cipher.ecb_decrypt(input_text.decode())
            elif mode == 'CBC':
                output = cipher.cbc_decrypt(input_text.decode())
            elif mode == 'CFB':
                output = cipher.cfb_decrypt(input_text.decode())
            elif mode == 'OFB':
                output = cipher.ofb_decrypt(input_text.decode())
            elif mode == 'CTR':
                output = cipher.ctr_decrypt(input_text.decode())
        else:
            return jsonify({'error': 'Invalid action'}), 400

        return jsonify({'output': output}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(debug=True, host="0.0.0.0", port=port)