#File "hsm.py" in ./S2
from flask import Flask, request, jsonify 
import ssl
import tink
from tink import aead

app = Flask(__name__)

# Initialisation de Google Tink
def init_tink():
    aead.register()
    keyset_handle = tink.new_keyset_handle(aead.aead_key_templates.AES256_GCM)
    return keyset_handle

keyset_handle = init_tink()

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = bytes.fromhex(request.json['data'])
    aead_primitive = keyset_handle.primitive(aead.Aead)
    ciphertext = aead_primitive.encrypt(data, b'')
    return jsonify({'encrypted': ciphertext.hex()})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = bytes.fromhex(request.json['data'])
    aead_primitive = keyset_handle.primitive(aead.Aead)
    plaintext = aead_primitive.decrypt(data, b'')
    return jsonify({'decrypted': plaintext.hex()})

if __name__ == '__main__':
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain('cert.pem', 'key.pem')
    app.run(host='0.0.0.0', port=8081, ssl_context=ssl_context)
