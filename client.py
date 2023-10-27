from flask import Flask, request, render_template, jsonify, session
import requests
import base64
import sha256
import os

from DiffieHellmanKeyExchange import DiffieHellmanKeyExchange
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from aes import AESFernetEncryptor

client_app = Flask(__name__)
client_app.secret_key = os.urandom(24)
SYMETRIC_KEY = None

@client_app.route('/')
def home():
    return render_template('client.html')


@client_app.route('/button_click', methods=['GET'])
def button_click():

    # DEFFIE HELLMAN KEY EXCHANGE 
    p = 23
    g = 5

    client_dh = DiffieHellmanKeyExchange(p, g)
    client_private = client_dh.generate_private_key()
    client_public = client_dh.generate_public_key(client_private)

    server_response = send_message_to_server(client_public)
    print("SERVER RESPONSE TYPE", type(server_response))

    print("SERVER RESPONSE", server_response)

    # Generate shared secret
    shared_secret = client_dh.calculate_shared_secret(client_private, server_response)
    print("CLIENT SIDE: SHARED SECRET", shared_secret)


    # Generate AES encryption key
    #CREATING AES ENCRYPTION SYMETRIC KEY FROM SHARED SECRET
    salt = b"random_salt"

    # Define the HKDF object with the shared secret, salt, and a hash function (e.g., SHA-256)
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        salt=salt,
        info=None,
        length = 32,
        backend=default_backend()
    )

    # Convert shared_secret to bytes
    shared_secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder='big')


    # Derive the symmetric key
    symmetric_key = kdf.derive(shared_secret_bytes)
    print("CLIENT SIDE: CLIENT ENC KEY", symmetric_key)

    session['key'] = symmetric_key
    global SYMETRIC_KEY
    SYMETRIC_KEY = symmetric_key
    print("symmetric key", SYMETRIC_KEY)


    return jsonify({'response': "Key Generated"})



@client_app.route('/send', methods=['POST'])
def send():
    key = session.get('key')
    # if key is not None:
    #     return jsonify({'response': "NO KEY"})
    
    client_message = request.form['message']
    # Send the message to the server

    # AES WALA KAAM 
    print("HERE")
    A = AESFernetEncryptor(SYMETRIC_KEY)
    client_enc_msg = A.encrypt(client_message)
    print("CLIENT SIDE: CLIENT SIMPLE MESSAGE " , client_message)
    print("CLIENT SIDE: CLIENT ENC MESSAGE " , client_enc_msg)
    print("DATA TYPE MESSAGE", type(client_enc_msg))

    send_enc_message_to_server(client_enc_msg)

    # server_response = send_message_to_server(client_public)

    # if server_response == 'some condition':
    #     # Encrypt your message
    #     shared_secret = client_dh.calculate_shared_secret(client_private, server_public_key)
    #     encryptor = AESFernetEncryptor(shared_secret)
    #     encrypted_message = encryptor.encrypt(client_message)

    #     # Send the encrypted message to the server
    #     response = send_message_to_server(encrypted_message)

    # return jsonify({'response': server_response})

def send_message_to_server(message):
    server_url = 'http://localhost:5000/process'

    # Convert the binary data to base64-encoded strings
    # common_AES_key_base64 = base64.b64encode(common_AES_key).decode("utf-8")
    # client_enc_msg_base64 = base64.b64encode(message).decode("utf-8")

    data = {'key': message }

    response = requests.post(server_url, json=data)

    if response.status_code == 200:
        return response.json()['response']
    else:
        return 'Error communicating with the server'
    

def send_enc_message_to_server(message):
    server_url = 'http://localhost:5000/processmessage'

    message = base64.b64encode(message).decode("utf-8")

    data = {'message': message }

    response = requests.post(server_url, json=data)

    if response.status_code == 200:
        return response.json()['response']
    else:
        return 'Error communicating with the server'



if __name__ == '__main__':
    client_app.run(debug=True, port=5001)