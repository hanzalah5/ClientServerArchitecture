# from flask import Flask, request, jsonify

# import ssl
# import socket

# server_app = Flask(__name__)

# @server_app.route('/process', methods=['POST'])
# def process():
#     client_message = request.json['message']
#     # You can process the message here as needed and prepare a response.
#     # For demonstration purposes, we'll just reverse the message.
#     server_response = client_message[::-1]

#     return jsonify({'response': server_response})

# if __name__ == '__main__':
#     server_app.run(debug=True, port=5000)



from flask import Flask, request, jsonify
from aes import AESFernetEncryptor
import base64
from DiffieHellmanKeyExchange import DiffieHellmanKeyExchange
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend




server_app = Flask(__name__)

SYMETRIC_KEY = None

@server_app.route('/process', methods=['POST'])
def process():
    client_message = request.json['key']
    p = 23
    g = 5
    server_dh = DiffieHellmanKeyExchange(p, g)
    server_private = server_dh.generate_private_key()
    server_public = server_dh.generate_public_key(server_private)


    print("Server SIDE KEY RECIEVED ", client_message)
    print("Server SIDE KEY RECIEVED TYPE ", type(client_message))
    shared_secret = server_dh.calculate_shared_secret(server_private, client_message)
    print("SERVER SIDE: SHARED SECRET", shared_secret)
    
    #CREATING AES ENCRYPTION SYMETRIC KEY FROM SHARED SECRET
    salt = b"random_salt"

    # Define the HKDF object with the shared secret, salt, and a hash function (e.g., SHA-256)
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        salt=salt,
        info=None,
        length=32,
        backend=default_backend()
    )

    # Convert shared_secret to bytes
    shared_secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder='big')


    # Derive the symmetric key
    symmetric_key = kdf.derive(shared_secret_bytes)
    print("SERVER SIDE: SERVER ENC KEY", symmetric_key)
    SYMETRIC_KEY = symmetric_key

    #NOW BOTH PARTIES HAVE AES ENCRYPTION KEY. WE CAN ENCRYPT DATA AND SEND IT TO EACH OTHER

    # AES WALA KAAM

    # print("SERVER SIDE: CLIENT ENC KEY", client_key)
    # print("SERVER SIDE: CLIENT ENC MESSAGE " , client_message)

    # print("DATA TYPE KEY", type(client_key))
    # print("DATA TYPE MESSAGE", type(client_message)
    # client_key = base64.b64decode(client_key)
    # client_message = base64.b64decode(client_message)
    # A = AESFernetEncryptor(client_key)
    # server_response = A.decrypt(client_message)
    # print("SERVER SIDE: SERVER DEC MESSAGE " , server_response)



    #server_response = client_message[::-1]

    return jsonify({'response': server_public})

@server_app.route('/processmessage', methods=['POST'])
def processmessage():
    client_message = request.json['message']
    A = AESFernetEncryptor(SYMETRIC_KEY)
    A.decrypt(client_message)

    print("SERVER SIDE: DECRYPTED MESSAGE " , client_message)

    return jsonify({'response': "Message Recieved"})
    


if __name__ == '__main__':
    server_app.run(debug=True, port=5000)



