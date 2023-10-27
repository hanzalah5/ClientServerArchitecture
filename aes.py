from cryptography.fernet import Fernet

class AESFernetEncryptor:
    def __init__(self, aes_key=None):
        if aes_key is None:
            self.aes_key = Fernet.generate_key()
        else:
            self.aes_key = aes_key

    def encrypt(self, plaintext):
        cipher_suite = Fernet(self.aes_key)
        encrypted_text = cipher_suite.encrypt(plaintext.encode())
        return encrypted_text

    def decrypt(self, ciphertext):
        cipher_suite = Fernet(self.aes_key)
        decrypted_text = cipher_suite.decrypt(ciphertext).decode()
        return decrypted_text

    def get_aes_key(self):
        return self.aes_key
