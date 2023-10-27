import hashlib

class HashGenerator:
    def sha256_hash(self, data):
        sha256 = hashlib.sha256()
        sha256.update(data.encode())
        return sha256.hexdigest()
