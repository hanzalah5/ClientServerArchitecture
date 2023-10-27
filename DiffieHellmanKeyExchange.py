import random

class DiffieHellmanKeyExchange:
    def __init__(self, prime, base):
        self.p = prime
        self.g = base

    def generate_private_key(self):
        return random.randint(2, self.p - 2)

    def generate_public_key(self, private_key):
        return (self.g ** private_key) % self.p

    def calculate_shared_secret(self, own_private_key, other_public_key):
        return (other_public_key ** own_private_key) % self.p

# if __name__ == "__main__":
#     # Diffie-Hellman parameters (prime and base)
#     p = 23  # A prime number
#     g = 5   # A primitive root modulo p

#     # Create instances for Alice and Bob
#     alice_dh = DiffieHellmanKeyExchange(p, g)
#     bob_dh = DiffieHellmanKeyExchange(p, g)

#     # Generate private and public keys for Alice and Bob
#     a_private = alice_dh.generate_private_key()
#     a_public = alice_dh.generate_public_key(a_private)

#     b_private = bob_dh.generate_private_key()
#     b_public = bob_dh.generate_public_key(b_private)

#     # Key exchange
#     shared_secret_alice = alice_dh.calculate_shared_secret(a_private, b_public)
#     shared_secret_bob = bob_dh.calculate_shared_secret(b_private, a_public)

#     # Ensure both parties have the same shared secret
#     assert shared_secret_alice == shared_secret_bob

#     print("Shared Secret (Alice & Bob):", shared_secret_alice)
