from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

class AsymmetricKeyManager:
    """Manager for asymmetric RSA keys"""
    
    def __init__(self, key_size=2048):
        self.private_key = None
        self.public_key = None
        self.key_size = key_size
        self.generate_key_pair()  # Calls the correct method
    
    def generate_key_pair(self):
        key = RSA.generate(self.key_size)
        self.private_key = key
        self.public_key = key.publickey()
        print(f"[Keys] RSA key pair of {self.key_size} bits generated!")
    
    def encrypt_with_public_key(self, data, recipient_public_key):
        cipher_rsa = PKCS1_OAEP.new(recipient_public_key)
        return cipher_rsa.encrypt(data)
    
    def decrypt_with_private_key(self, encrypted_data):
        cipher_rsa = PKCS1_OAEP.new(self.private_key)
        return cipher_rsa.decrypt(encrypted_data)
    
    def export_public_key(self):
        return self.public_key.export_key().decode('utf-8')
    
    def import_public_key(self, public_key_pem):
        return RSA.import_key(public_key_pem.encode('utf-8'))
    
    def generate_session_key(self, size=32):
        return get_random_bytes(size)  # 32 bytes = 256 bits