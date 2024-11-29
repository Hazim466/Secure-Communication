# crypto.py - Handles all cryptographic operations
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64

class CryptoManager:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        
    def generate_keypair(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        return self.get_public_key_pem()
    
    def get_public_key_pem(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    # Encrypt Message
    def encrypt_message(self, message: str, recipient_public_key_pem: bytes):
        # Generate a random AES key
        aes_key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        
        # Encrypt the message using AES-GCM
        message_bytes = message.encode()
        ciphertext = aesgcm.encrypt(nonce, message_bytes, None)
        
        # Encrypt the AES key using recipient's public key
        recipient_public_key = serialization.load_pem_public_key(recipient_public_key_pem)
        encrypted_key = recipient_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Combine all components
        return base64.b64encode(encrypted_key + b":::" + nonce + b":::" + ciphertext)
