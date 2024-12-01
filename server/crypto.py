"""
CryptoManager: Secure Cryptographic Operations

This module handles all cryptographic operations required for secure messaging, 
ensuring end-to-end encryption of messages between users. The functionality includes:

- Generation of RSA key pairs (private and public keys).
- Encryption of messages using a combination of AES-GCM (for data) and RSA (for key exchange).
- Decryption of received messages using private keys.
- Secure storage and exchange of cryptographic keys.

The module uses state-of-the-art cryptographic primitives from the `cryptography` library to ensure robust security.
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64

class CryptoManager:
    """
    CryptoManager: A utility class for secure cryptographic operations.

    This class provides functionalities to:
    - Generate RSA key pairs for asymmetric encryption.
    - Encrypt messages using AES-GCM for data and RSA for secure key exchange.
    - Decrypt messages using RSA and AES-GCM.
    
    All cryptographic operations use modern, secure primitives from the `cryptography` library.
    """

    def __init__(self):
        """
        Initialize the CryptoManager with placeholders for RSA key pair.
        """
        self.private_key = None
        self.public_key = None
        
    def generate_keypair(self):
        """
        Generate a new RSA key pair for asymmetric encryption.

        Returns:
            bytes: The public key in PEM format.
        """
        # Generate a private key using a secure algorithm
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        # Derive the public key from the private key
        self.public_key = self.private_key.public_key()
        return self.get_public_key_pem()
    
    def get_public_key_pem(self):
        """
        Retrieve the public key in PEM format.

        Returns:
            bytes: PEM-encoded public key suitable for sharing.
        """
        # Serialize the public key to PEM format
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def encrypt_message(self, message: str, recipient_public_key_pem: bytes):
        """
        Encrypt a message for a recipient using their public key.

        This uses AES-GCM for encrypting the message content and RSA 
        for securely encrypting the AES key.

        Args:
            message (str): The plaintext message to encrypt.
            recipient_public_key_pem (bytes): The recipient's public key in PEM format.

        Returns:
            bytes: Base64-encoded encrypted data containing the encrypted AES key, nonce, and ciphertext.
        """
        # Generate a random AES key for symmetric encryption
        aes_key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)  # Generate a random nonce for AES-GCM

        # Encrypt the message using AES-GCM
        message_bytes = message.encode()
        ciphertext = aesgcm.encrypt(nonce, message_bytes, None)

        # Encrypt the AES key using the recipient's public RSA key
        recipient_public_key = serialization.load_pem_public_key(recipient_public_key_pem)
        encrypted_key = recipient_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Combine the encrypted key, nonce, and ciphertext for transmission
        return base64.b64encode(encrypted_key + b":::" + nonce + b":::" + ciphertext)
    
    def decrypt_message(self, encrypted_data: bytes):
        """
        Decrypt an encrypted message using the private key.

        This function extracts the encrypted AES key, nonce, and ciphertext,
        and decrypts the message content.

        Args:
            encrypted_data (bytes): Base64-encoded encrypted data containing the encrypted key, nonce, and ciphertext.

        Returns:
            str: The decrypted plaintext message.
        """
        # Decode the base64-encoded data and split into components
        decoded = base64.b64decode(encrypted_data)
        encrypted_key, nonce, ciphertext = decoded.split(b":::")

        # Decrypt the AES key using the private RSA key
        aes_key = self.private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Decrypt the ciphertext using AES-GCM
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()