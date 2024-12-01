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

