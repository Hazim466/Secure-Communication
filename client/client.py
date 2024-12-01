"""
Secure Messaging Client

This client application allows users to:
- Register securely with a server.
- Send encrypted messages to other users.
- View and decrypt received messages.

The application uses asymmetric encryption (RSA) and symmetric encryption (AES-GCM) for secure communication.
"""

import cmd
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import base64


class CryptoManager:
    """
    Handles encryption and decryption operations using RSA and AES-GCM.
    
    Attributes:
        private_key (rsa.RSAPrivateKey): RSA private key for decryption.
        public_key (rsa.RSAPublicKey): RSA public key for encryption.
    """
    def __init__(self):
        """Initializes the CryptoManager with no keypair."""
        self.private_key = None
        self.public_key = None

    def generate_keypair(self):
        """
        Generates an RSA keypair for encryption and decryption.

        Returns:
            bytes: The public key in PEM format.
        """
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        return self.get_public_key_pem()

    def get_public_key_pem(self):
        """
        Retrieves the public key in PEM format.

        Returns:
            bytes: The public key in PEM format.
        """
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def encrypt_message(self, message: str, recipient_public_key_pem: bytes):
        """
        Encrypts a message using the recipient's public key and AES-GCM.

        Args:
            message (str): The plaintext message to encrypt.
            recipient_public_key_pem (bytes): The recipient's public key in PEM format.

        Returns:
            bytes: The encrypted message encoded in base64 format.
        """
        aes_key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        message_bytes = message.encode()
        ciphertext = aesgcm.encrypt(nonce, message_bytes, None)

        recipient_public_key = serialization.load_pem_public_key(recipient_public_key_pem)
        encrypted_key = recipient_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted_key + b":::" + nonce + b":::" + ciphertext)

    def decrypt_message(self, encrypted_data: bytes):
        """
        Decrypts a message using the private RSA key and AES-GCM.

        Args:
            encrypted_data (bytes): The encrypted message in base64 format.

        Returns:
            str: The decrypted plaintext message.

        Raises:
            Exception: If decryption fails.
        """
        try:
            decoded = base64.b64decode(encrypted_data)
            encrypted_key, nonce, ciphertext = decoded.split(b":::")

            aes_key = self.private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            aesgcm = AESGCM(aes_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode()
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")


class MessengerClient(cmd.Cmd):
    """
    Secure messaging client with commands for user registration, message sending, 
    and viewing messages.

    Commands:
        - register <username>: Registers the user with the server.
        - send <recipient> <message>: Sends an encrypted message to the recipient.
        - messages: Displays and decrypts received messages.
        - help: Shows the help message.
        - quit: Exits the messenger.
    """
    intro = '''
    Welcome to Secure Messenger!
    Available commands:
    - help           Show this help message
    - register       Register a new user (usage: register <username>)
    - send           Send a message (usage: send <recipient> <message>)
    - messages       Check your messages
    - quit           Exit the messenger

    Start by registering with: register <your_username>
    '''
    prompt = 'messenger> '

    def __init__(self):
        """Initializes the messenger client."""
        super().__init__()
        self.crypto_manager = CryptoManager()
        self.server_url = 'http://localhost:5000'
        self.username = None
        self.token = None

    def do_register(self, arg):
        """Registers a new user: register <username>"""
        username = arg.strip()
        if not username:
            print("Please provide a username")
            print("Usage: register <username>")
            return

        try:
            public_key_pem = self.crypto_manager.generate_keypair()

            response = requests.post(
                f"{self.server_url}/register",
                json={
                    'username': username,
                    'public_key': public_key_pem.decode()
                }
            )

            data = response.json()
            if data['status'] == 'success':
                self.username = username
                self.token = data['token']
                print(f"Successfully registered as {username}")
                print("You can now send messages using: send <recipient> <message>")
            else:
                print(f"Registration failed: {data['message']}")
        except requests.exceptions.ConnectionError:
            print("Error: Could not connect to server. Make sure server.py is running.")
        except Exception as e:
            print(f"Error: {str(e)}")

    def do_send(self, arg):
        """Sends a message: send <recipient> <message>"""
        if not self.token:
            print("Please register first using: register <username>")
            return

        try:
            recipient, message = arg.split(' ', 1)
        except ValueError:
            print("Usage: send <recipient> <message>")
            return

        try:
            response = requests.get(f"{self.server_url}/get_public_key/{recipient}")
            data = response.json()

            if data['status'] != 'success':
                print(f"Error: {data['message']}")
                return

            encrypted_message = self.crypto_manager.encrypt_message(
                message, 
                data['public_key'].encode()
            )

            headers = {'Authorization': self.token}
            response = requests.post(
                f"{self.server_url}/send",
                headers=headers,
                json={
                    'recipient': recipient,
                    'message': encrypted_message.decode()
                }
            )

            data = response.json()
            if data['status'] == 'success':
                print("\nMessage sent successfully!")
            else:
                print(f"\nFailed to send message: {data['message']}")

        except requests.exceptions.ConnectionError:
            print("Error: Could not connect to server. Make sure server.py is running.")
        except Exception as e:
            print(f"Error: {str(e)}")

    def do_messages(self, arg):
        """Displays and decrypts received messages"""
        if not self.token:
            print("Please register first using: register <username>")
            return

        try:
            headers = {'Authorization': self.token}
            response = requests.get(
                f"{self.server_url}/messages/{self.username}",
                headers=headers
            )
            data = response.json()

            if data['status'] == 'success':
                messages = data['messages']
                if not messages:
                    print("No messages")
                    return

                print("\nYour messages:")
                print("=" * 70)
                for msg in messages:
                    print(f"\nFrom: {msg['sender']}")
                    print(f"Timestamp: {msg['timestamp']}")
                    print("-" * 50)
                    print("Encrypted message (base64):")
                    print(msg['message'])
                    print("-" * 50)

                    try:
                        decrypted = self.crypto_manager.decrypt_message(
                            msg['message'].encode()
                        )
                        print("Decrypted message:")
                        print(decrypted)
                    except Exception as e:
                        print(f"Error decrypting message: {str(e)}")
                    print("=" * 70)
            else:
                print(f"Failed to fetch messages: {data['message']}")
        except requests.exceptions.ConnectionError:
            print("Error: Could not connect to server. Make sure server.py is running.")
        except Exception as e:
            print(f"Error: {str(e)}")

    def do_help(self, arg):
        """Displays the help message"""
        print(self.intro)

    def do_quit(self, arg):
        """Exits the messenger"""
        print("Goodbye!")
        return True

    def default(self, line):
        """Handles unknown commands"""
        print(f"Unknown command: {line}")
        print("Type 'help' to see available commands")


if __name__ == '__main__':
    """Starts the MessengerClient command loop."""
    MessengerClient().cmdloop()