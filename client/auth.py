"""
Authentication Module

This module handles user authentication and identity verification 
using JWT (JSON Web Tokens). It provides functionality to generate 
and verify tokens and register users with a remote server.

Environment variables:
    - SECRET_KEY: A secret key used for JWT encoding/decoding.
"""

import requests
import jwt
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv

# Load environment variables from a .env file
load_dotenv()

class AuthManager:
    """
    Manages authentication tasks including token generation, 
    token verification, and user registration.
    
    Attributes:
        server_url (str): The base URL of the authentication server.
        jwt_secret (bytes): The secret key used for JWT operations.
    """
    def __init__(self, server_url):
        """
        Initializes the AuthManager with the server URL and loads the JWT secret key.

        Args:
            server_url (str): The base URL of the authentication server.
        """
        self.server_url = server_url
        # Retrieve the secret key from the environment or use a default fallback
        self.jwt_secret = os.getenv('SECRET_KEY', 'Zaid@@##123').encode()

    def generate_token(self, username, public_key_pem):
        """
        Generates a JWT for the given username and public key.

        Args:
            username (str): The username of the user.
            public_key_pem (bytes): The public key in PEM format.

        Returns:
            str: The encoded JWT token.
        """
        payload = {
            'username': username,
            'public_key': public_key_pem.decode(),
            'exp': datetime.utcnow() + timedelta(days=1)  # Token expiration time
        }
        # Encode the payload into a JWT token
        return jwt.encode(payload, self.jwt_secret, algorithm='HS256')

    def verify_token(self, token):
        """
        Verifies the validity of a given JWT token.

        Args:
            token (str): The JWT token to verify.

        Returns:
            dict: The decoded payload if the token is valid.
            None: If the token is invalid or expired.
        """
        try:
            return jwt.decode(token, self.jwt_secret, algorithms=['HS256'])
        except jwt.InvalidTokenError:
            # Return None if token validation fails
            return None

    def register_user(self, username, public_key_pem):
        """
        Registers a new user with the authentication server.

        Args:
            username (str): The username of the new user.
            public_key_pem (bytes): The public key in PEM format.

        Returns:
            dict: The JSON response from the server.
        """
        response = requests.post(
            f"{self.server_url}/register", 
            json={
                'username': username, 
                'public_key': public_key_pem.decode()
            }
        )
        # Parse and return the server's JSON response
        return response.json()



""" authentication - for random key generation """

# class AuthManager:
#     def __init__(self, server_url):
#         self.server_url = server_url
#         self.jwt_secret = os.urandom(32)  # you can use persistent secret
        
#     def generate_token(self, username, public_key_pem):
#         payload = {
#             'username': username,
#             'public_key': public_key_pem.decode(),
#             'exp': datetime.utcnow() + timedelta(days=1)
#         }
#         return jwt.encode(payload, self.jwt_secret, algorithm='HS256')
    
#     def verify_token(self, token):
#         try:
#             return jwt.decode(token, self.jwt_secret, algorithms=['HS256'])
#         except jwt.InvalidTokenError:
#             return None
    
#     def register_user(self, username, public_key_pem):
#         response = requests.post(f"{self.server_url}/register", 
#                                json={'username': username, 
#                                     'public_key': public_key_pem.decode()})
#         return response.json()


""" Authentication (Handles authentication and identity verification) for secrect_persistant key """

import requests
import jwt
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class AuthManager:
    def __init__(self, server_url):
        self.server_url = server_url
        # Get secret key from environment variable, fallback to a random key if not found
        self.jwt_secret = os.getenv('SECRET_KEY', 'Zaid@@##123').encode()
        
    def generate_token(self, username, public_key_pem):
        payload = {
            'username': username,
            'public_key': public_key_pem.decode(),
            'exp': datetime.utcnow() + timedelta(days=1)
        }
        return jwt.encode(payload, self.jwt_secret, algorithm='HS256')
    
    def verify_token(self, token):
        try:
            return jwt.decode(token, self.jwt_secret, algorithms=['HS256'])
        except jwt.InvalidTokenError:
            return None
    
    def register_user(self, username, public_key_pem):
        response = requests.post(f"{self.server_url}/register", 
                               json={'username': username, 
                                    'public_key': public_key_pem.decode()})
        return response.json()

