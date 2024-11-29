""" authentication - for random key generation """
# import requests
# import jwt
# from datetime import datetime, timedelta
# import os

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