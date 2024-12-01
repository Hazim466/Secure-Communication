# Secure Communication CLI Application

## Secure Communication Project Command Line Communication Tool

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

A secure command-line interface application that enables end-to-end encrypted communication between two parties without prior key exchange. Built with Python, implementing RSA and AES encryption standards.

## 📁 Project Structure




<!-- # Secure Communication CLI Application

## Secure Communication Project Command Line Communication Tool

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

A secure command-line interface application that enables end-to-end encrypted communication between two parties without prior key exchange. Built with Python, implementing RSA and AES encryption standards.

## 📁 Project Structure

```
Secure Communication Project/
├── server/
│   ├── server.py       # serverside
│   ├── crypto.py       # Encryption/decryption operations
├── client/
│   ├── client.py # Client Registration & Messages
│   └── auth.py   # User authentication
├── .env.example                # Example environment variables
├── requirements.txt            # Project dependencies
└── README.md                   # This file
```

## 🚀 Features

- **Secure Key Management**
  - RSA-2048 key pair generation
  - Secure key storage
  - Automatic key exchange

- **Message Security**
  - AES-256 message encryption
  - End-to-end encryption
  - Message integrity verification

- **User Authentication**
  - Secure user registration
  - Session management
  - Two-factor authentication support

## 🛠️ Installation

1. Clone the repository:
```bash
git clone 
cd Secure-Communication
```

2. Create and activate virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
```bash
cp .env
# Edit .env with your configurations
```

## 📝 Configuration

Create a `.env` file with the following variables:
```env
SECRET_KEY=your_secret_key
STORAGE_PATH=/path/to/storage
DEBUG_MODE=False
```

## 💻 Usage

1. Start the application:

- 1.1. Run server.py
```bash
python server/server.py
```
- 1.2. Run client.py
```bash
python client/client.py
```
- - Note: You have to run server.py onces. Client.py for twice for two user (like: john, alice) for registration and sending & reading message.

2. Register your users:
- 2.1. # client.py 1
```bash
messenger> register "John"
```
- 2.2. # client.py 2
```bash
messenger> register "John"
```

3. Send a message:
```bash
messenger> send "John" message "Hello Alice, I am John!"
```

4. Read messages:
```bash
messenger> message
```

## 🔐 Security Features

### Key Management
- RSA-2048 for asymmetric encryption
- Secure key storage using environment variables
- Regular key rotation support

### Message Security
- AES-256 for symmetric message encryption
- SHA-256 for message integrity
- Perfect forward secrecy

### Authentication
- Secure password hashing
- Session management
- Rate limiting


## 📦 Dependencies

- Flask
- flask-sqlalchemy
- flask-mail
- cryptography
- pyjwt
- werkzeug
- python-dotenv

## 🤝 Contributing

1. Fork the repository
2. Create your branch:

```bash
git checkout -b "branch"
```
3. Commit your changes:
```bash
git commit -m "your commit message"
```
4. Push to the branch:
```bash
git push origin "branch"
```
5. Open a Pull Request


## ⚠️ Security Considerations

- Keep your private key secure
- Don't share sensitive information in debug logs
- Regularly update dependencies
- Use strong passwords
- Enable two-factor authentication when possible

## 👥 Authors

- @Hazim466

## 🙏 Acknowledgments

- Cryptography library developers
- Security researchers and testers
- Open source community -->