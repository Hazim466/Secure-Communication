

from flask import Flask, request, jsonify
import sqlite3
import jwt
import os
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Generate a random secret key for JWT signing

# Database Initialization
def init_db():
    """
    Initialize the SQLite database.
    Creates the `users` and `messages` tables if they do not already exist.
    - `users` table stores usernames and their associated public keys.
    - `messages` table stores encrypted messages between users.
    """
    try:
        conn = sqlite3.connect('messenger.db')
        c = conn.cursor()
        
        # Create tables if not exists
        c.execute('''CREATE TABLE IF NOT EXISTS users
                     (username TEXT PRIMARY KEY,
                      public_key TEXT NOT NULL)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS messages
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      sender TEXT NOT NULL,
                      recipient TEXT NOT NULL,
                      message TEXT NOT NULL,
                      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        
        conn.commit()
        conn.close()
        print("Database initialized successfully!")
    except Exception as e:
        print(f"Error initializing database: {e}")

# Route for User Registration
@app.route('/register', methods=['POST'])
def register():
    """
    Register a new user by storing their username and public key in the database.
    Generates a JWT token for the user upon successful registration.
    Returns:
    - Success: JSON response with a JWT token.
    - Failure: Error message if username already exists or other issues occur.
    """
    data = request.json
    conn = sqlite3.connect('messenger.db')
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (username, public_key) VALUES (?, ?)', 
                 (data['username'], data['public_key']))
        conn.commit()
        
        # Create a JWT token valid for 1 day
        token = jwt.encode(
            {'username': data['username'], 'exp': datetime.utcnow() + timedelta(days=1)},
            app.config['SECRET_KEY'],
            algorithm='HS256'
        )
        return jsonify({'status': 'success', 'token': token})
    except sqlite3.IntegrityError:
        return jsonify({'status': 'error', 'message': 'Username already exists'})
    finally:
        conn.close()

# Route for Retrieving Public Keys
@app.route('/get_public_key/<username>', methods=['GET'])
def get_public_key(username):
    """
    Fetch the public key of a specific user.
    Parameters:
    - username: The username whose public key is being requested.
    Returns:
    - Success: Public key of the requested user.
    - Failure: Error message if the user is not found.
    """
    conn = sqlite3.connect('messenger.db')
    c = conn.cursor()
    try:
        c.execute('SELECT public_key FROM users WHERE username = ?', (username,))
        result = c.fetchone()
        if result:
            return jsonify({'status': 'success', 'public_key': result[0]})
        return jsonify({'status': 'error', 'message': 'User not found'})
    finally:
        conn.close()

# Route for Sending Messages
@app.route('/send', methods=['POST'])
def send_message():
    """
    Send a message to a recipient.
    Verifies the sender's JWT token and ensures the recipient exists before storing the message.
    Parameters:
    - token (header): JWT token for authentication.
    - recipient: The username of the recipient.
    - message: Encrypted message content.
    Returns:
    - Success: Message delivery confirmation.
    - Failure: Error messages for invalid token or non-existent recipient.
    """
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'status': 'error', 'message': 'No token provided'})
    
    try:
        user_data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return jsonify({'status': 'error', 'message': 'Token has expired'})
    except jwt.InvalidTokenError:
        return jsonify({'status': 'error', 'message': 'Invalid token'})
    
    data = request.json
    conn = sqlite3.connect('messenger.db')
    c = conn.cursor()
    try:
        # Verify recipient exists
        c.execute('SELECT username FROM users WHERE username = ?', (data['recipient'],))
        if not c.fetchone():
            return jsonify({'status': 'error', 'message': 'Recipient not found'})
        
        # Insert message into database
        c.execute('INSERT INTO messages (sender, recipient, message) VALUES (?, ?, ?)',
                 (user_data['username'], data['recipient'], data['message']))
        conn.commit()
        return jsonify({'status': 'success'})
    finally:
        conn.close()

# Route for Viewing Messages
@app.route('/messages/<username>', methods=['GET'])
def get_messages(username):
    """
    Retrieve messages sent to a specific user.
    Verifies the user's JWT token before returning up to 50 most recent messages.
    Parameters:
    - token (header): JWT token for authentication.
    - username: The username whose messages are being retrieved.
    Returns:
    - Success: A list of messages (sender, encrypted message, timestamp).
    - Failure: Error messages for unauthorized access or invalid token.
    """
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'status': 'error', 'message': 'No token provided'})
    
    try:
        user_data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        if user_data['username'] != username:
            return jsonify({'status': 'error', 'message': 'Unauthorized'})
    except jwt.ExpiredSignatureError:
        return jsonify({'status': 'error', 'message': 'Token has expired'})
    except jwt.InvalidTokenError:
        return jsonify({'status': 'error', 'message': 'Invalid token'})
    
    conn = sqlite3.connect('messenger.db')
    c = conn.cursor()
    try:
        # Fetch messages for the recipient
        c.execute('''SELECT sender, message, timestamp FROM messages 
                     WHERE recipient = ? ORDER BY timestamp DESC LIMIT 50''', 
                 (username,))
        messages = [{'sender': m[0], 'message': m[1], 'timestamp': m[2]} 
                   for m in c.fetchall()]
        return jsonify({'status': 'success', 'messages': messages})
    finally:
        conn.close()

# Main Execution
if __name__ == '__main__':
    """
    Entry point for the Flask server.
    Initializes the database and starts the server on localhost:5000.
    """
    init_db()
    print("\nServer starting...")
    print("Server is running on http://localhost:5000")
    app.run(debug=True)