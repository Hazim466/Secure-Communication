# server.py
from flask import Flask, request, jsonify
import sqlite3
import jwt
import os
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

def init_db():
    try:
        conn = sqlite3.connect('messenger.db')
        c = conn.cursor()
        
        # Create users table if not exists
        c.execute('''CREATE TABLE IF NOT EXISTS users
                     (username TEXT PRIMARY KEY,
                      public_key TEXT NOT NULL)''')
        
        # Create messages table if not exists
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

#register user
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    conn = sqlite3.connect('messenger.db')
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (username, public_key) VALUES (?, ?)', 
                 (data['username'], data['public_key']))
        conn.commit()
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

# Getting Keys
@app.route('/get_public_key/<username>', methods=['GET'])
def get_public_key(username):
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

# Route For Send message
@app.route('/send', methods=['POST'])
def send_message():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'status': 'error', 'message': 'No token provided'})
    
    try:
        user_data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except:
        return jsonify({'status': 'error', 'message': 'Invalid token'})
    
    data = request.json
    conn = sqlite3.connect('messenger.db')
    c = conn.cursor()
    try:
        # Verify recipient exists
        c.execute('SELECT username FROM users WHERE username = ?', (data['recipient'],))
        if not c.fetchone():
            return jsonify({'status': 'error', 'message': 'Recipient not found'})
        
        c.execute('INSERT INTO messages (sender, recipient, message) VALUES (?, ?, ?)',
                 (user_data['username'], data['recipient'], data['message']))
        conn.commit()
        return jsonify({'status': 'success'})
    finally:
        conn.close()

# Route For Showing Messages
@app.route('/messages/<username>', methods=['GET'])
def get_messages(username):
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'status': 'error', 'message': 'No token provided'})
    
    try:
        user_data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        if user_data['username'] != username:
            return jsonify({'status': 'error', 'message': 'Unauthorized'})
    except:
        return jsonify({'status': 'error', 'message': 'Invalid token'})
    
    conn = sqlite3.connect('messenger.db')
    c = conn.cursor()
    try:
        c.execute('''SELECT sender, message, timestamp FROM messages 
                     WHERE recipient = ? ORDER BY timestamp DESC LIMIT 50''', 
                 (username,))
        messages = [{'sender': m[0], 'message': m[1], 'timestamp': m[2]} 
                   for m in c.fetchall()]
        return jsonify({'status': 'success', 'messages': messages})
    finally:
        conn.close()


# main code
if __name__ == '__main__':
    # Initialize database before starting the server
    init_db()
    print("\nServer starting...")
    print("Server is running on http://localhost:5000")
    app.run(debug=True)