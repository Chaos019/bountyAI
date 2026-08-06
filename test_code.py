# Example vulnerable Flask application for testing
from flask import Flask, request, jsonify, session
import sqlite3
import json

app = Flask(__name__)
app.secret_key = "dev-secret-key-12345"

@app.route('/api/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    
    # SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(query)
    user = cursor.fetchone()
    
    if user:
        session['user_id'] = user[0]
        return jsonify({"status": "success", "token": user[3]})
    return jsonify({"error": "Invalid credentials"})

@app.route('/api/profile')
def profile():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    # XSS vulnerability - reflected input in HTML
    name = request.args.get('name', '')
    return f"<h1>Welcome {name}</h1>"

@app.route('/api/admin/users', methods=['GET'])
def admin_users():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    # IDOR vulnerability - no authorization check
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email FROM users")
    users = cursor.fetchall()
    return jsonify(users)

@app.route('/api/transfer', methods=['POST'])
def transfer():
    amount = request.json.get('amount')
    to_account = request.json.get('to_account')
    
    # No CSRF protection
    # No rate limiting
    # Race condition possible
    
    return jsonify({"status": "Transferred", "amount": amount})

@app.route('/api/upload', methods=['POST'])
def upload():
    file = request.files['file']
    filename = file.filename
    
    # Path traversal vulnerability
    file.save(f"/var/uploads/{filename}")
    
    return jsonify({"status": "Uploaded"})

if __name__ == '__main__':
    app.run(debug=True)