import os
import sqlite3
import bcrypt
import pyotp
import qrcode
import io
from base64 import b64encode
from flask import Flask, render_template, request, redirect, url_for, session, flash
from database import init_db, get_db_connection

app = Flask(__name__)
# In production, use a strong random secret key.
app.secret_key = os.urandom(24)

# Initialize the database
init_db()

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            flash('Username and password are required', 'error')
            return redirect(url_for('register'))

        # Lowering work factor to 10 for faster hashing (default is 12)
        hashed_bytes = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=10))
        password_hash = hashed_bytes.decode('utf-8')

        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', 
                         (username, password_hash))
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists', 'error')
            return redirect(url_for('register'))
        finally:
            conn.close()

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            session['pending_user_id'] = user['id']
            if user['totp_secret']:
                return redirect(url_for('verify_2fa'))
            else:
                session['user_id'] = user['id']
                session['username'] = user['username']
                session.pop('pending_user_id', None)
                return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html')

@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'pending_user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        token = request.form.get('token')
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['pending_user_id'],)).fetchone()
        conn.close()

        totp = pyotp.TOTP(user['totp_secret'])
        if totp.verify(token):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session.pop('pending_user_id', None)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid 2FA token', 'error')

    return render_template('verify_2fa.html')

@app.route('/setup_2fa', methods=['GET', 'POST'])
def setup_2fa():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    if user['totp_secret']:
        conn.close()
        flash('2FA is already set up!', 'success')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        secret = request.form.get('secret')
        token = request.form.get('token')
        
        totp = pyotp.TOTP(secret)
        if totp.verify(token):
            conn.execute('UPDATE users SET totp_secret = ? WHERE id = ?', (secret, session['user_id']))
            conn.commit()
            conn.close()
            flash('2FA has been successfully enabled!', 'success')
            return redirect(url_for('dashboard'))
        else:
            conn.close()
            flash('Invalid token, please try again.', 'error')

    # Generate new secret for GET request or failed POST
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    totp_uri = totp.provisioning_uri(name=user['username'], issuer_name="SecureGate")
    
    # Generate QR Code
    qr = qrcode.make(totp_uri)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    qr_b64 = b64encode(buf.getvalue()).decode('utf-8')
    
    return render_template('setup_2fa.html', secret=secret, qr_b64=qr_b64)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    
    return render_template('dashboard.html', user=user)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    from waitress import serve
    serve(app, host='127.0.0.1', port=5000)
