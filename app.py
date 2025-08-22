#!/usr/bin/env python3
import os
import sqlite3
from flask import Flask, request, redirect, render_template, session, url_for, flash, send_from_directory, make_response, jsonify
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'uploads'

if not os.path.exists('uploads'):
    os.makedirs('uploads')

# --------------------
# Database initialization
# --------------------
def init_db():
    with sqlite3.connect("database.db") as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT,
                password TEXT,
                banned INTEGER DEFAULT 0,
                bio TEXT DEFAULT '',
                profile_photo TEXT DEFAULT NULL
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY,
                user TEXT,
                message TEXT
            )
        """)
        con.execute("CREATE TABLE IF NOT EXISTS friends (user TEXT, friend TEXT)")
        con.execute("CREATE TABLE IF NOT EXISTS likes (message_id INTEGER, username TEXT)")
        con.execute("""
            CREATE TABLE IF NOT EXISTS direct_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT,
                recipient TEXT,
                message TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Ensure admin exists
        cur = con.cursor()
        cur.execute("SELECT * FROM users WHERE username='admin'")
        if not cur.fetchone():
            cur.execute("INSERT INTO users (username, password, banned, bio) VALUES ('admin','dolphin1234',0,'I am the admin.')")
            con.commit()

# --------------------
# Helper functions
# --------------------
def get_dm_contacts(username):
    with sqlite3.connect("database.db") as con:
        cur = con.cursor()
        cur.execute("""
            SELECT DISTINCT
                CASE
                    WHEN sender=? THEN recipient
                    WHEN recipient=? THEN sender
                END as contact
            FROM direct_messages
            WHERE sender=? OR recipient=?
        """, (username, username, username, username))
        contacts = [row[0] for row in cur.fetchall() if row[0] != username]
    return contacts

# --------------------
# Routes
# --------------------
@app.route('/')
def index():
    return redirect(url_for('login'))

# --- Register ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        uname = request.form['username']
        pw = request.form['password']
        if uname.lower() == 'admin':
            flash("Cannot register as admin.")
            return redirect(url_for('register'))
        with sqlite3.connect("database.db") as con:
            cur = con.cursor()
            cur.execute("INSERT INTO users (username, password) VALUES (?,?)", (uname, pw))
            con.commit()
        flash("Registration successful!")
        return redirect(url_for('login'))
    return render_template('register.html')

# --- Login ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    banned_msg = None
    if request.method == 'POST':
        uname = request.form['username']
        pw = request.form['password']
        with sqlite3.connect("database.db") as con:
            cur = con.cursor()
            cur.execute("SELECT username,password,banned FROM users WHERE username=? AND password=?", (uname, pw))
            row = cur.fetchone()
            if row:
                if row[2]:
                    banned_msg = "Your account is banned."
                    return render_template('login.html', error=error, banned_msg=banned_msg)
                session['username'] = uname
                resp = make_response(redirect(url_for('chat')))
                resp.set_cookie('ctf_username', uname)
                return resp
            error = "Invalid credentials."
    return render_template('login.html', error=error, banned_msg=banned_msg)

# --- Logout ---
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

# --- Vulnerable File Upload ---
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        file = request.files['file']
        if file:
            # Weak WAF only blocks <?php
            file_content = file.read()
            file.seek(0)
            if b'<?php' in file_content:
                flash('Malicious file detected.')
                return redirect(url_for('myprofile'))

            # Save file directly, no restrictions
            user_upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], session['username'])
            os.makedirs(user_upload_dir, exist_ok=True)
            filename = secure_filename(file.filename)
            filepath = os.path.join(user_upload_dir, filename)
            file.save(filepath)
            flash('File uploaded successfully!')
            return redirect(url_for('myprofile'))
        else:
            flash('No file selected.')
    return render_template('upload.html')

@app.route('/uploads/<username>/<filename>')
def uploaded_file(username, filename):
    user_upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], username)
    return send_from_directory(user_upload_dir, filename)

# --- My Profile ---
# --------------------
# My Profile (Vulnerable)
# --------------------
@app.route('/myprofile', methods=['GET', 'POST'])
def myprofile():
    if 'username' not in session:
        return redirect(url_for('login'))

    # Ensure the user's upload directory exists
    user_upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], session['username'])
    os.makedirs(user_upload_dir, exist_ok=True)

    if request.method == 'POST':
        bio = request.form['bio']
        file = request.files.get('profile_photo')
        profile_photo = None

        if file:
            # Weak WAF: only blocks '<?php'
            file_content = file.read()
            file.seek(0)
            if b'<?php' in file_content:
                flash('Malicious file detected.')
                return redirect(url_for('myprofile'))

            # Save file directly (vulnerable)
            profile_photo = secure_filename(file.filename)
            photo_filepath = os.path.join(user_upload_dir, profile_photo)
            file.save(photo_filepath)

        # Update database
        with sqlite3.connect("database.db") as con:
            cur = con.cursor()
            if profile_photo:
                cur.execute("UPDATE users SET bio=?, profile_photo=? WHERE username=?",
                            (bio, profile_photo, session['username']))
            else:
                cur.execute("UPDATE users SET bio=? WHERE username=?",
                            (bio, session['username']))
            con.commit()

        flash("Profile updated!")
        return redirect(url_for('myprofile'))

    # Fetch current bio and profile photo from database
    with sqlite3.connect("database.db") as con:
        cur = con.cursor()
        cur.execute("SELECT bio, profile_photo FROM users WHERE username=?", (session['username'],))
        row = cur.fetchone()
        bio = row[0]
        profile_photo = row[1] if len(row) > 1 else None

    return render_template('myprofile.html', bio=bio, profile_photo=profile_photo)

# --- Chat ---
@app.route('/chat', methods=['GET', 'POST'])
def chat():
    if 'username' not in session:
        return redirect(url_for('login'))
    username_cookie = request.cookies.get('ctf_username')
    dm_contacts = get_dm_contacts(session['username'])
    with sqlite3.connect("database.db") as con:
        cur = con.cursor()
        if request.method == 'POST':
            msg = request.form['message']
            cur.execute("INSERT INTO messages (user,message) VALUES (?,?)", (session['username'], msg))
            con.commit()
        cur.execute("SELECT id,user,message FROM messages ORDER BY id DESC LIMIT 10")
        messages = cur.fetchall()
        cur.execute("SELECT friend FROM friends WHERE user=?", (session['username'],))
        friends = [row[0] for row in cur.fetchall()]
    return render_template('chat.html', messages=messages, username_cookie=username_cookie, friends=friends, dm_contacts=dm_contacts)

# --- Admin panel ---
@app.route('/admin')
def admin():
    if 'username' not in session or session['username'] != 'admin':
        flash("You must be admin.")
        return redirect(url_for('login'))
    search = request.args.get('search','')
    with sqlite3.connect("database.db") as con:
        cur = con.cursor()
        if search:
            cur.execute("SELECT username,banned FROM users WHERE username LIKE ?", ('%' + search + '%',))
        else:
            cur.execute("SELECT username,banned FROM users")
        users = cur.fetchall()
    return render_template('admin.html', users=users, search=search)

# --- Admin actions ---
@app.route('/admin/ban/<username>')
def admin_ban(username):
    if 'username' not in session or session['username'] != 'admin' or username=='admin':
        flash("Unauthorized.")
        return redirect(url_for('admin'))
    with sqlite3.connect("database.db") as con:
        cur = con.cursor()
        cur.execute("UPDATE users SET banned=1 WHERE username=?", (username,))
        con.commit()
    flash(f"{username} banned.")
    return redirect(url_for('admin'))

@app.route('/admin/unban/<username>')
def admin_unban(username):
    if 'username' not in session or session['username'] != 'admin' or username=='admin':
        flash("Unauthorized.")
        return redirect(url_for('admin'))
    with sqlite3.connect("database.db") as con:
        cur = con.cursor()
        cur.execute("UPDATE users SET banned=0 WHERE username=?", (username,))
        con.commit()
    flash(f"{username} unbanned.")
    return redirect(url_for('admin'))

@app.route('/admin/reset/<username>')
def admin_reset(username):
    if 'username' not in session or session['username'] != 'admin' or username=='admin':
        flash("Unauthorized.")
        return redirect(url_for('admin'))
    with sqlite3.connect("database.db") as con:
        cur = con.cursor()
        cur.execute("UPDATE users SET password='changeme' WHERE username=?", (username,))
        con.commit()
    flash(f"{username}'s password reset to 'changeme'.")
    return redirect(url_for('admin'))

# --------------------
# Main
# --------------------
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=80, debug=True)

