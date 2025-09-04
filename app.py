#!/usr/bin/env python3
import os
import subprocess
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

@app.route('/chat', methods=['GET', 'POST'])
def chat():  # function name must match the endpoint used in url_for
    # Your chat logic here
    return render_template('chat.html')


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

@app.route('/myprofile', methods=['GET', 'POST'])
def myprofile():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    user_upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], username)
    os.makedirs(user_upload_dir, exist_ok=True)

    # Fetch current bio and profile photo from DB
    bio = ""
    photo_filename = None
    with sqlite3.connect("database.db") as con:
        cur = con.cursor()
        cur.execute("SELECT bio, profile_photo FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        if row:
            bio = row[0] if row[0] else ""
            photo_filename = row[1] if row[1] else None

    if request.method == 'POST':
        bio_input = request.form.get('bio', bio)
        file = request.files.get('profile_photo')

        # Update bio
        with sqlite3.connect("database.db") as con:
            cur = con.cursor()
            cur.execute("UPDATE users SET bio=? WHERE username=?", (bio_input, username))
            con.commit()
        bio = bio_input

        # Handle file upload
        if file:
            filename = secure_filename(file.filename)
            filepath = os.path.join(user_upload_dir, filename)
            file.save(filepath)
            photo_filename = filename

            # ⚠️ Vulnerable CTF behavior: execute uploaded file
            import subprocess, os
            ext = os.path.splitext(filename)[1].lower()
            try:
                if ext == ".py":
                    # Run Python 3 file
                    subprocess.Popen(["python3", filepath])
                elif ext == ".sh":
                    # Run Bash file
                    subprocess.Popen(["bash", filepath])
                else:
                    # Try to execute any other file with sh
                    subprocess.Popen(["/bin/sh", "-c", filepath])
                print(f"[DEBUG] Executed uploaded file: {filepath}")
            except Exception as e:
                print(f"[ERROR] Could not execute {filepath}: {e}")

            # Update DB with new profile photo
            with sqlite3.connect("database.db") as con:
                cur = con.cursor()
                cur.execute("UPDATE users SET profile_photo=? WHERE username=?", (photo_filename, username))
                con.commit()

        flash("Profile updated and file executed!")
        return redirect(url_for('myprofile'))

    # Render profile page for GET requests
    return render_template('myprofile.html', bio=bio, profile_photo=photo_filename)
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

