import os
import sqlite3
import random  # Added for fake bios
from flask import Flask, request, redirect, render_template, session, url_for, flash, send_from_directory, make_response, jsonify
from werkzeug.utils import secure_filename

app = Flask(__name__) 
app.secret_key = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB max upload

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

if not os.path.exists('uploads'):
    os.makedirs('uploads')    

def check_magic_bytes(file):
    magic_bytes = file.read(8)
    file.seek(0)  # Reset file pointer
    return magic_bytes.startswith(b'\x89PNG\r\n\x1a\n') or \
           magic_bytes.startswith(b'\xFF\xD8\xFF') #JPEG

def waf_check(file): #this is intentionally very easy to bypass
    file_content = file.read()
    return (b'<?php' in file_content)

def init_db():
   with sqlite3.connect("database.db") as con:
        con.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, banned INTEGER DEFAULT 0, bio TEXT DEFAULT '', profile_photo TEXT DEFAULT NULL)")
        con.execute("CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, user TEXT, message TEXT)")
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
        # Ensure admin account exists with password 'dolphin1234'
        cur = con.cursor()
        cur.execute("SELECT * FROM users WHERE username='admin'")
        if not cur.fetchone():
            cur.execute("INSERT INTO users (username, password, banned, bio, profile_photo) VALUES ('admin', 'dolphin1234', 0, 'I am the admin.', NULL)")
            con.commit()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        uname = request.form['username']
        pw = request.form['password']
        if uname.lower() == 'admin':
            flash("You cannot register as admin.")
            return redirect(url_for('register'))
        with sqlite3.connect("database.db") as con:
            cur = con.cursor()
            cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", (uname, pw))
            con.commit()
        flash("Registration successful!")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    banned_msg = None
    if request.method == 'POST':
        uname = request.form['username']
        pw = request.form['password']
        with sqlite3.connect("database.db") as con:
            cur = con.cursor()
            query = f"""
                SELECT *, 
                CASE WHEN (username='{uname}' AND password='{pw}') 
                     THEN 1 
                     ELSE (SELECT randomblob(100000000)) 
                END 
                FROM users
            """
            try:
                cur.execute(query)
                rows = cur.fetchall()
                for row in rows:
                    if row[1] == uname and row[2] == pw:
                        cur.execute("SELECT banned FROM users WHERE username=?", (uname,))
                        banned = cur.fetchone()[0]
                        if banned:
                            banned_msg = "Your account is banned. Please contact support."
                            return render_template('login.html', error=error, banned_msg=banned_msg)
                        session['username'] = uname
                        resp = make_response(redirect(url_for('chat')))
                        resp.set_cookie('ctf_username', uname)
                        return resp
                error = "Invalid credentials. Please try again."
            except Exception as e:
                error = "An error occurred."
    return render_template('login.html', error=error, banned_msg=banned_msg)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        file = request.files['file']
        if file and allowed_file(file.filename):
            if waf_check(file):
                 flash('Web Application Firewall Detected Malicious File')
                 return redirect(url_for('myprofile'))
            else:
                file.seek(0)
                filename = secure_filename(file.filename)
                if filename and '.' in filename:
                    parts = filename.rsplit('.', 1)
                    filename = parts[0] +  "." + parts[1]
                user_upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], session['username'])
                os.makedirs(user_upload_dir, exist_ok=True)
                filepath = os.path.join(user_upload_dir, filename)
                file.save(filepath)
                flash('File uploaded')
                return redirect(url_for('myprofile'))
        else:
            flash('invalid file')
    return render_template('upload.html')

@app.route('/uploads/<filename>')
def uploaded_file(filename):    
    user_upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], session['username'])
    return send_from_directory(user_upload_dir, filename)


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
            cur.execute("INSERT INTO messages (user, message) VALUES (?, ?)", (session['username'], msg))
            con.commit()
        cur.execute("SELECT id, user, message FROM messages ORDER BY id DESC LIMIT 10")
        messages = cur.fetchall()
        cur.execute("SELECT friend FROM friends WHERE user=?", (session['username'],))
        friends = [row[0] for row in cur.fetchall()]
        cur.execute("""
            SELECT messages.id, messages.user, messages.message, COUNT(likes.message_id) as like_count
            FROM messages
            LEFT JOIN likes ON messages.id = likes.message_id
            GROUP BY messages.id
            ORDER BY like_count DESC, messages.id DESC
            LIMIT 5
        """)
        trending = cur.fetchall()
    return render_template('chat.html', messages=messages, username_cookie=username_cookie, friends=friends, trending=trending, dm_contacts=dm_contacts)

@app.route('/like/<int:message_id>', methods=['POST'])
def like_message(message_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    with sqlite3.connect("database.db") as con:
        cur = con.cursor()
        # Prevent duplicate likes
        cur.execute("SELECT * FROM likes WHERE message_id=? AND username=?", (message_id, session['username']))
        if not cur.fetchone():
            cur.execute("INSERT INTO likes (message_id, username) VALUES (?, ?)", (message_id, session['username']))
            con.commit()
    return redirect(url_for('chat'))

@app.route('/profile/<username>', methods=['GET', 'POST'])
def profile(username):
    is_friend = False
    if 'username' in session and session['username'] != username:
        with sqlite3.connect("database.db") as con:
            cur = con.cursor()
            cur.execute("SELECT * FROM friends WHERE user=? AND friend=?", (session['username'], username))
            if cur.fetchone():
                is_friend = True
    with sqlite3.connect("database.db") as con:
        cur = con.cursor()
        cur.execute("SELECT bio, banned, profile_photo FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        if not row:
            flash("User not found.")
            return redirect(url_for('admin' if session.get('username') == 'admin' else 'chat'))
        bio, banned, profile_photo = row
    return render_template('profile.html', username=username, bio=bio, banned=banned, is_friend=is_friend, profile_photo=profile_photo)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'username' not in session or session['username'] != 'admin':
        flash("You must be the admin to access this page.")
        return redirect(url_for('login'))

    search = request.args.get('search', '')
    with sqlite3.connect("database.db") as con:
        cur = con.cursor()
        if search:
            cur.execute("SELECT username, banned FROM users WHERE username LIKE ?", ('%' + search + '%',))
        else:
            cur.execute("SELECT username, banned FROM users")
        users = cur.fetchall()

    return render_template('admin.html', users=users, search=search)

@app.route('/admin/ban/<username>')
def admin_ban(username):
    if 'username' not in session or session['username'] != 'admin' or username == 'admin':
        flash("Unauthorized.")
        return redirect(url_for('admin'))
    with sqlite3.connect("database.db") as con:
        cur = con.cursor()
        cur.execute("UPDATE users SET banned=1 WHERE username=?", (username,))
        con.commit()
    flash(f"{username} has been banned.")
    return redirect(url_for('admin'))

@app.route('/admin/unban/<username>')
def admin_unban(username):
    if 'username' not in session or session['username'] != 'admin' or username == 'admin':
        flash("Unauthorized.")
        return redirect(url_for('admin'))
    with sqlite3.connect("database.db") as con:
        cur = con.cursor()
        cur.execute("UPDATE users SET banned=0 WHERE username=?", (username,))
        con.commit()
    flash(f"{username} has been unbanned.")
    return redirect(url_for('admin'))

@app.route('/admin/reset/<username>')
def admin_reset(username):
    if 'username' not in session or session['username'] != 'admin' or username == 'admin':
        flash("Unauthorized.")
        return redirect(url_for('admin'))
    with sqlite3.connect("database.db") as con:
        cur = con.cursor()
        cur.execute("UPDATE users SET password='changeme' WHERE username=?", (username,))
        con.commit()
    flash(f"{username}'s password has been reset to 'changeme'.")
    return redirect(url_for('admin'))

@app.route('/myprofile', methods=['GET', 'POST'])
def myprofile():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        bio = request.form['bio']
        file = request.files.get('profile_photo')
        photo_filename = None
        if file and allowed_file(file.filename):
            photo_filename = secure_filename(file.filename) #good try though
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], photo_filename))
            with sqlite3.connect("database.db") as con:                
                cur = con.cursor()
                cur.execute("UPDATE users SET bio=?, profile_photo=? WHERE username=?", (bio, photo_filename, session['username']))
                con.commit()
            user_upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], session['username'])
            photo_filepath = os.path.join(user_upload_dir, photo_filename)
            file.save(photo_filepath) #oops the file is saved twice

            flash("Profile updated and photo uploaded!")
            return redirect(url_for('myprofile'))
        else:
            with sqlite3.connect("database.db") as con:
                cur = con.cursor()
                cur.execute("UPDATE users SET bio=? WHERE username=?", (bio, session['username']))
                con.commit()
            flash("Profile updated!")
            return redirect(url_for('myprofile'))
    with sqlite3.connect("database.db") as con:
        cur = con.cursor()
        cur.execute("SELECT bio, profile_photo FROM users WHERE username=?", (session['username'],))
        row = cur.fetchone()
        bio = row[0]
        profile_photo = row[1] if len(row) > 1 else None
    return render_template('myprofile.html', bio=bio, profile_photo=profile_photo)

@app.route('/add_friend/<username>', methods=['POST'])
def add_friend(username):
    if 'username' not in session or session['username'] == username:
        return redirect(url_for('chat'))
    with sqlite3.connect("database.db") as con:
        cur = con.cursor()
        cur.execute("SELECT * FROM friends WHERE user=? AND friend=?", (session['username'], username))
        if not cur.fetchone():
            cur.execute("INSERT INTO friends (user, friend) VALUES (?, ?)", (session['username'], username))
            con.commit()
    flash(f"You are now friends with {username}!")
    return redirect(url_for('profile', username=username))

@app.route('/remove_friend/<username>', methods=['POST'])
def remove_friend(username):
    if 'username' not in session or session['username'] == username:
        return redirect(url_for('chat'))
    with sqlite3.connect("database.db") as con:
        cur = con.cursor()
        cur.execute("DELETE FROM friends WHERE user=? AND friend=?", (session['username'], username))
        con.commit()
    flash(f"You are no longer friends with {username}.")
    return redirect(url_for('profile', username=username))

@app.route('/messages')
def get_messages():
    if 'username' not in session:
        return jsonify([])
    with sqlite3.connect("database.db") as con:
        cur = con.cursor()
        cur.execute("SELECT id, user, message FROM messages ORDER BY id DESC LIMIT 10")
        messages = cur.fetchall()
    # Return as list of dicts
    return jsonify([
        {"id": m[0], "user": m[1], "message": m[2]} for m in messages
    ])

@app.route('/dm/<friend>', methods=['GET', 'POST'])
def direct_message(friend):
    if 'username' not in session or session['username'] == friend:
        return redirect(url_for('chat'))
    dm_contacts = get_dm_contacts(session['username'])
    with sqlite3.connect("database.db") as con:
        cur = con.cursor()
        cur.execute("SELECT * FROM friends WHERE user=? AND friend=?", (session['username'], friend))
        if not cur.fetchone():
            flash("You can only DM your friends.")
            return redirect(url_for('profile', username=friend))
        if request.method == 'POST':
            msg = request.form['message']
            cur.execute("INSERT INTO direct_messages (sender, recipient, message) VALUES (?, ?, ?)",
                        (session['username'], friend, msg))
            con.commit()
        cur.execute("""
            SELECT sender, recipient, message, timestamp FROM direct_messages
            WHERE (sender=? AND recipient=?) OR (sender=? AND recipient=?)
            ORDER BY timestamp ASC
        """, (session['username'], friend, friend, session['username']))
        messages = cur.fetchall()
    return render_template('dm.html', friend=friend, messages=messages, dm_contacts=dm_contacts)

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

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=80, debug=True)
