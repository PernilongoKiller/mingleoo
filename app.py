from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import random

app = Flask(__name__)
app.secret_key = "uma_senha_super_secreta_qualquer"

def db():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    conn = db()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        account_id INTEGER UNIQUE NOT NULL,
        name TEXT NOT NULL,
        bio TEXT,
        FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS tags (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS user_tags (
        user_id INTEGER,
        tag_id INTEGER,
        PRIMARY KEY (user_id, tag_id),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS mingles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        from_user INTEGER,
        to_user INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (from_user) REFERENCES users(id),
        FOREIGN KEY (to_user) REFERENCES users(id)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS user_links (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        platform TEXT,
        url TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS user_sections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        title TEXT,
        content TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    conn.commit()
    conn.close()

def current_user_id():
    if "account_id" not in session:
        return None
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE account_id = ?", (session["account_id"],))
    row = cur.fetchone()
    conn.close()
    return row["id"] if row else None

@app.route("/")
def index():
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT id, name, bio FROM users")
    users = cur.fetchall()
    conn.close()

    return render_template(
        "index.html",
        users=users,
        total_users=len(users),
        logged_in="account_id" in session
    )

@app.route("/search")
def search():
    tag = request.args.get("tag") 
    if not tag:
        return redirect(url_for("index"))  
    conn = db()
    cur = conn.cursor()

    cur.execute("""
        SELECT u.id, u.name, u.bio
        FROM users u
        JOIN user_tags ut ON u.id = ut.user_id
        JOIN tags t ON t.id = ut.tag_id
        WHERE t.name = ?
    """, (tag,))
    users = cur.fetchall()
    conn.close()

    return render_template("search.html", users=users, tag=tag)


@app.route("/notifications")
def notifications():
    user_id = current_user_id()
    if not user_id:
        return redirect(url_for("login"))

    conn = db()
    cur = conn.cursor()

    cur.execute("""
        SELECT 
            m.id AS mingle_id,
            u.id AS from_user_id,
            u.name AS from_user_name,
            m.created_at
        FROM mingles m
        JOIN users u ON u.id = m.from_user
        WHERE m.to_user = ?
        ORDER BY m.created_at DESC
    """, (user_id,))

    notifications = cur.fetchall()
    conn.close()

    return render_template(
        "notifications.html",
        notifications=notifications
    )

@app.route("/surpreenda")
def surprise():
    conn = db()
    cur = conn.cursor()

    cur.execute("SELECT id FROM users ORDER BY RANDOM() LIMIT 1")
    user = cur.fetchone()
    conn.close()

    if not user:
        return redirect(url_for("index"))

    return redirect(url_for("view_profile", user_id=user[0]))


@app.route("/mingle/<int:user_id>", methods=["POST"])
def mingle(user_id):
    from_user = current_user_id()
    if not from_user:
        return redirect(url_for("login"))

    if from_user == user_id:
        return redirect(url_for("view_profile", user_id=user_id))

    conn = db()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO mingles (from_user, to_user)
        VALUES (?, ?)
    """, (from_user, user_id))

    conn.commit()
    conn.close()

    return redirect(url_for("view_profile", user_id=user_id))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        password_hash = generate_password_hash(password)

        conn = db()
        cur = conn.cursor()

        try:
            cur.execute(
                "INSERT INTO accounts (username, password_hash) VALUES (?, ?)",
                (username, password_hash)
            )
            account_id = cur.lastrowid

            cur.execute(
                "INSERT INTO users (account_id, name) VALUES (?, ?)",
                (account_id, username)
            )

            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return "Usuário já existe"

        conn.close()
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = db()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, password_hash FROM accounts WHERE username = ?",
            (username,)
        )
        user = cur.fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["account_id"] = user["id"]
            return redirect(url_for("dashboard"))

        return "Usuário ou senha inválidos"

    return render_template("login.html")

@app.route("/delete_account", methods=["POST"])
def delete_account():
    user_id = current_user_id()
    if not user_id:
        return redirect(url_for("login"))

    conn = db()
    cur = conn.cursor()
    
    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    
    cur.execute("DELETE FROM accounts WHERE id = ?", (session["account_id"],))

    conn.commit()
    conn.close()

    session.clear()

    return redirect(url_for("index"))


@app.route("/dashboard")
def dashboard():
    user_id = current_user_id()
    if not user_id:
        return redirect(url_for("login"))

    conn = db()
    cur = conn.cursor()

    cur.execute("""
        SELECT a.username
        FROM accounts a
        JOIN users u ON u.account_id = a.id
        WHERE u.id = ?
    """, (user_id,))
    username = cur.fetchone()["username"]

    cur.execute("SELECT COUNT(*) FROM mingles WHERE to_user = ?", (user_id,))
    notification_count = cur.fetchone()[0]

    cur.execute("""
        SELECT t.id
        FROM tags t
        JOIN user_tags ut ON t.id = ut.tag_id
        WHERE ut.user_id = ?
    """, (user_id,))
    tag_ids = [r["id"] for r in cur.fetchall()]

    compatible_users = []
    if tag_ids:
        placeholders = ",".join("?" * len(tag_ids))
        query = f"""
        SELECT u.id, u.name, u.bio, COUNT(*) AS common_tags
        FROM users u
        JOIN user_tags ut ON u.id = ut.user_id
        WHERE ut.tag_id IN ({placeholders}) AND u.id != ?
        GROUP BY u.id
        ORDER BY common_tags DESC
        """
        cur.execute(query, (*tag_ids, user_id))
        compatible_users = cur.fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        username=username,
        notification_count=notification_count,
        compatible_users=compatible_users
    )

@app.route("/profile/<int:user_id>")
def view_profile(user_id):
    conn = db()
    cur = conn.cursor()

    cur.execute("SELECT id, name, bio FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()

    if not user:
        conn.close()
        return redirect(url_for("index"))

    cur.execute("""
        SELECT t.name FROM tags t
        JOIN user_tags ut ON t.id = ut.tag_id
        WHERE ut.user_id = ?
    """, (user_id,))
    user_tags = [t["name"] for t in cur.fetchall()]

    cur.execute("SELECT platform, url FROM user_links WHERE user_id = ?", (user_id,))
    user_links = cur.fetchall()

    cur.execute("SELECT title, content FROM user_sections WHERE user_id = ?", (user_id,))
    user_sections = cur.fetchall()

    conn.close()

    return render_template(
    "profile.html",
    user=user,
    sections=user_sections,
    tags=user_tags,
    links=user_links
)



@app.route("/profile", methods=["GET", "POST"])
def edit_profile():
    user_id = current_user_id()
    if not user_id:
        return redirect(url_for("login"))

    conn = db()
    cur = conn.cursor()

    cur.execute("SELECT name, bio FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()

    cur.execute("""
        SELECT t.name FROM tags t
        JOIN user_tags ut ON t.id = ut.tag_id
        WHERE ut.user_id = ?
    """, (user_id,))
    user_tags = [t["name"] for t in cur.fetchall()]

    cur.execute("SELECT platform, url FROM user_links WHERE user_id = ?", (user_id,))
    user_links = cur.fetchall()

    cur.execute("SELECT title, content FROM user_sections WHERE user_id = ?", (user_id,))
    user_sections = cur.fetchall()

    if request.method == "POST":
        bio = request.form.get("bio", "")
        cur.execute("UPDATE users SET bio = ? WHERE id = ?", (bio, user_id))

        cur.execute("DELETE FROM user_tags WHERE user_id = ?", (user_id,))
        for tag in request.form.getlist("tags"):
            tag = tag.strip()
            if tag:
                cur.execute("INSERT OR IGNORE INTO tags (name) VALUES (?)", (tag,))
                cur.execute("SELECT id FROM tags WHERE name = ?", (tag,))
                tag_id = cur.fetchone()["id"]
                cur.execute(
                    "INSERT INTO user_tags (user_id, tag_id) VALUES (?, ?)",
                    (user_id, tag_id)
                )

        cur.execute("DELETE FROM user_links WHERE user_id = ?", (user_id,))
        for link in request.form.getlist("links"):
            if "|" in link:
                platform, url = map(str.strip, link.split("|", 1))
                cur.execute(
                    "INSERT INTO user_links (user_id, platform, url) VALUES (?, ?, ?)",
                    (user_id, platform, url)
                )

        cur.execute("DELETE FROM user_sections WHERE user_id = ?", (user_id,))
        for t, c in zip(
            request.form.getlist("section_title"),
            request.form.getlist("section_content")
        ):
            if t.strip():
                cur.execute(
                    "INSERT INTO user_sections (user_id, title, content) VALUES (?, ?, ?)",
                    (user_id, t.strip(), c.strip())
                )



        conn.commit()
        conn.close()
        return redirect(url_for("view_profile", user_id=user_id))

    conn.close()
    return render_template(
        "edit_profile.html",
        user=user,
        user_tags=user_tags,
        user_links=user_links,
        user_sections=user_sections
    )



if __name__ == "__main__":
    init_db()
    app.run(debug=True)
