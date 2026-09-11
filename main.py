import os
import sqlite3
import secrets
from datetime import datetime
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, request, jsonify, session, send_from_directory

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "msafiri_v2.db")

app = Flask(__name__, static_folder=None)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS posts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        caption TEXT NOT NULL DEFAULT '',
        media_url TEXT DEFAULT '',
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS messages(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        body TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """)
    conn.commit()
    conn.close()

init_db()

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    conn = db()
    user = conn.execute("SELECT id,name,email FROM users WHERE id=?", (uid,)).fetchone()
    conn.close()
    return user

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            return jsonify({"ok": False, "error": "Login required"}), 401
        return fn(*args, **kwargs)
    return wrapper

@app.get("/")
def home():
    return send_from_directory(APP_DIR, "index.html")

@app.get("/api/health")
def health():
    return jsonify({"ok": True, "app": "MSAFIRI GLOBAL MEDIA V2", "status": "running"})

@app.post("/api/register")
def register():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    if not name or not email or len(password) < 6:
        return jsonify({"ok": False, "error": "Jaza jina, email na password ya angalau herufi 6."}), 400
    conn = db()
    try:
        cur = conn.execute(
            "INSERT INTO users(name,email,password_hash,created_at) VALUES(?,?,?,?)",
            (name, email, generate_password_hash(password), datetime.utcnow().isoformat())
        )
        conn.commit()
        uid = cur.lastrowid
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"ok": False, "error": "Email hii tayari imesajiliwa. Tumia Login."}), 409
    conn.close()
    session["user_id"] = uid
    return jsonify({"ok": True, "user": {"id": uid, "name": name, "email": email}})

@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    conn = db()
    user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    conn.close()
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"ok": False, "error": "Email au password si sahihi."}), 401
    session["user_id"] = user["id"]
    return jsonify({"ok": True, "user": {"id": user["id"], "name": user["name"], "email": user["email"]}})

@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify({"ok": True})

@app.get("/api/me")
def me():
    u = current_user()
    if not u:
        return jsonify({"ok": True, "user": None})
    return jsonify({"ok": True, "user": dict(u)})

@app.get("/api/posts")
def posts():
    conn = db()
    rows = conn.execute("""
        SELECT p.id,p.user_id,p.caption,p.media_url,p.created_at,u.name
        FROM posts p JOIN users u ON u.id=p.user_id
        ORDER BY p.id DESC
    """).fetchall()
    conn.close()
    return jsonify({"ok": True, "posts": [dict(r) for r in rows]})

@app.post("/api/posts")
@login_required
def create_post():
    data = request.get_json(silent=True) or {}
    caption = (data.get("caption") or "").strip()
    media_url = (data.get("media_url") or "").strip()
    if not caption and not media_url:
        return jsonify({"ok": False, "error": "Andika caption au weka media."}), 400
    u = current_user()
    conn = db()
    cur = conn.execute(
        "INSERT INTO posts(user_id,caption,media_url,created_at) VALUES(?,?,?,?)",
        (u["id"], caption, media_url, datetime.utcnow().isoformat())
    )
    conn.commit()
    row = conn.execute("""
        SELECT p.id,p.user_id,p.caption,p.media_url,p.created_at,u.name
        FROM posts p JOIN users u ON u.id=p.user_id WHERE p.id=?
    """, (cur.lastrowid,)).fetchone()
    conn.close()
    return jsonify({"ok": True, "post": dict(row)})

@app.delete("/api/posts/<int:post_id>")
@login_required
def delete_post(post_id):
    u = current_user()
    conn = db()
    row = conn.execute("SELECT user_id FROM posts WHERE id=?", (post_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "Post haipo."}), 404
    if row["user_id"] != u["id"]:
        conn.close()
        return jsonify({"ok": False, "error": "Unaweza kufuta post zako tu."}), 403
    conn.execute("DELETE FROM posts WHERE id=?", (post_id,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

@app.get("/api/users")
@login_required
def users():
    conn = db()
    rows = conn.execute("SELECT id,name,email FROM users ORDER BY name LIMIT 100").fetchall()
    conn.close()
    return jsonify({"ok": True, "users": [dict(r) for r in rows]})

@app.post("/api/messages")
@login_required
def send_message():
    data = request.get_json(silent=True) or {}
    receiver = int(data.get("receiver_id") or 0)
    body = (data.get("body") or "").strip()
    if not receiver or not body:
        return jsonify({"ok": False, "error": "Receiver na ujumbe vinahitajika."}), 400
    u = current_user()
    conn = db()
    conn.execute(
        "INSERT INTO messages(sender_id,receiver_id,body,created_at) VALUES(?,?,?,?)",
        (u["id"], receiver, body, datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

@app.get("/api/messages/<int:user_id>")
@login_required
def messages(user_id):
    u = current_user()
    conn = db()
    rows = conn.execute("""
        SELECT m.*, su.name sender_name
        FROM messages m JOIN users su ON su.id=m.sender_id
        WHERE (m.sender_id=? AND m.receiver_id=?)
           OR (m.sender_id=? AND m.receiver_id=?)
        ORDER BY m.id ASC
    """, (u["id"],user_id,user_id,u["id"])).fetchall()
    conn.close()
    return jsonify({"ok": True, "messages": [dict(r) for r in rows]})

AI_KNOWLEDGE = {
    "education": {
        "title": "EDU AI COUNCIL",
        "topics": ["curriculum planning","lesson notes","revision","quizzes","marking rubrics","study plans"],
        "reply": "EDU AI inaweza kupanga somo kwa kiwango/darasa, kutengeneza notes, maswali ya mazoezi na rubric ya kusahihisha. Kwa syllabus rasmi, pakia au taja syllabus husika ili majibu yafuate hati hiyo badala ya kudai data ambayo haijapakiwa."
    },
    "health": {
        "title": "HEALTH AI COUNCIL",
        "topics": ["health education","symptoms","prevention","medication information","healthy habits"],
        "reply": "HEALTH AI hutoa elimu ya afya na kusaidia kuelewa taarifa. Si mbadala wa daktari, na hali za dharura zinahitaji huduma ya kitabibu."
    },
    "business": {
        "title": "BUSINESS AI COUNCIL",
        "topics": ["business plans","marketing","pricing","market research","cash flow","strategy"],
        "reply": "BUSINESS AI inaweza kusaidia business model, market research framework, marketing plans, pricing analysis na financial projections."
    },
    "agriculture": {
        "title": "AGRICULTURE AI COUNCIL",
        "topics": ["crop planning","soil","irrigation","pests","post-harvest","farm business"],
        "reply": "AGRI AI inaweza kupanga ratiba za kilimo, irrigation, pest-management frameworks na farm business plans. Kwa ushauri wa shamba, eneo, zao na hali ya udongo huongeza usahihi."
    },
    "research": {
        "title": "RESEARCH AI COUNCIL",
        "topics": ["research questions","literature review","methodology","data analysis","citations"],
        "reply": "RESEARCH AI inaweza kusaidia research question, proposal structure, methodology, literature-review matrix na uchambuzi wa data. Usidanganye citations; vyanzo halisi vinapaswa kuthibitishwa."
    },
    "vision": {
        "title": "VISION AI COUNCIL",
        "topics": ["image understanding","object counting","visual inspection","document vision"],
        "reply": "VISION AI imeandaliwa kwa workflows za picha kama object counting, document understanding na plant-identification concepts. Uchanganuzi halisi wa picha unahitaji image/vision model kuunganishwa."
    }
}

@app.post("/api/ai")
def ai():
    data = request.get_json(silent=True) or {}
    council = (data.get("council") or "education").lower()
    question = (data.get("question") or "").strip()
    item = AI_KNOWLEDGE.get(council, AI_KNOWLEDGE["education"])
    if not question:
        return jsonify({"ok": False, "error": "Andika swali."}), 400
    return jsonify({
        "ok": True,
        "council": item["title"],
        "answer": item["reply"] + "\n\nSwali lako: " + question,
        "topics": item["topics"]
    })

@app.post("/api/reality")
def reality():
    data = request.get_json(silent=True) or {}
    mode = data.get("mode", "object_counter")
    if mode == "plant":
        return jsonify({"ok": True, "result": "Plant Identifier: pakia picha ili vision model itambue mmea kwa confidence score."})
    if mode == "length":
        return jsonify({"ok": True, "result": "Measure Length: kamera/AR sensor inahitajika kwa kipimo halisi."})
    return jsonify({"ok": True, "result": "Object Counter: vision model inahitajika kwa kuhesabu vitu kwenye picha."})

@app.errorhandler(413)
def too_large(e):
    return jsonify({"ok": False, "error": "File ni kubwa sana (max 50MB)."}), 413

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
