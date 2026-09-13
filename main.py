# ============================================================
# MSAFIRI GLOBAL MEDIA V4
# FastAPI + PostgreSQL + LiveKit
# ============================================================
from fastapi.responses import FileResponse
import os
import re
import uuid
import hashlib
import secrets
import mimetypes
from pathlib import Path
from datetime import datetime, timezone

import psycopg
from psycopg.rows import dict_row

from fastapi import (
    FastAPI,
    HTTPException,
    UploadFile,
    File,
    Form,
    Header,
    Cookie,
    Query,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr

from livekit import api


# ============================================================
# CONFIG
# ============================================================

APP_NAME = "MSAFIRI GLOBAL MEDIA V4"

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
POST_UPLOAD_DIR = UPLOAD_DIR / "posts"
AVATAR_UPLOAD_DIR = UPLOAD_DIR / "avatars"
WALLPAPER_UPLOAD_DIR = UPLOAD_DIR / "wallpapers"
VOICE_UPLOAD_DIR = UPLOAD_DIR / "voice"

for folder in [
    UPLOAD_DIR,
    POST_UPLOAD_DIR,
    AVATAR_UPLOAD_DIR,
    WALLPAPER_UPLOAD_DIR,
    VOICE_UPLOAD_DIR,
]:
    folder.mkdir(parents=True, exist_ok=True)


DATABASE_URL = os.getenv("DATABASE_URL", "").strip()

LIVEKIT_URL = os.getenv("LIVEKIT_URL", "").strip()
LIVEKIT_API_KEY = os.getenv("LIVEKIT_API_KEY", "").strip()
LIVEKIT_API_SECRET = os.getenv("LIVEKIT_API_SECRET", "").strip()


if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace(
        "postgres://",
        "postgresql://",
        1,
    )


# ============================================================
# APP
# ============================================================

app = FastAPI(
    title=APP_NAME,
    version="4.0.0",
    description="MSAFIRI GLOBAL MEDIA V4 Backend",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# STATIC FILES
# ============================================================

app.mount(
    "/uploads",
    StaticFiles(directory=str(UPLOAD_DIR)),
    name="uploads",
)


# ============================================================
# HELPERS
# ============================================================

def now_utc():
    return datetime.now(timezone.utc)


def db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not configured")

    return psycopg.connect(
        DATABASE_URL,
        row_factory=dict_row,
    )


def hash_token(token: str):
    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


def generate_token():
    return secrets.token_urlsafe(48)


def normalize_email(email: str):
    return email.strip().lower()


def clean_text(value: str, max_length: int = 5000):
    if value is None:
        return ""

    value = value.strip()

    if len(value) > max_length:
        raise HTTPException(
            status_code=400,
            detail=f"Text is too long. Maximum {max_length} characters.",
        )

    return value


def valid_password(password: str):
    if len(password) < 6:
        raise HTTPException(
            status_code=400,
            detail="Password must contain at least 6 characters.",
        )


def password_hash(password: str):
    """
    Compatible PBKDF2 password format.
    """
    salt = secrets.token_hex(16)

    iterations = 120000

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
    )

    return (
        f"pbkdf2_sha256${iterations}$"
        f"{salt}${digest.hex()}"
    )


def password_verify(password: str, stored: str):
    try:
        algorithm, iterations, salt, stored_hash = stored.split(
            "$",
            3,
        )

        if algorithm != "pbkdf2_sha256":
            return False

        iterations = int(iterations)

        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            iterations,
        )

        return secrets.compare_digest(
            digest.hex(),
            stored_hash,
        )

    except Exception:
        return False


def safe_filename(filename: str):
    ext = Path(filename or "").suffix.lower()

    allowed = {
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".webp",
        ".mp4",
        ".webm",
        ".mov",
        ".mp3",
        ".wav",
        ".m4a",
        ".ogg",
    }

    if ext not in allowed:
        ext = ""

    return f"{uuid.uuid4().hex}{ext}"


def get_bearer_token(
    authorization: str | None,
    token_cookie: str | None,
):
    if authorization:
        if authorization.lower().startswith("bearer "):
            return authorization[7:].strip()

    if token_cookie:
        return token_cookie.strip()

    return None


def require_user(
    authorization: str | None = None,
    token_cookie: str | None = None,
):
    token = get_bearer_token(
        authorization,
        token_cookie,
    )

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Authentication required.",
        )

    token_hash = hash_token(token)

    with db() as conn:
        user = conn.execute(
            """
            SELECT
                u.id,
                u.name,
                u.email,
                u.bio,
                u.avatar,
                u.created_at,
                u.updated_at
            FROM sessions s
            JOIN users u
                ON u.id = s.user_id
            WHERE s.token_hash = %s
              AND s.revoked = FALSE
              AND u.deleted_at IS NULL
            LIMIT 1
            """,
            (token_hash,),
        ).fetchone()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid or logged-out session.",
        )

    return user


def user_dict(user):
    if not user:
        return None

    return {
        "id": user["id"],
        "name": user["name"],
        "email": user["email"],
        "bio": user.get("bio"),
        "avatar": user.get("avatar"),
        "created_at": user.get("created_at"),
        "updated_at": user.get("updated_at"),
    }


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def init_db():

    with db() as conn:

        # ----------------------------------------------------
        # USERS
        # ----------------------------------------------------

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id BIGSERIAL PRIMARY KEY,

                name TEXT NOT NULL,

                email TEXT NOT NULL UNIQUE,

                password_hash TEXT NOT NULL,

                bio TEXT DEFAULT '',

                avatar TEXT,

                deleted_at TIMESTAMPTZ,

                created_at TIMESTAMPTZ NOT NULL
                    DEFAULT CURRENT_TIMESTAMP,

                updated_at TIMESTAMPTZ NOT NULL
                    DEFAULT CURRENT_TIMESTAMP
            )
            """
        )


        # ----------------------------------------------------
        # SESSIONS
        # ----------------------------------------------------

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id BIGSERIAL PRIMARY KEY,

                user_id BIGINT NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                token_hash TEXT NOT NULL UNIQUE,

                revoked BOOLEAN NOT NULL DEFAULT FALSE,

                created_at TIMESTAMPTZ NOT NULL
                    DEFAULT CURRENT_TIMESTAMP
            )
            """
        )


        # ----------------------------------------------------
        # POSTS
        # ----------------------------------------------------

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS posts (
                id BIGSERIAL PRIMARY KEY,

                user_id BIGINT NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                caption TEXT DEFAULT '',

                media_url TEXT,

                media_type TEXT,

                deleted_at TIMESTAMPTZ,

                created_at TIMESTAMPTZ NOT NULL
                    DEFAULT CURRENT_TIMESTAMP,

                updated_at TIMESTAMPTZ NOT NULL
                    DEFAULT CURRENT_TIMESTAMP
            )
            """
        )


        # ----------------------------------------------------
        # LIKES
        # ----------------------------------------------------

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS likes (
                id BIGSERIAL PRIMARY KEY,

                user_id BIGINT NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                post_id BIGINT NOT NULL
                    REFERENCES posts(id)
                    ON DELETE CASCADE,

                created_at TIMESTAMPTZ NOT NULL
                    DEFAULT CURRENT_TIMESTAMP,

                UNIQUE(user_id, post_id)
            )
            """
        )


        # ----------------------------------------------------
        # COMMENTS
        # ----------------------------------------------------

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS comments (
                id BIGSERIAL PRIMARY KEY,

                user_id BIGINT NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                post_id BIGINT NOT NULL
                    REFERENCES posts(id)
                    ON DELETE CASCADE,

                text TEXT NOT NULL,

                created_at TIMESTAMPTZ NOT NULL
                    DEFAULT CURRENT_TIMESTAMP
            )
            """
        )


        # ----------------------------------------------------
        # SAVED POSTS
        # ----------------------------------------------------

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS saved_posts (
                id BIGSERIAL PRIMARY KEY,

                user_id BIGINT NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                post_id BIGINT NOT NULL
                    REFERENCES posts(id)
                    ON DELETE CASCADE,

                created_at TIMESTAMPTZ NOT NULL
                    DEFAULT CURRENT_TIMESTAMP,

                UNIQUE(user_id, post_id)
            )
            """
        )


        # ----------------------------------------------------
        # RESHARES
        # ----------------------------------------------------

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS reshares (
                id BIGSERIAL PRIMARY KEY,

                user_id BIGINT NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                post_id BIGINT NOT NULL
                    REFERENCES posts(id)
                    ON DELETE CASCADE,

                created_at TIMESTAMPTZ NOT NULL
                    DEFAULT CURRENT_TIMESTAMP,

                UNIQUE(user_id, post_id)
            )
            """
        )


        # ----------------------------------------------------
        # MESSAGES
        # ----------------------------------------------------

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id BIGSERIAL PRIMARY KEY,

                sender_id BIGINT NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                receiver_id BIGINT NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                text TEXT DEFAULT '',

                media_url TEXT,

                media_type TEXT,

                voice_url TEXT,

                read BOOLEAN NOT NULL DEFAULT FALSE,

                deleted_for_sender BOOLEAN NOT NULL DEFAULT FALSE,

                deleted_for_receiver BOOLEAN NOT NULL DEFAULT FALSE,

                created_at TIMESTAMPTZ NOT NULL
                    DEFAULT CURRENT_TIMESTAMP
            )
            """
        )


        # ----------------------------------------------------
        # CHAT SETTINGS
        # ----------------------------------------------------

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS chat_settings (
                id BIGSERIAL PRIMARY KEY,

                user_id BIGINT NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                chat_user_id BIGINT NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                wallpaper_url TEXT,

                muted BOOLEAN NOT NULL DEFAULT FALSE,

                pinned BOOLEAN NOT NULL DEFAULT FALSE,

                blocked BOOLEAN NOT NULL DEFAULT FALSE,

                updated_at TIMESTAMPTZ NOT NULL
                    DEFAULT CURRENT_TIMESTAMP,

                UNIQUE(user_id, chat_user_id)
            )
            """
        )


        # ----------------------------------------------------
        # FOLLOWERS
        # ----------------------------------------------------

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS followers (
                id BIGSERIAL PRIMARY KEY,

                follower_id BIGINT NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                following_id BIGINT NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                created_at TIMESTAMPTZ NOT NULL
                    DEFAULT CURRENT_TIMESTAMP,

                UNIQUE(follower_id, following_id),

                CHECK(follower_id <> following_id)
            )
            """
        )


        # ----------------------------------------------------
        # STATUSES
        # ----------------------------------------------------

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS statuses (
                id BIGSERIAL PRIMARY KEY,

                user_id BIGINT NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                media_url TEXT,

                media_type TEXT,

                text TEXT DEFAULT '',

                expires_at TIMESTAMPTZ,

                created_at TIMESTAMPTZ NOT NULL
                    DEFAULT CURRENT_TIMESTAMP
            )
            """
        )


        # ----------------------------------------------------
        # CALL SESSIONS
        # ----------------------------------------------------

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS call_sessions (
                id UUID PRIMARY KEY,

                caller_id BIGINT NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                receiver_id BIGINT NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                room_name TEXT NOT NULL UNIQUE,

                call_type TEXT NOT NULL,

                status TEXT NOT NULL DEFAULT 'calling',

                started_at TIMESTAMPTZ,

                ended_at TIMESTAMPTZ,

                created_at TIMESTAMPTZ NOT NULL
                    DEFAULT CURRENT_TIMESTAMP
            )
            """
        )


        # ----------------------------------------------------
        # BLOCKS
        # ----------------------------------------------------

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS blocks (
                id BIGSERIAL PRIMARY KEY,

                blocker_id BIGINT NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                blocked_id BIGINT NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                created_at TIMESTAMPTZ NOT NULL
                    DEFAULT CURRENT_TIMESTAMP,

                UNIQUE(blocker_id, blocked_id),

                CHECK(blocker_id <> blocked_id)
            )
            """
        )


        # ----------------------------------------------------
        # REPORTS
        # ----------------------------------------------------

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS reports (
                id BIGSERIAL PRIMARY KEY,

                reporter_id BIGINT NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                reported_user_id BIGINT
                    REFERENCES users(id)
                    ON DELETE SET NULL,

                post_id BIGINT
                    REFERENCES posts(id)
                    ON DELETE SET NULL,

                message_id BIGINT
                    REFERENCES messages(id)
                    ON DELETE SET NULL,

                reason TEXT NOT NULL,

                created_at TIMESTAMPTZ NOT NULL
                    DEFAULT CURRENT_TIMESTAMP
            )
            """
        )


        # ----------------------------------------------------
        # INDEXES
        # ----------------------------------------------------

        indexes = [

            """
            CREATE INDEX IF NOT EXISTS idx_users_email
            ON users(email)
            """,

            """
            CREATE INDEX IF NOT EXISTS idx_sessions_user
            ON sessions(user_id)
            """,

            """
            CREATE INDEX IF NOT EXISTS idx_sessions_token
            ON sessions(token_hash)
            """,

            """
            CREATE INDEX IF NOT EXISTS idx_posts_user
            ON posts(user_id)
            """,

            """
            CREATE INDEX IF NOT EXISTS idx_posts_created
            ON posts(created_at DESC)
            """,

            """
            CREATE INDEX IF NOT EXISTS idx_likes_post
            ON likes(post_id)
            """,

            """
            CREATE INDEX IF NOT EXISTS idx_comments_post
            ON comments(post_id)
            """,

            """
            CREATE INDEX IF NOT EXISTS idx_messages_sender
            ON messages(sender_id)
            """,

            """
            CREATE INDEX IF NOT EXISTS idx_messages_receiver
            ON messages(receiver_id)
            """,

            """
            CREATE INDEX IF NOT EXISTS idx_messages_created
            ON messages(created_at DESC)
            """,

            """
            CREATE INDEX IF NOT EXISTS idx_followers_following
            ON followers(following_id)
            """,

            """
            CREATE INDEX IF NOT EXISTS idx_followers_follower
            ON followers(follower_id)
            """,
        ]

        for statement in indexes:
            conn.execute(statement)

        conn.commit()


# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
def startup():
    init_db()


# ============================================================
# ROOT
# ============================================================

@app.get("/", include_in_schema=False)
def root():
    return FileResponse(
        str(BASE_DIR / "index.html")
    )


# ============================================================
# HEALTH
# ============================================================

@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "app": APP_NAME,
        "version": "4.0.0",
    }


@app.get("/api/health/db")
def database_health():

    try:
        with db() as conn:

            row = conn.execute(
                "SELECT NOW() AS server_time"
            ).fetchone()

        return {
            "status": "ok",
            "database": "postgresql",
            "server_time": row["server_time"],
        }

    except Exception as e:

        return {
            "status": "error",
            "database": "postgresql",
            "error": str(e),
        }


# ============================================================
# AUTH MODELS
# ============================================================

class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ProfileUpdateRequest(BaseModel):
    name: str | None = None
    bio: str | None = None


class MessageRequest(BaseModel):
    receiver_id: int
    text: str


class CommentRequest(BaseModel):
    text: str


class CallRequest(BaseModel):
    receiver_id: int
    call_type: str


class ChatSettingsRequest(BaseModel):
    muted: bool | None = None
    pinned: bool | None = None
    blocked: bool | None = None


class ReportRequest(BaseModel):
    reason: str


# ============================================================
# REGISTER
# ============================================================

@app.post("/api/register")
def register(data: RegisterRequest):

    name = clean_text(data.name, 100)
    email = normalize_email(data.email)
    password = data.password

    if len(name) < 2:
        raise HTTPException(
            status_code=400,
            detail="Name is too short.",
        )

    valid_password(password)

    password_h = password_hash(password)

    with db() as conn:

        # Check whether this email already has an account.
        # Do NOT use deleted_at because the current users table
        # does not contain that column.
        existing = conn.execute(
            """
            SELECT id
            FROM users
            WHERE email = %s
            LIMIT 1
            """,
            (email,),
        ).fetchone()

        if existing:
            raise HTTPException(
                status_code=409,
                detail="An account with this email already exists.",
            )

        user = conn.execute(
            """
            INSERT INTO users
                (name, email, password_hash)
            VALUES
                (%s, %s, %s)
            RETURNING
                id,
                name,
                email,
                bio,
                avatar,
                created_at,
                updated_at
            """,
            (
                name,
                email,
                password_h,
            ),
        ).fetchone()

        conn.commit()

    return {
        "ok": True,
        "message": "Account created successfully.",
        "user": user_dict(user),
    }



# ============================================================
# LOGIN
# ============================================================

@app.post("/api/login")
def login(data: LoginRequest):

    email = normalize_email(data.email)

    with db() as conn:

        user = conn.execute(
            """
            SELECT *
            FROM users
            WHERE email = %s
              AND deleted_at IS NULL
            LIMIT 1
            """,
            (email,),
        ).fetchone()

        if not user:
            raise HTTPException(
                status_code=401,
                detail="Invalid email or password.",
            )

        if not password_verify(
            data.password,
            user["password_hash"],
        ):
            raise HTTPException(
                status_code=401,
                detail="Invalid email or password.",
            )

        raw_token = generate_token()

        conn.execute(
            """
            INSERT INTO sessions
                (user_id, token_hash)
            VALUES
                (%s, %s)
            """,
            (
                user["id"],
                hash_token(raw_token),
            ),
        )

        conn.commit()

    return {
        "ok": True,
        "token": raw_token,
        "user": user_dict(user),
    }


# ============================================================
# ME
# ============================================================

@app.get("/api/me")
def me(
    authorization: str | None = Header(default=None),
    msafiri_token: str | None = Cookie(default=None),
):

    user = require_user(
        authorization,
        msafiri_token,
    )

    return {
        "ok": True,
        "user": user_dict(user),
    }


# ============================================================
# LOGOUT
# ============================================================

@app.post("/api/logout")
def logout(
    authorization: str | None = Header(default=None),
    msafiri_token: str | None = Cookie(default=None),
):

    token = get_bearer_token(
        authorization,
        msafiri_token,
    )

    if not token:
        return {
            "ok": True,
            "message": "Already logged out.",
        }

    with db() as conn:

        conn.execute(
            """
            UPDATE sessions
            SET revoked = TRUE
            WHERE token_hash = %s
            """,
            (hash_token(token),),
        )

        conn.commit()

    return {
        "ok": True,
        "message": "Logged out successfully.",
    }


# ============================================================
# DELETE ACCOUNT
# ============================================================

@app.delete("/api/account")
def delete_account(
    authorization: str | None = Header(default=None),
    msafiri_token: str | None = Cookie(default=None),
):

    user = require_user(
        authorization,
        msafiri_token,
    )

    with db() as conn:

        conn.execute(
            """
            UPDATE users
            SET
                deleted_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP,
                email = CONCAT(
                    'deleted_',
                    id,
                    '_',
                    EXTRACT(EPOCH FROM CURRENT_TIMESTAMP),
                    '@deleted.local'
                )
            WHERE id = %s
            """,
            (user["id"],),
        )

        conn.execute(
            """
            UPDATE sessions
            SET revoked = TRUE
            WHERE user_id = %s
            """,
            (user["id"],),
        )

        conn.commit()

    return {
        "ok": True,
        "message": "Account deleted.",
    }


# ============================================================
# PROFILE
# ============================================================

@app.get("/api/profile/{user_id}")
def get_profile(user_id: int):

    with db() as conn:

        user = conn.execute(
            """
            SELECT
                id,
                name,
                email,
                bio,
                avatar,
                created_at
            FROM users
            WHERE id = %s
              AND deleted_at IS NULL
            """,
            (user_id,),
        ).fetchone()

        if not user:
            raise HTTPException(
                status_code=404,
                detail="User not found.",
            )

        followers = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM followers
            WHERE following_id = %s
            """,
            (user_id,),
        ).fetchone()["count"]

        following = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM followers
            WHERE follower_id = %s
            """,
            (user_id,),
        ).fetchone()["count"]

    return {
        "ok": True,
        "user": user,
        "followers": followers,
        "following": following,
    }


@app.patch("/api/profile")
def update_profile(
    data: ProfileUpdateRequest,
    authorization: str | None = Header(default=None),
    msafiri_token: str | None = Cookie(default=None),
):

    user = require_user(
        authorization,
        msafiri_token,
    )

    name = (
        clean_text(data.name, 100)
        if data.name is not None
        else user["name"]
    )

    bio = (
        clean_text(data.bio, 1000)
        if data.bio is not None
        else user["bio"]
    )

    with db() as conn:

        updated = conn.execute(
            """
            UPDATE users
            SET
                name = %s,
                bio = %s,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
            RETURNING
                id,
                name,
                email,
                bio,
                avatar,
                created_at,
                updated_at
            """,
            (
                name,
                bio,
                user["id"],
            ),
        ).fetchone()

        conn.commit()

    return {
        "ok": True,
        "user": updated,
    }


# ============================================================
# PROFILE PICTURE
# ============================================================

@app.post("/api/profile/avatar")
async def upload_avatar(
    file: UploadFile = File(...),
    authorization: str | None = Header(default=None),
    msafiri_token: str | None = Cookie(default=None),
):

    user = require_user(
        authorization,
        msafiri_token,
    )

    content_type = file.content_type or ""

    if not content_type.startswith("image/"):
        raise HTTPException(
            status_code=400,
            detail="Profile picture must be an image.",
        )

    filename = safe_filename(
        file.filename or ""
    )

    destination = AVATAR_UPLOAD_DIR / filename

    content = await file.read()

    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(
            status_code=400,
            detail="Image is too large. Maximum 10MB.",
        )

    destination.write_bytes(content)

    avatar_url = f"/uploads/avatars/{filename}"

    with db() as conn:

        updated = conn.execute(
            """
            UPDATE users
            SET
                avatar = %s,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
            RETURNING
                id,
                name,
                email,
                bio,
                avatar,
                created_at,
                updated_at
            """,
            (
                avatar_url,
                user["id"],
            ),
        ).fetchone()

        conn.commit()

    return {
        "ok": True,
        "avatar": avatar_url,
        "user": updated,
    }


# ============================================================
# CREATE POST
# ============================================================

@app.post("/api/posts")
async def create_post(
    caption: str = Form(default=""),
    media: UploadFile | None = File(default=None),
    authorization: str | None = Header(default=None),
    msafiri_token: str | None = Cookie(default=None),
):

    user = require_user(
        authorization,
        msafiri_token,
    )

    caption = clean_text(caption, 5000)

    media_url = None
    media_type = None

    if media:

        content_type = media.content_type or ""

        if not (
            content_type.startswith("image/")
            or content_type.startswith("video/")
            or content_type.startswith("audio/")
        ):
            raise HTTPException(
                status_code=400,
                detail="Unsupported media type.",
            )

        filename = safe_filename(
            media.filename or ""
        )

        destination = POST_UPLOAD_DIR / filename

        content = await media.read()

        if len(content) > 100 * 1024 * 1024:
            raise HTTPException(
                status_code=400,
                detail="Media is too large. Maximum 100MB.",
            )

        destination.write_bytes(content)

        media_url = f"/uploads/posts/{filename}"

        if content_type.startswith("image/"):
            media_type = "image"

        elif content_type.startswith("video/"):
            media_type = "video"

        else:
            media_type = "audio"

    if not caption and not media_url:
        raise HTTPException(
            status_code=400,
            detail="Post must contain text or media.",
        )

    with db() as conn:

        post = conn.execute(
            """
            INSERT INTO posts
                (
                    user_id,
                    caption,
                    media_url,
                    media_type
                )
            VALUES
                (%s, %s, %s, %s)
            RETURNING *
            """,
            (
                user["id"],
                caption,
                media_url,
                media_type,
            ),
        ).fetchone()

        conn.commit()

    return {
        "ok": True,
        "post": post,
    }


# ============================================================
# FEED
# ============================================================

@app.get("/api/posts")
def get_posts(
    limit: int = Query(default=30, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
):

    with db() as conn:

        posts = conn.execute(
            """
            SELECT
                p.id,
                p.user_id,
                p.caption,
                p.media_url,
                p.media_type,
                p.created_at,

                u.name AS user_name,
                u.avatar AS user_avatar,

                (
                    SELECT COUNT(*)
                    FROM likes l
                    WHERE l.post_id = p.id
                ) AS likes_count,

                (
                    SELECT COUNT(*)
                    FROM comments c
                    WHERE c.post_id = p.id
                ) AS comments_count,

                (
                    SELECT COUNT(*)
                    FROM reshares r
                    WHERE r.post_id = p.id
                ) AS reshares_count

            FROM posts p

            JOIN users u
                ON u.id = p.user_id

            WHERE p.deleted_at IS NULL
              AND u.deleted_at IS NULL

            ORDER BY p.created_at DESC

            LIMIT %s
            OFFSET %s
            """,
            (
                limit,
                offset,
            ),
        ).fetchall()

    return {
        "ok": True,
        "posts": posts,
        "limit": limit,
        "offset": offset,
    }


# ============================================================
# DELETE POST
# ============================================================

@app.delete("/api/posts/{post_id}")
def delete_post(
    post_id: int,
    authorization: str | None = Header(default=None),
    msafiri_token: str | None = Cookie(default=None),
):

    user = require_user(
        authorization,
        msafiri_token,
    )

    with db() as conn:

        post = conn.execute(
            """
            SELECT id
            FROM posts
            WHERE id = %s
              AND user_id = %s
              AND deleted_at IS NULL
            """,
            (
                post_id,
                user["id"],
            ),
        ).fetchone()

        if not post:
            raise HTTPException(
                status_code=404,
                detail="Post not found.",
            )

        conn.execute(
            """
            UPDATE posts
            SET
                deleted_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
            """,
            (post_id,),
        )

        conn.commit()

    return {
        "ok": True,
        "message": "Post deleted.",
    }


# ============================================================
# LIKE / UNLIKE
# ============================================================

@app.post("/api/posts/{post_id}/like")
def like_post(
    post_id: int,
    authorization: str | None = Header(default=None),
    msafiri_token: str | None = Cookie(default=None),
):

    user = require_user(
        authorization,
        msafiri_token,
    )

    with db() as conn:

        post = conn.execute(
            """
            SELECT id
            FROM posts
            WHERE id = %s
              AND deleted_at IS NULL
            """,
            (post_id,),
        ).fetchone()

        if not post:
            raise HTTPException(
                status_code=404,
                detail="Post not found.",
            )

        conn.execute(
            """
            INSERT INTO likes
                (user_id, post_id)
            VALUES
                (%s, %s)
            ON CONFLICT
                (user_id, post_id)
            DO NOTHING
            """,
            (
                user["id"],
                post_id,
            ),
        )

        conn.commit()

    return {
        "ok": True,
        "liked": True,
    }


@app.delete("/api/posts/{post_id}/like")
def unlike_post(
    post_id: int,
    authorization: str | None = Header(default=None),
    msafiri_token: str | None = Cookie(default=None),
):

    user = require_user(
        authorization,
        msafiri_token,
    )

    with db() as conn:

        conn.execute(
            """
            DELETE FROM likes
            WHERE user_id = %s
              AND post_id = %s
            """,
            (
                user["id"],
                post_id,
            ),
        )

        conn.commit()

    return {
        "ok": True,
        "liked": False,
    }


# ============================================================
# COMMENTS
# ============================================================

@app.post("/api/posts/{post_id}/comments")
def add_comment(
    post_id: int,
    data: CommentRequest,
    authorization: str | None = Header(default=None),
    msafiri_token: str | None = Cookie(default=None),
):

    user = require_user(
        authorization,
        msafiri_token,
    )

    text = clean_text(data.text, 2000)

    if not text:
        raise HTTPException(
            status_code=400,
            detail="Comment cannot be empty.",
        )

    with db() as conn:

        post = conn.execute(
            """
            SELECT id
            FROM posts
            WHERE id = %s
              AND deleted_at IS NULL
            """,
            (post_id,),
        ).fetchone()

        if not post:
            raise HTTPException(
                status_code=404,
                detail="Post not found.",
            )

        comment = conn.execute(
            """
            INSERT INTO comments
                (
                    user_id,
                    post_id,
                    text
                )
            VALUES
                (%s, %s, %s)
            RETURNING *
            """,
            (
                user["id"],
                post_id,
                text,
            ),
        ).fetchone()

        conn.commit()

    return {
        "ok": True,
        "comment": comment,
    }


@app.get("/api/posts/{post_id}/comments")
def get_comments(
    post_id: int,
):

    with db() as conn:

        comments = conn.execute(
            """
            SELECT
                c.id,
                c.text,
                c.created_at,
                c.user_id,
                u.name AS user_name,
                u.avatar AS user_avatar
            FROM comments c
            JOIN users u
                ON u.id = c.user_id
            WHERE c.post_id = %s
              AND u.deleted_at IS NULL
            ORDER BY c.created_at ASC
            """,
            (post_id,),
        ).fetchall()

    return {
        "ok": True,
        "comments": comments,
    }


# ============================================================
# SAVE / UNSAVE
# ============================================================

@app.post("/api/posts/{post_id}/save")
def save_post(
    post_id: int,
    authorization: str | None = Header(default=None),
    msafiri_token: str | None = Cookie(default=None),
):

    user = require_user(
        authorization,
        msafiri_token,
    )

    with db() as conn:

        conn.execute(
            """
            INSERT INTO saved_posts
                (user_id, post_id)
            VALUES
                (%s, %s)
            ON CONFLICT
                (user_id, post_id)
            DO NOTHING
            """,
            (
                user["id"],
                post_id,
            ),
        )

        conn.commit()

    return {
        "ok": True,
        "saved": True,
    }


@app.delete("/api/posts/{post_id}/save")
def unsave_post(
    post_id: int,
    authorization: str | None = Header(default=None),
    msafiri_token: str | None = Cookie(default=None),
):

    user = require_user(
        authorization,
        msafiri_token,
    )

    with db() as conn:

        conn.execute(
            """
            DELETE FROM saved_posts
            WHERE user_id = %s
              AND post_id = %s
            """,
            (
                user["id"],
                post_id,
            ),
        )

        conn.commit()

    return {
        "ok": True,
        "saved": False,
    }


# ============================================================
# RESHARE
# ============================================================

@app.post("/api/posts/{post_id}/reshare")
def reshare_post(
    post_id: int,
    authorization: str | None = Header(default=None),
    msafiri_token: str | None = Cookie(default=None),
):

    user = require_user(
        authorization,
        msafiri_token,
    )

    with db() as conn:

        conn.execute(
            """
            INSERT INTO reshares
                (user_id, post_id)
            VALUES
                (%s, %s)
            ON CONFLICT
                (user_id, post_id)
            DO NOTHING
            """,
            (
                user["id"],
                post_id,
            ),
        )

        conn.commit()

    return {
        "ok": True,
        "reshared": True,
    }


# ============================================================
# FOLLOW / UNFOLLOW
# ============================================================

@app.post("/api/users/{user_id}/follow")
def follow_user(
    user_id: int,
    authorization: str | None = Header(default=None),
    msafiri_token: str | None = Cookie(default=None),
):

    user = require_user(
        authorization,
        msafiri_token,
    )

    if user["id"] == user_id:
        raise HTTPException(
            status_code=400,
            detail="You cannot follow yourself.",
        )

    with db() as conn:

        target = conn.execute(
            """
            SELECT id
            FROM users
            WHERE id = %s
              AND deleted_at IS NULL
            """,
            (user_id,),
        ).fetchone()

        if not target:
            raise HTTPException(
                status_code=404,
                detail="User not found.",
            )

        conn.execute(
            """
            INSERT INTO followers
                (
                    follower_id,
                    following_id
                )
            VALUES
                (%s, %s)
            ON CONFLICT
                (follower_id, following_id)
            DO NOTHING
            """,
            (
                user["id"],
                user_id,
            ),
        )

        conn.commit()

    return {
        "ok": True,
        "following": True,
    }


@app.delete("/api/users/{user_id}/follow")
def unfollow_user(
    user_id: int,
    authorization: str | None = Header(default=None),
    msafiri_token: str | None = Cookie(default=None),
):

    user = require_user(
        authorization,
        msafiri_token,
    )

    with db() as conn:

        conn.execute(
            """
            DELETE FROM followers
            WHERE follower_id = %s
              AND following_id = %s
            """,
            (
                user["id"],
                user_id,
            ),
        )

        conn.commit()

    return {
        "ok": True,
        "following": False,
    }


# ============================================================
# CHAT USER SEARCH
# ============================================================

@app.get("/api/users/search")
def search_users(
    q: str = Query(min_length=1),
    limit: int = Query(default=30, ge=1, le=100),
    authorization: str | None = Header(default=None),
    msafiri_token: str | None = Cookie(default=None),
):

    require_user(
        authorization,
        msafiri_token,
    )

    query = q.strip()

    with db() as conn:

        users = conn.execute(
            """
            SELECT
                id,
                name,
                email,
                bio,
                avatar
            FROM users
            WHERE deleted_at IS NULL
              AND (
                    name ILIKE %s
                    OR email ILIKE %s
              )
            ORDER BY name ASC
            LIMIT %s
            """,
            (
                f"%{query}%",
                f"%{query}%",
                limit,
            ),
        ).fetchall()

    return {
        "ok": True,
        "users": users,
    }


# ============================================================
# SEND MESSAGE
# ============================================================

@app.post("/api/messages")
def send_message(
    data: MessageRequest,
    authorization: str | None = Header(default=None),
    msafiri_token: str | None = Cookie(default=None),
):

    user = require_user(
        authorization,
        msafiri_token,
    )

    text = clean_text(data.text, 10000)

    if not text:
        raise HTTPException(
            status_code=400,
            detail="Message cannot be empty.",
        )

    if user["id"] == data.receiver_id:
        raise HTTPException(
            status_code=400,
            detail="You cannot message yourself.",
        )

    with db() as conn:

        receiver = conn.execute(
            """
            SELECT id
            FROM users
            WHERE id = %s
              AND deleted_at IS NULL
            """,
            (data.receiver_id,),
        ).fetchone()

        if not receiver:
            raise HTTPException(
                status_code=404,
                detail="Receiver not found.",
            )

        blocked = conn.execute(
            """
            SELECT id
            FROM blocks
            WHERE
                (
                    blocker_id = %s
                    AND blocked_id = %s
                )
                OR
                (
                    blocker_id = %s
                    AND blocked_id = %s
                )
            LIMIT 1
            """,
            (
                user["id"],
                data.receiver_id,
                data.receiver_id,
                user["id"],
            ),
        ).fetchone()

        if blocked:
            raise HTTPException(
                status_code=403,
                detail="Messaging is blocked.",
            )

        message = conn.execute(
            """
            INSERT INTO messages
                (
                    sender_id,
                    receiver_id,
                    text
                )
            VALUES
                (%s, %s, %s)
            RETURNING *
            """,
            (
                user["id"],
                data.receiver_id,
                text,
            ),
        ).fetchone()

        conn.commit()

    return {
        "ok": True,
        "message": message,
    }


# ============================================================
# CHAT HISTORY
# ============================================================

@app.get("/api/messages/{other_user_id}")
def get_messages(
    other_user_id: int,
    limit: int = Query(default=100, ge=1, le=200),
    before_id: int | None = Query(default=None),
    authorization: str | None = Header(default=None),
    msafiri_token: str | None = Cookie(default=None),
):

    user = require_user(
        authorization,
        msafiri_token,
    )

    with db() as conn:

        if before_id:

            messages = conn.execute(
                """
                SELECT *
                FROM messages
                WHERE
                    (
                        sender_id = %s
                        AND receiver_id = %s
                    )
                    OR
                    (
                        sender_id = %s
                        AND receiver_id = %s
                    )
                AND id < %s
                ORDER BY id DESC
                LIMIT %s
                """,
                (
                    user["id"],
                    other_user_id,
                    other_user_id,
                    user["id"],
                    before_id,
                    limit,
                ),
            ).fetchall()

        else:

            messages = conn.execute(
                """
                SELECT *
                FROM messages
                WHERE
                    (
                        sender_id = %s
                        AND receiver_id = %s
                    )
                    OR
                    (
                        sender_id = %s
                        AND receiver_id = %s
                    )
                ORDER BY id DESC
                LIMIT %s
                """,
                (
                    user["id"],
                    other_user_id,
                    other_user_id,
                    user["id"],
                    limit,
                ),
            ).fetchall()

        conn.execute(
            """
            UPDATE messages
            SET read = TRUE
            WHERE sender_id = %s
              AND receiver_id = %s
              AND read = FALSE
            """,
            (
                other_user_id,
                user["id"],
            ),
        )

        conn.commit()

    messages.reverse()

    return {
        "ok": True,
        "messages": messages,
    }


# ============================================================
# VOICE NOTE
# ============================================================

@app.post("/api/messages/voice")
async def send_voice_note(
    receiver_id: int = Form(...),
    file: UploadFile = File(...),
    authorization: str | None = Header(default=None),
    msafiri_token: str | None = Cookie(default=None),
):

    user = require_user(
        authorization,
        msafiri_token,
    )

    content_type = file.content_type or ""

    allowed_audio = (
        content_type.startswith("audio/")
        or content_type in {
            "application/ogg",
            "application/octet-stream",
        }
    )

    if not allowed_audio:
        raise HTTPException(
            status_code=400,
            detail="File must be an audio recording.",
        )

    filename = safe_filename(
        file.filename or ".webm"
    )

    destination = VOICE_UPLOAD_DIR / filename

    content = await file.read()

    if len(content) > 50 * 1024 * 1024:
        raise HTTPException(
            status_code=400,
            detail="Voice note is too large.",
        )

    destination.write_bytes(content)

    voice_url = f"/uploads/voice/{filename}"

    with db() as conn:

        receiver = conn.execute(
            """
            SELECT id
            FROM users
            WHERE id = %s
              AND deleted_at IS NULL
            """,
            (receiver_id,),
        ).fetchone()

        if not receiver:
            raise HTTPException(
                status_code=404,
                detail="Receiver not found.",
            )

        message = conn.execute(
            """
            INSERT INTO messages
                (
                    sender_id,
                    receiver_id,
                    voice_url,
                    media_type
                )
            VALUES
                (%s, %s, %s, 'voice')
            RETURNING *
            """,
            (
                user["id"],
                receiver_id,
                voice_url,
            ),
        ).fetchone()

        conn.commit()

    return {
        "ok": True,
        "message": message,
        "voice_url": voice_url,
    }


# ============================================================
# CHAT WALLPAPER UPLOAD
# ============================================================

@app.post("/api/chats/{chat_user_id}/wallpaper")
async def upload_chat_wallpaper(
    chat_user_id: int,
    file: UploadFile = File(...),
    authorization: str | None = Header(default=None),
    msafiri_token: str | None = Cookie(default=None),
):

    user = require_user(
        authorization,
        msafiri_token,
    )

    content_type = file.content_type or ""

    if not content_type.startswith("image/"):
        raise HTTPException(
            status_code=400,
            detail="Wallpaper must be an image.",
        )

    filename = safe_filename(
        file.filename or ""
    )

    destination = WALLPAPER_UPLOAD_DIR / filename

    content = await file.read()

    if len(content) > 15 * 1024 * 1024:
        raise HTTPException(
            status_code=400,
            detail="Wallpaper is too large. Maximum 15MB.",
        )

    destination.write_bytes(content)

    wallpaper_url = (
        f"/uploads/wallpapers/{filename}"
    )

    with db() as conn:

        target = conn.execute(
            """
            SELECT id
            FROM users
            WHERE id = %s
              AND deleted_at IS NULL
            """,
            (chat_user_id,),
        ).fetchone()

        if not target:
            raise HTTPException(
                status_code=404,
                detail="Chat user not found.",
            )

        conn.execute(
            """
            INSERT INTO chat_settings
                (
                    user_id,
                    chat_user_id,
                    wallpaper_url,
                    updated_at
                )
            VALUES
                (
                    %s,
                    %s,
                    %s,
                    CURRENT_TIMESTAMP
                )
            ON CONFLICT
                (user_id, chat_user_id)
            DO UPDATE SET
                wallpaper_url = EXCLUDED.wallpaper_url,
                updated_at = CURRENT_TIMESTAMP
            """,
            (
                user["id"],
                chat_user_id,
                wallpaper_url,
            ),
        )

        conn.commit()

    return {
        "ok": True,
        "wallpaper_url": wallpaper_url,
    }


# ============================================================
# GET CHAT SETTINGS
# ============================================================

@app.get("/api/chats/{chat_user_id}/settings")
def get_chat_settings(
    chat_user_id: int,
    authorization: str | None = Header(default=None),
    msafiri_token: str | None = Cookie(default=None),
):

    user = require_user(
        authorization,
        msafiri_token,
    )

    with db() as conn:

        settings = conn.execute(
            """
            SELECT
                wallpaper_url,
                muted,
                pinned,
                blocked,
                updated_at
            FROM chat_settings
            WHERE user_id = %s
              AND chat_user_id = %s
            LIMIT 1
            """,
            (
                user["id"],
                chat_user_id,
            ),
        ).fetchone()

    if not settings:

        settings = {
            "wallpaper_url": None,
            "muted": False,
            "pinned": False,
            "blocked": False,
            "updated_at": None,
        }

    return {
        "ok": True,
        "settings": settings,
    }


# ============================================================
# UPDATE CHAT SETTINGS
# ============================================================

@app.patch("/api/chats/{chat_user_id}/settings")
def update_chat_settings(
    chat_user_id: int,
    data: ChatSettingsRequest,
    authorization: str | None = Header(default=None),
    msafiri_token: str | None = Cookie(default=None),
):

    user = require_user(
        authorization,
        msafiri_token,
    )

    with db() as conn:

        target = conn.execute(
            """
            SELECT id
            FROM users
            WHERE id = %s
              AND deleted_at IS NULL
            """,
            (chat_user_id,),
        ).fetchone()

        if not target:
            raise HTTPException(
                status_code=404,
                detail="Chat user not found.",
            )

        current = conn.execute(
            """
            SELECT *
            FROM chat_settings
            WHERE user_id = %s
              AND chat_user_id = %s
            LIMIT 1
            """,
            (
                user["id"],
                chat_user_id,
            ),
        ).fetchone()

        muted = (
            data.muted
            if data.muted is not None
            else (
                current["muted"]
                if current
                else False
            )
        )

        pinned = (
            data.pinned
            if data.pinned is not None
            else (
                current["pinned"]
                if current
                else False
            )
        )

        blocked = (
            data.blocked
            if data.blocked is not None
            else (
                current["blocked"]
                if current
                else False
            )
        )

        wallpaper = (
            current["wallpaper_url"]
            if current
            else None
        )

        settings = conn.execute(
            """
            INSERT INTO chat_settings
                (
                    user_id,
                    chat_user_id,
                    wallpaper_url,
                    muted,
                    pinned,
                    blocked,
                    updated_at
                )
            VALUES
                (%s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)

            ON CONFLICT
                (user_id, chat_user_id)

            DO UPDATE SET
                muted = EXCLUDED.muted,
                pinned = EXCLUDED.pinned,
                blocked = EXCLUDED.blocked,
                updated_at = CURRENT_TIMESTAMP

            RETURNING *
            """,
            (
                user["id"],
                chat_user_id,
                wallpaper,
                muted,
                pinned,
                blocked,
            ),
        ).fetchone()

        conn.commit()

    return {
        "ok": True,
        "settings": settings,
    }


# ============================================================
# CLEAR CHAT
# ============================================================

@app.delete("/api/chats/{chat_user_id}")
def clear_chat(
    chat_user_id: int,
    authorization: str | None = Header(default=None),
    msafiri_token: str | None = Cookie(default=None),
):

    user = require_user(
        authorization,
        msafiri_token,
    )

    with db() as conn:

        conn.execute(
            """
            UPDATE messages
            SET deleted_for_sender = TRUE
            WHERE sender_id = %s
              AND receiver_id = %s
            """,
            (
                user["id"],
                chat_user_id,
            ),
        )

        conn.execute(
            """
            UPDATE messages
            SET deleted_for_receiver = TRUE
            WHERE sender_id = %s
              AND receiver_id = %s
            """,
            (
                chat_user_id,
                user["id"],
            ),
        )

        conn.commit()

    return {
        "ok": True,
        "message": "Chat cleared for this account.",
    }


# ============================================================
# BLOCK USER
# ============================================================

@app.post("/api/users/{user_id}/block")
def block_user(
    user_id: int,
    authorization: str | None = Header(default=None),
    msafiri_token: str | None = Cookie(default=None),
):

    user = require_user(
        authorization,
        msafiri_token,
    )

    if user["id"] == user_id:
        raise HTTPException(
            status_code=400,
            detail="You cannot block yourself.",
        )

    with db() as conn:

        target = conn.execute(
            """
            SELECT id
            FROM users
            WHERE id = %s
              AND deleted_at IS NULL
            """,
            (user_id,),
        ).fetchone()

        if not target:
            raise HTTPException(
                status_code=404,
                detail="User not found.",
            )

        conn.execute(
            """
            INSERT INTO blocks
                (
                    blocker_id,
                    blocked_id
                )
            VALUES
                (%s, %s)
            ON CONFLICT
                (blocker_id, blocked_id)
            DO NOTHING
            """,
            (
                user["id"],
                user_id,
            ),
        )

        conn.commit()

    return {
        "ok": True,
        "blocked": True,
    }


# ============================================================
# UNBLOCK
# ============================================================

@app.delete("/api/users/{user_id}/block")
def unblock_user(
    user_id: int,
    authorization: str | None = Header(default=None),
    msafiri_token: str | None = Cookie(default=None),
):

    user = require_user(
        authorization,
        msafiri_token,
    )

    with db() as conn:

        conn.execute(
            """
            DELETE FROM blocks
            WHERE blocker_id = %s
              AND blocked_id = %s
            """,
            (
                user["id"],
                user_id,
            ),
        )

        conn.commit()

    return {
        "ok": True,
        "blocked": False,
    }


# ============================================================
# REPORT USER
# ============================================================

@app.post("/api/users/{user_id}/report")
def report_user(
    user_id: int,
    data: ReportRequest,
    authorization: str | None = Header(default=None),
    msafiri_token: str | None = Cookie(default=None),
):

    user = require_user(
        authorization,
        msafiri_token,
    )

    reason = clean_text(
        data.reason,
        1000,
    )

    if not reason:
        raise HTTPException(
            status_code=400,
            detail="Report reason is required.",
        )

    with db() as conn:

        conn.execute(
            """
            INSERT INTO reports
                (
                    reporter_id,
                    reported_user_id,
                    reason
                )
            VALUES
                (%s, %s, %s)
            """,
            (
                user["id"],
                user_id,
                reason,
            ),
        )

        conn.commit()

    return {
        "ok": True,
        "message": "Report submitted.",
    }


# ============================================================
# REPORT POST
# ============================================================

@app.post("/api/posts/{post_id}/report")
def report_post(
    post_id: int,
    data: ReportRequest,
    authorization: str | None = Header(default=None),
    msafiri_token: str | None = Cookie(default=None),
):

    user = require_user(
        authorization,
        msafiri_token,
    )

    reason = clean_text(
        data.reason,
        1000,
    )

    if not reason:
        raise HTTPException(
            status_code=400,
            detail="Report reason is required.",
        )

    with db() as conn:

        conn.execute(
            """
            INSERT INTO reports
                (
                    reporter_id,
                    post_id,
                    reason
                )
            VALUES
                (%s, %s, %s)
            """,
            (
                user["id"],
                post_id,
                reason,
            ),
        )

        conn.commit()

    return {
        "ok": True,
        "message": "Report submitted.",
    }


# ============================================================
# LIVEKIT CALL TOKEN
# ============================================================

@app.post("/api/calls/token")
def create_call_token(
    data: CallRequest,
    authorization: str | None = Header(default=None),
    msafiri_token: str | None = Cookie(default=None),
):

    user = require_user(
        authorization,
        msafiri_token,
    )

    call_type = data.call_type.lower().strip()

    if call_type not in {
        "voice",
        "video",
    }:
        raise HTTPException(
            status_code=400,
            detail="call_type must be voice or video.",
        )

    if not (
        LIVEKIT_URL
        and LIVEKIT_API_KEY
        and LIVEKIT_API_SECRET
    ):
        raise HTTPException(
            status_code=503,
            detail="LiveKit is not configured on the server.",
        )

    if user["id"] == data.receiver_id:
        raise HTTPException(
            status_code=400,
            detail="You cannot call yourself.",
        )

    with db() as conn:

        receiver = conn.execute(
            """
            SELECT
                id,
                name,
                avatar
            FROM users
            WHERE id = %s
              AND deleted_at IS NULL
            """,
            (data.receiver_id,),
        ).fetchone()

        if not receiver:
            raise HTTPException(
                status_code=404,
                detail="Receiver not found.",
            )

        blocked = conn.execute(
            """
            SELECT id
            FROM blocks
            WHERE
                (
                    blocker_id = %s
                    AND blocked_id = %s
                )
                OR
                (
                    blocker_id = %s
                    AND blocked_id = %s
                )
            LIMIT 1
            """,
            (
                user["id"],
                data.receiver_id,
                data.receiver_id,
                user["id"],
            ),
        ).fetchone()

        if blocked:
            raise HTTPException(
                status_code=403,
                detail="Calling is blocked.",
            )

        call_id = uuid.uuid4()

        room_name = (
            f"msg-{call_id.hex}"
        )

        conn.execute(
            """
            INSERT INTO call_sessions
                (
                    id,
                    caller_id,
                    receiver_id,
                    room_name,
                    call_type,
                    status
                )
            VALUES
                (
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    'calling'
                )
            """,
            (
                call_id,
                user["id"],
                data.receiver_id,
                room_name,
                call_type,
            ),
        )

        conn.commit()

    # --------------------------------------------------------
    # LIVEKIT TOKEN
    # --------------------------------------------------------

    identity = f"user-{user['id']}"

    token = (
        api.AccessToken(
            LIVEKIT_API_KEY,
            LIVEKIT_API_SECRET,
        )
        .with_identity(identity)
        .with_name(user["name"])
        .with_grants(
            api.VideoGrants(
                room_join=True,
                room=room_name,
            )
        )
        .to_jwt()
    )

    return {
        "ok": True,
        "call_id": str(call_id),
        "room": room_name,
        "token": token,
        "livekit_url": LIVEKIT_URL,
        "call_type": call_type,
        "caller": {
            "id": user["id"],
            "name": user["name"],
            "avatar": user["avatar"],
        },
        "receiver": receiver,
    }


# ============================================================
# UPDATE CALL STATUS
# ============================================================

@app.patch("/api/calls/{call_id}")
def update_call(
    call_id: str,
    status: str = Query(...),
    authorization: str | None = Header(default=None),
    msafiri_token: str | None = Cookie(default=None),
):

    user = require_user(
        authorization,
        msafiri_token,
    )

    allowed = {
        "calling",
        "ringing",
        "connected",
        "ended",
        "rejected",
        "missed",
    }

    status = status.lower().strip()

    if status not in allowed:
        raise HTTPException(
            status_code=400,
            detail="Invalid call status.",
        )

    try:
        call_uuid = uuid.UUID(call_id)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid call ID.",
        )

    with db() as conn:

        call = conn.execute(
            """
            SELECT *
            FROM call_sessions
            WHERE id = %s
              AND (
                    caller_id = %s
                    OR receiver_id = %s
                  )
            LIMIT 1
            """,
            (
                call_uuid,
                user["id"],
                user["id"],
            ),
        ).fetchone()

        if not call:
            raise HTTPException(
                status_code=404,
                detail="Call not found.",
            )

        if status == "connected":

            updated = conn.execute(
                """
                UPDATE call_sessions
                SET
                    status = %s,
                    started_at = COALESCE(
                        started_at,
                        CURRENT_TIMESTAMP
                    )
                WHERE id = %s
                RETURNING *
                """,
                (
                    status,
                    call_uuid,
                ),
            ).fetchone()

        elif status in {
            "ended",
            "rejected",
            "missed",
        }:

            updated = conn.execute(
                """
                UPDATE call_sessions
                SET
                    status = %s,
                    ended_at = CURRENT_TIMESTAMP
                WHERE id = %s
                RETURNING *
                """,
                (
                    status,
                    call_uuid,
                ),
            ).fetchone()

        else:

            updated = conn.execute(
                """
                UPDATE call_sessions
                SET status = %s
                WHERE id = %s
                RETURNING *
                """,
                (
                    status,
                    call_uuid,
                ),
            ).fetchone()

        conn.commit()

    return {
        "ok": True,
        "call": updated,
    }


# ============================================================
# CALL HISTORY
# ============================================================

@app.get("/api/calls/history")
def call_history(
    limit: int = Query(default=50, ge=1, le=100),
    authorization: str | None = Header(default=None),
    msafiri_token: str | None = Cookie(default=None),
):

    user = require_user(
        authorization,
        msafiri_token,
    )

    with db() as conn:

        calls = conn.execute(
            """
            SELECT
                c.*,

                caller.name AS caller_name,
                caller.avatar AS caller_avatar,

                receiver.name AS receiver_name,
                receiver.avatar AS receiver_avatar

            FROM call_sessions c

            JOIN users caller
                ON caller.id = c.caller_id

            JOIN users receiver
                ON receiver.id = c.receiver_id

            WHERE
                c.caller_id = %s
                OR c.receiver_id = %s

            ORDER BY c.created_at DESC

            LIMIT %s
            """,
            (
                user["id"],
                user["id"],
                limit,
            ),
        ).fetchall()

    return {
        "ok": True,
        "calls": calls,
    }


# ============================================================
# RUN DIRECTLY
# ============================================================

if __name__ == "__main__":

    import uvicorn

    port = int(
        os.getenv(
            "PORT",
            "8000",
        )
    )

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=port,
        reload=False,
    )
