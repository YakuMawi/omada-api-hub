"""
Blueprint auth — authentification applicative.

Routes : /login, /app-logout, /register, /forgot-password, /reset-password

Aucune logique Omada ici : ce module gère uniquement les comptes locaux
(users.db), la protection brute-force, et la réinitialisation de mot de passe.
"""
import secrets
import sqlite3
import time
from urllib.parse import urlparse

import bcrypt
from flask import (
    Blueprint,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from config import DB_FILE
from db import get_smtp_config, send_reset_email, smtp_is_configured

auth_bp = Blueprint("auth", __name__)

# ---------------------------------------------------------------------------
# Protection brute-force (en mémoire, propre à ce module)
# ---------------------------------------------------------------------------

_login_attempts: dict[str, list[float]] = {}
_MAX_ATTEMPTS    = 5
_LOCKOUT_SECONDS = 300  # 5 minutes


def _is_locked_out(ip: str) -> bool:
    now = time.time()
    attempts = [t for t in _login_attempts.get(ip, []) if now - t < _LOCKOUT_SECONDS]
    _login_attempts[ip] = attempts
    return len(attempts) >= _MAX_ATTEMPTS


def _record_attempt(ip: str):
    _login_attempts.setdefault(ip, []).append(time.time())


def _clear_attempts(ip: str):
    _login_attempts.pop(ip, None)


def get_client_ip() -> str:
    """IP réelle du client, en tenant compte des reverse-proxies."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def safe_redirect_url(next_url: str, fallback: str) -> str:
    """Valide que next_url est une URL relative pour éviter l'open redirect."""
    if not next_url:
        return fallback
    parsed = urlparse(next_url)
    if parsed.scheme or parsed.netloc:
        return fallback
    return next_url


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@auth_bp.route("/login", methods=["GET", "POST"])
def app_login_page():
    if session.get("app_authenticated"):
        return redirect(url_for("login_page"))

    error = None

    if request.method == "POST":
        ip = get_client_ip()

        if _is_locked_out(ip):
            error = "Trop de tentatives. Réessayez dans 5 minutes."
        else:
            token_form    = request.form.get("csrf_token", "")
            token_session = session.get("csrf_token", "")
            if not token_form or not token_session or not secrets.compare_digest(token_form, token_session):
                error = "Requête invalide. Veuillez réessayer."
            else:
                username = request.form.get("username", "").strip()
                password = request.form.get("password", "")

                valid   = False
                user_id = None
                db = sqlite3.connect(DB_FILE)
                row = db.execute(
                    "SELECT id, password_hash FROM users WHERE username=?", (username,)
                ).fetchone()
                db.close()
                if row:
                    try:
                        valid = bcrypt.checkpw(password.encode(), row[1].encode())
                        if valid:
                            user_id = row[0]
                    except Exception:
                        valid = False

                if valid and user_id:
                    _clear_attempts(ip)
                    session.permanent = True
                    session["app_authenticated"] = True
                    session["user_id"]            = user_id
                    session["app_username"]        = username
                    next_url = safe_redirect_url(
                        request.form.get("next", ""), url_for("login_page")
                    )
                    return redirect(next_url)
                else:
                    _record_attempt(ip)
                    remaining = _MAX_ATTEMPTS - len(_login_attempts.get(ip, []))
                    if remaining > 0:
                        error = f"Identifiants incorrects. {remaining} tentative(s) restante(s)."
                    else:
                        error = "Trop de tentatives. Réessayez dans 5 minutes."

    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    next_url = safe_redirect_url(request.args.get("next", ""), "")
    return render_template("app_login.html", error=error, next=next_url,
                           csrf_token=session["csrf_token"])


@auth_bp.route("/app-logout")
def app_logout():
    session.clear()
    return redirect(url_for("auth.app_login_page"))


@auth_bp.route("/register", methods=["GET", "POST"])
def app_register_page():
    if session.get("app_authenticated"):
        return redirect(url_for("login_page"))

    error   = None
    success = None
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)

    if request.method == "POST":
        token_form    = request.form.get("csrf_token", "")
        token_session = session.get("csrf_token", "")
        if not token_form or not token_session or not secrets.compare_digest(token_form, token_session):
            error = "Requête invalide. Veuillez réessayer."
        else:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            confirm  = request.form.get("confirm_password", "")
            email    = request.form.get("email", "").strip().lower()
            if not username or not password:
                error = "Nom d'utilisateur et mot de passe requis."
            elif len(username) < 3:
                error = "Nom d'utilisateur trop court (3 caractères minimum)."
            elif len(password) < 8:
                error = "Mot de passe trop court (8 caractères minimum)."
            elif password != confirm:
                error = "Les mots de passe ne correspondent pas."
            elif email and "@" not in email:
                error = "Adresse email invalide."
            else:
                pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
                try:
                    db = sqlite3.connect(DB_FILE)
                    db.execute(
                        "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                        (username, pw_hash, email),
                    )
                    db.commit()
                    db.close()
                    success = "Compte créé avec succès. Vous pouvez vous connecter."
                except sqlite3.IntegrityError:
                    error = "Ce nom d'utilisateur est déjà pris."

    return render_template(
        "register.html",
        error=error,
        success=success,
        csrf_token=session["csrf_token"],
    )


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def app_forgot_password():
    if session.get("app_authenticated"):
        return redirect(url_for("login_page"))
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)

    error = None
    info  = None

    if request.method == "POST":
        ip = get_client_ip()
        if _is_locked_out(ip):
            error = "Trop de tentatives. Réessayez dans 5 minutes."
        else:
            token_form    = request.form.get("csrf_token", "")
            token_session = session.get("csrf_token", "")
            if not token_form or not token_session or not secrets.compare_digest(token_form, token_session):
                error = "Requête invalide. Veuillez réessayer."
            else:
                username = request.form.get("username", "").strip()
                email    = request.form.get("email", "").strip().lower()
                db = sqlite3.connect(DB_FILE)
                row = db.execute(
                    "SELECT id, email FROM users WHERE username=?", (username,)
                ).fetchone()
                db.close()
                match = row and row[1] and row[1].lower() == email

                if match:
                    _clear_attempts(ip)
                    if smtp_is_configured():
                        code    = f"{secrets.randbelow(1_000_000):06d}"
                        expires = time.time() + 900
                        db2 = sqlite3.connect(DB_FILE)
                        db2.execute("DELETE FROM password_resets WHERE user_id=?", (row[0],))
                        db2.execute(
                            "INSERT INTO password_resets (user_id, code, expires_at) VALUES (?,?,?)",
                            (row[0], code, expires),
                        )
                        db2.commit()
                        db2.close()
                        send_reset_email(email, code)
                        session["reset_uid"]  = row[0]
                        session["reset_smtp"] = True
                    else:
                        session["reset_uid"]  = row[0]
                        session["reset_smtp"] = False
                    return redirect(url_for("auth.app_reset_password"))
                else:
                    _record_attempt(ip)
                    info = "Si ce compte existe et que l'email correspond, vous pouvez réinitialiser votre mot de passe."

    return render_template(
        "forgot_password.html",
        error=error,
        info=info,
        csrf_token=session["csrf_token"],
        smtp_active=smtp_is_configured(),
    )


@auth_bp.route("/reset-password", methods=["GET", "POST"])
def app_reset_password():
    if session.get("app_authenticated"):
        return redirect(url_for("login_page"))
    if "reset_uid" not in session:
        return redirect(url_for("auth.app_forgot_password"))
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)

    uid      = session["reset_uid"]
    use_smtp = session.get("reset_smtp", False)
    code_ok  = session.get("reset_code_ok", False)
    error    = None

    # Étape A (SMTP seulement) : vérification du code
    if use_smtp and not code_ok and request.method == "POST":
        token_form    = request.form.get("csrf_token", "")
        token_session = session.get("csrf_token", "")
        if not token_form or not secrets.compare_digest(token_form, token_session):
            error = "Requête invalide."
        else:
            submitted_code = request.form.get("code", "").strip()
            db = sqlite3.connect(DB_FILE)
            row = db.execute(
                "SELECT id FROM password_resets WHERE user_id=? AND code=? AND used=0",
                (uid, submitted_code),
            ).fetchone()
            if row:
                expires = db.execute(
                    "SELECT expires_at FROM password_resets WHERE id=?", (row[0],)
                ).fetchone()
                db.close()
                if expires and time.time() < expires[0]:
                    session["reset_code_ok"] = True
                    code_ok = True
                else:
                    error = "Ce code a expiré. Recommencez depuis le début."
                    session.pop("reset_uid", None)
                    session.pop("reset_smtp", None)
            else:
                db.close()
                error = "Code incorrect."

    # Étape B : nouveau mot de passe
    elif (not use_smtp or code_ok) and request.method == "POST" and request.form.get("new_password"):
        token_form    = request.form.get("csrf_token", "")
        token_session = session.get("csrf_token", "")
        if not token_form or not secrets.compare_digest(token_form, token_session):
            error = "Requête invalide."
        else:
            new_pw  = request.form.get("new_password", "")
            confirm = request.form.get("confirm_password", "")
            if len(new_pw) < 8:
                error = "Mot de passe trop court (8 caractères minimum)."
            elif new_pw != confirm:
                error = "Les mots de passe ne correspondent pas."
            else:
                new_hash = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
                db = sqlite3.connect(DB_FILE)
                db.execute("UPDATE users SET password_hash=? WHERE id=?", (new_hash, uid))
                db.execute("DELETE FROM password_resets WHERE user_id=?", (uid,))
                db.commit()
                db.close()
                session.pop("reset_uid", None)
                session.pop("reset_smtp", None)
                session.pop("reset_code_ok", None)
                return redirect(url_for("auth.app_login_page"))

    return render_template(
        "reset_password.html",
        error=error,
        use_smtp=use_smtp,
        code_ok=code_ok,
        csrf_token=session["csrf_token"],
    )
