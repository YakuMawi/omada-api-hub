"""
Helpers base de données et SMTP partagés par app.py et les blueprints.
"""
import json
import smtplib
import sqlite3
from email.mime.text import MIMEText

from flask import g, session

from config import DB_FILE


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_FILE)
        g.db.row_factory = sqlite3.Row
    return g.db


def init_db():
    """Crée les tables et migre les credentials JSON existants au premier démarrage."""
    import json as _json
    import os

    from config import CREDENTIALS_FILE

    conn = sqlite3.connect(DB_FILE)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS controllers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            label TEXT DEFAULT '',
            mode TEXT DEFAULT 'msp',
            base_url TEXT DEFAULT '',
            omadac_id TEXT DEFAULT '',
            client_id TEXT DEFAULT '',
            client_secret TEXT DEFAULT '',
            ac_client_id TEXT DEFAULT '',
            ac_client_secret TEXT DEFAULT '',
            omada_username TEXT DEFAULT '',
            omada_password TEXT DEFAULT '',
            customer_apps TEXT DEFAULT '{}',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS app_settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL DEFAULT ''
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS password_resets (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            code       TEXT NOT NULL,
            expires_at REAL NOT NULL,
            used       INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    try:
        conn.execute("ALTER TABLE users ADD COLUMN email TEXT DEFAULT ''")
    except Exception:
        pass
    conn.commit()

    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        env_user = os.environ.get("APP_USERNAME", "")
        env_hash = os.environ.get("APP_PASSWORD_HASH", "")
        if env_user and env_hash:
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (env_user, env_hash),
            )
            conn.commit()
            uid = conn.execute("SELECT id FROM users WHERE username=?", (env_user,)).fetchone()[0]
            try:
                with open(CREDENTIALS_FILE) as f:
                    profiles = _json.load(f)
                if isinstance(profiles, dict):
                    profiles = [profiles] if profiles.get("base_url") else []
                for p in profiles:
                    ca = _json.dumps(p.get("customer_apps") or {})
                    conn.execute(
                        """INSERT INTO controllers
                           (user_id, label, mode, base_url, omadac_id, client_id,
                            client_secret, ac_client_id, ac_client_secret,
                            omada_username, omada_password, customer_apps)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (uid, p.get("label", ""), p.get("mode", "msp"), p.get("base_url", ""),
                         p.get("omadac_id", ""), p.get("client_id", ""), p.get("client_secret", ""),
                         p.get("ac_client_id", ""), p.get("ac_client_secret", ""),
                         p.get("username", ""), p.get("password", ""), ca),
                    )
                conn.commit()
            except Exception:
                pass
    conn.close()


def save_credentials(data):
    """Sauvegarde les profils contrôleur pour l'utilisateur courant."""
    uid = session.get("user_id")
    if not uid:
        return
    db = get_db()
    db.execute("DELETE FROM controllers WHERE user_id=?", (uid,))
    for p in data:
        ca = json.dumps(p.get("customer_apps") or {})
        db.execute(
            """INSERT INTO controllers
               (user_id, label, mode, base_url, omadac_id, client_id,
                client_secret, ac_client_id, ac_client_secret,
                omada_username, omada_password, customer_apps)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (uid, p.get("label", ""), p.get("mode", "msp"), p.get("base_url", ""),
             p.get("omadac_id", ""), p.get("client_id", ""), p.get("client_secret", ""),
             p.get("ac_client_id", ""), p.get("ac_client_secret", ""),
             p.get("username", ""), p.get("password", ""), ca),
        )
    db.commit()


def load_credentials():
    """Charge les profils contrôleur pour l'utilisateur courant."""
    uid = session.get("user_id")
    if not uid:
        return []
    rows = get_db().execute(
        "SELECT * FROM controllers WHERE user_id=? ORDER BY id", (uid,)
    ).fetchall()
    result = []
    for r in rows:
        p = dict(r)
        p["username"] = p.pop("omada_username", "")
        p["password"] = p.pop("omada_password", "")
        p["customer_apps"] = json.loads(p.get("customer_apps") or "{}")
        result.append(p)
    return result


# ---------------------------------------------------------------------------
# SMTP
# ---------------------------------------------------------------------------

def get_smtp_config():
    """Retourne la config SMTP depuis app_settings, ou {} si non configuré."""
    try:
        rows = get_db().execute("SELECT key, value FROM app_settings").fetchall()
        return {r[0]: r[1] for r in rows}
    except Exception:
        return {}


def smtp_is_configured():
    cfg = get_smtp_config()
    return bool(cfg.get("smtp_host") and cfg.get("smtp_user"))


def send_reset_email(to_email, code):
    """Envoie un code de réinitialisation par email. Retourne True si succès."""
    cfg = get_smtp_config()
    host      = cfg.get("smtp_host", "")
    port      = int(cfg.get("smtp_port", 587))
    user      = cfg.get("smtp_user", "")
    password  = cfg.get("smtp_password", "")
    from_addr = cfg.get("smtp_from") or user
    use_tls   = cfg.get("smtp_tls", "1") not in ("0", "false", "False", "")
    body = (
        f"Bonjour,\n\n"
        f"Votre code de réinitialisation de mot de passe est :\n\n"
        f"    {code}\n\n"
        f"Ce code est valable 15 minutes.\n\n"
        f"Si vous n'avez pas demandé ce code, ignorez cet email.\n\n"
        f"— Omada API Hub"
    )
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = "Réinitialisation de mot de passe — Omada API Hub"
    msg["From"]    = from_addr
    msg["To"]      = to_email
    try:
        if port == 465:
            srv = smtplib.SMTP_SSL(host, port, timeout=10)
        else:
            srv = smtplib.SMTP(host, port, timeout=10)
            if use_tls:
                srv.starttls()
        srv.login(user, password)
        srv.sendmail(from_addr, [to_email], msg.as_string())
        srv.quit()
        return True
    except Exception:
        return False
