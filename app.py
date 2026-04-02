#!/usr/bin/env python3
import os
import secrets
import time
import urllib3
from datetime import timedelta

import bcrypt
import requests as http_requests
from dotenv import load_dotenv

load_dotenv()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from flask import (
    Flask,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from config import CREDENTIALS_FILE, DB_FILE
from db import (
    get_db,
    get_smtp_config,
    init_db,
    load_credentials,
    save_credentials,
    send_reset_email,
    smtp_is_configured,
)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.permanent_session_lifetime = timedelta(
    seconds=int(os.environ.get("SESSION_LIFETIME", 28800))
)

# Routes publiques exemptées de la vérification app_authenticated
# Les routes auth sont dans le blueprint "auth" (préfixe "auth.")
_PUBLIC_ROUTES = {
    "auth.app_login_page", "auth.app_register_page",
    "auth.app_forgot_password", "auth.app_reset_password",
    "auth.app_logout", "static",
}

# ---------------------------------------------------------------------------
# Blueprints
# ---------------------------------------------------------------------------
from blueprints.auth import auth_bp  # noqa: E402
app.register_blueprint(auth_bp)



# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def omada_headers():
    token = session.get("access_token")
    return {
        "Content-Type": "application/json",
        "Authorization": f"AccessToken={token}",
    }


def omada_base():
    return session.get("base_url", "").rstrip("/")


def omada_id():
    return session.get("omadac_id", "")


def is_customer_mode():
    """Check if current session is in Customer mode (vs MSP)."""
    return session.get("mode") == "customer"


def is_standard_mode():
    """Check if current session is in Standard controller mode (non-MSP)."""
    return session.get("mode") == "standard"


def is_direct_site_mode():
    """True when sites are accessible directly (customer or standard mode)."""
    return is_customer_mode() or is_standard_mode()


def msp(path=""):
    """Build MSP API path prefix."""
    return f"/openapi/v1/msp/{omada_id()}{path}"


def std(path=""):
    """Build standard (Customer-level) API path prefix."""
    return f"/openapi/v1/{omada_id()}{path}"


def omada_get(path, params=None):
    return http_requests.get(
        f"{omada_base()}{path}",
        params=params,
        headers=omada_headers(),
        timeout=15,
        verify=False,
    )


def omada_post(path, body=None):
    return http_requests.post(
        f"{omada_base()}{path}",
        json=body,
        headers=omada_headers(),
        timeout=30,
        verify=False,
    )


def omada_delete(path):
    return http_requests.delete(
        f"{omada_base()}{path}",
        headers=omada_headers(),
        timeout=15,
        verify=False,
    )


def omada_put(path, body=None):
    return http_requests.put(
        f"{omada_base()}{path}",
        json=body,
        headers=omada_headers(),
        timeout=30,
        verify=False,
    )


def require_auth(f):
    from functools import wraps

    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("access_token"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Non authentifie"}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)

    return decorated


def require_customer_mode(f):
    from functools import wraps

    @wraps(f)
    def decorated(*args, **kwargs):
        if not is_customer_mode():
            return jsonify({"error": "Disponible uniquement en mode Client"}), 403
        return f(*args, **kwargs)

    return decorated


def require_direct_site_mode(f):
    """Allow access in Customer mode or Standard controller mode."""
    from functools import wraps

    @wraps(f)
    def decorated(*args, **kwargs):
        if not is_direct_site_mode():
            return jsonify({"error": "Disponible uniquement en mode Client ou Standard"}), 403
        return f(*args, **kwargs)

    return decorated


def require_app_login(f):
    from functools import wraps

    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("app_authenticated"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Acces refuse"}), 401
            return redirect(url_for("auth.app_login_page", next=request.path))
        return f(*args, **kwargs)

    return decorated


def refresh_token_if_needed():
    expires_at = session.get("token_expires_at", 0)
    if time.time() < expires_at - 300:
        return True
    refresh_tok = session.get("refresh_token")
    if not refresh_tok:
        return False
    try:
        resp = http_requests.post(
            f"{omada_base()}/openapi/authorize/token",
            params={"grant_type": "refresh_token", "refresh_token": refresh_tok},
            json={
                "client_id": session.get("client_id"),
                "client_secret": session.get("client_secret"),
            },
            timeout=15,
            verify=False,
        )
        if resp.status_code == 200:
            data = resp.json().get("result", {})
            session["access_token"] = data.get("accessToken", "")
            session["refresh_token"] = data.get("refreshToken", refresh_tok)
            session["token_expires_at"] = time.time() + data.get("expiresIn", 3600)
            return True
    except Exception:
        pass
    return False


def get_auth_code_token():
    """Obtain an access token via the Authorization Code flow.

    Required for MSP customer create/delete operations.
    Returns the access token string or raises an exception.
    """
    # Check if we already have a valid auth code token cached
    ac_expires = session.get("ac_token_expires_at", 0)
    ac_token = session.get("ac_access_token", "")
    if ac_token and time.time() < ac_expires - 60:
        return ac_token

    # Try to refresh the auth code token first
    ac_refresh = session.get("ac_refresh_token", "")
    ac_cid_for_refresh = session.get("ac_client_id", "") or session.get("client_id", "")
    ac_csecret_for_refresh = session.get("ac_client_secret", "") or session.get("client_secret", "")
    if ac_refresh:
        try:
            resp = http_requests.post(
                f"{omada_base()}/openapi/authorize/token",
                params={
                    "grant_type": "refresh_token",
                    "refresh_token": ac_refresh,
                    "client_id": ac_cid_for_refresh,
                    "client_secret": ac_csecret_for_refresh,
                },
                timeout=15,
                verify=False,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("errorCode", -1) == 0:
                    result = data.get("result", {})
                    session["ac_access_token"] = result.get("accessToken", "")
                    session["ac_refresh_token"] = result.get("refreshToken", ac_refresh)
                    session["ac_token_expires_at"] = time.time() + result.get("expiresIn", 3600)
                    return session["ac_access_token"]
        except Exception:
            pass

    base_url = omada_base()
    # Use dedicated Auth Code app credentials (fall back to main app if not set)
    ac_cid = session.get("ac_client_id", "") or session.get("client_id", "")
    ac_csecret = session.get("ac_client_secret", "") or session.get("client_secret", "")
    oid = omada_id()
    username = session.get("username", "")
    password = session.get("password", "")

    if not username or not password:
        raise ValueError(
            "Username et password requis pour le mode Authorization Code. "
            "Reconnectez-vous en renseignant vos identifiants."
        )
    if not ac_cid or not ac_csecret:
        raise ValueError(
            "Client ID / Secret de l'app Authorization Code requis. "
            "Reconnectez-vous en renseignant les identifiants de l'app Auth Code."
        )

    # Use a persistent HTTP session to share cookies across the 3 steps
    http_session = http_requests.Session()
    http_session.verify = False

    # Step 1: Login to get csrfToken + sessionId
    login_resp = http_session.post(
        f"{base_url}/openapi/authorize/login",
        params={"client_id": ac_cid, "omadac_id": oid},
        json={"username": username, "password": password},
        timeout=15,
    )
    if login_resp.status_code != 200:
        raise RuntimeError(f"Auth login failed (HTTP {login_resp.status_code})")
    login_data = login_resp.json()
    if login_data.get("errorCode", -1) != 0:
        err_msg = login_data.get("msg", "Unknown")
        if "client" in err_msg.lower() and "invalid" in err_msg.lower():
            raise RuntimeError(
                f"Auth login error: {err_msg}. "
                "Verifiez que l'application OpenAPI MSP est configuree en mode "
                "'Authorization Code' (et non 'Client Credentials' uniquement). "
                "Vous devrez peut-etre creer une nouvelle application OpenAPI."
            )
        raise RuntimeError(f"Auth login error: {err_msg}")

    login_result = login_data.get("result", {})
    csrf_token = login_result.get("csrfToken", "")
    session_id_val = login_result.get("sessionId", "")

    if not csrf_token or not session_id_val:
        raise RuntimeError("Auth login did not return csrfToken/sessionId")

    # Inject session cookie explicitly
    http_session.cookies.set("TPOMADA_SESSIONID", session_id_val)

    # Step 2: Get authorization code
    code_resp = http_session.post(
        f"{base_url}/openapi/authorize/code",
        params={"client_id": ac_cid, "omadac_id": oid, "response_type": "code"},
        headers={"Content-Type": "application/json", "Csrf-Token": csrf_token},
        timeout=15,
    )
    if code_resp.status_code != 200:
        raise RuntimeError(f"Auth code request failed (HTTP {code_resp.status_code})")
    code_data = code_resp.json()
    if code_data.get("errorCode", -1) != 0:
        raise RuntimeError(f"Auth code error: {code_data.get('msg', 'Unknown')}")

    auth_code = code_data.get("result", "")
    if not auth_code:
        raise RuntimeError("Auth code response empty")

    # Step 3: Exchange code for access token
    token_resp = http_session.post(
        f"{base_url}/openapi/authorize/token",
        params={"grant_type": "authorization_code", "code": auth_code},
        json={"client_id": ac_cid, "client_secret": ac_csecret},
        timeout=15,
    )
    if token_resp.status_code != 200:
        raise RuntimeError(f"Auth token exchange failed (HTTP {token_resp.status_code})")
    token_data = token_resp.json()
    if token_data.get("errorCode", -1) != 0:
        raise RuntimeError(f"Auth token error: {token_data.get('msg', 'Unknown')}")

    result = token_data.get("result", {})
    ac_token = result.get("accessToken", "")
    if not ac_token:
        raise RuntimeError("No accessToken in auth code token response")

    # Cache the auth code token
    session["ac_access_token"] = ac_token
    session["ac_refresh_token"] = result.get("refreshToken", "")
    session["ac_token_expires_at"] = time.time() + result.get("expiresIn", 3600)

    return ac_token


def omada_headers_authcode():
    """Headers using Authorization Code token (for customer CRUD)."""
    token = get_auth_code_token()
    return {
        "Content-Type": "application/json",
        "Authorization": f"AccessToken={token}",
    }


def omada_post_authcode(path, body=None):
    """POST using Authorization Code token."""
    return http_requests.post(
        f"{omada_base()}{path}",
        json=body,
        headers=omada_headers_authcode(),
        timeout=30,
        verify=False,
    )


def omada_delete_authcode(path):
    """DELETE using Authorization Code token."""
    return http_requests.delete(
        f"{omada_base()}{path}",
        headers=omada_headers_authcode(),
        timeout=15,
        verify=False,
    )




# ---------------------------------------------------------------------------
# Global auth gate — s'applique à TOUTES les routes sauf les publiques
# ---------------------------------------------------------------------------

@app.before_request
def enforce_app_login():
    if request.endpoint in _PUBLIC_ROUTES:
        return  # page de login et fichiers statiques sont libres
    if not session.get("app_authenticated") or not session.get("user_id"):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Acces refuse"}), 401
        return redirect(url_for("auth.app_login_page", next=request.path))


# ---------------------------------------------------------------------------
# Template context
# ---------------------------------------------------------------------------

@app.context_processor
def inject_mode():
    mode = session.get("mode", "msp")
    return {
        "profile_mode": mode,
        "is_customer_mode": mode == "customer",
        "is_standard_mode": mode == "standard",
        "is_direct_site_mode": mode in ("customer", "standard"),
        "customer_name": session.get("customer_name", ""),
        "controller_id": session.get("omadac_id", ""),
        "app_username": session.get("app_username", ""),
        "has_authcode_creds": bool(
            session.get("username") and session.get("password")
            and (session.get("ac_client_id") or session.get("client_id"))
        ),
    }




# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

@app.route("/")
@require_app_login
def login_page():
    if session.get("access_token"):
        if is_direct_site_mode():
            return redirect(url_for("sites_page"))
        return redirect(url_for("customers_page"))
    return render_template("login.html")


@app.route("/customers")
@require_app_login
@require_auth
def customers_page():
    """MSP view: list all customers. Entry point after MSP login."""
    if is_standard_mode():
        return redirect(url_for("sites_page"))
    return render_template("customers.html")


@app.route("/sites")
@require_app_login
@require_auth
def sites_page():
    # In MSP mode, user must pick a customer first
    if not is_direct_site_mode():
        return redirect(url_for("customers_page"))
    return render_template("sites.html")


@app.route("/sites/create")
@require_app_login
@require_auth
def create_site_page():
    if not is_direct_site_mode():
        return redirect(url_for("customers_page"))
    return render_template("create_site.html")


@app.route("/sites/<site_id>")
@require_app_login
@require_auth
def site_detail_page(site_id):
    return render_template("site_detail.html", site_id=site_id)


# ---------------------------------------------------------------------------
# API : Credentials
# ---------------------------------------------------------------------------

@app.route("/api/credentials", methods=["GET"])
def api_get_credentials():
    profiles = load_credentials()
    return jsonify(profiles)


@app.route("/api/credentials", methods=["POST"])
def api_save_credentials():
    """Add or update an MSP credential profile. Matches by omadac_id."""
    body = request.get_json(silent=True) or {}
    profiles = load_credentials()
    idx = None
    for i, p in enumerate(profiles):
        if p.get("omadac_id") == body.get("omadac_id"):
            idx = i
            break
    if idx is not None:
        # Preserve customer_apps when updating
        if "customer_apps" not in body and "customer_apps" in profiles[idx]:
            body["customer_apps"] = profiles[idx]["customer_apps"]
        profiles[idx] = body
    else:
        profiles.append(body)
    save_credentials(profiles)
    return jsonify({"success": True})


@app.route("/api/credentials/customer-app", methods=["POST"])
def api_save_customer_app():
    """Save customer-level OpenAPI app credentials for a specific customer."""
    body = request.get_json(silent=True) or {}
    msp_omadac_id = session.get("omadac_id", "")
    customer_id = body.get("customer_id", "")
    client_id = body.get("client_id", "")
    client_secret = body.get("client_secret", "")

    if not all([customer_id, client_id, client_secret]):
        return jsonify({"error": "Champs obligatoires manquants"}), 400

    profiles = load_credentials()
    for p in profiles:
        if p.get("omadac_id") == msp_omadac_id:
            if "customer_apps" not in p:
                p["customer_apps"] = {}
            p["customer_apps"][customer_id] = {
                "client_id": client_id,
                "client_secret": client_secret,
                "controller_id": body.get("controller_id", ""),
            }
            save_credentials(profiles)
            return jsonify({"success": True})
    return jsonify({"error": "Profil MSP non trouve"}), 404


@app.route("/api/credentials/customer-app/<customer_id>", methods=["GET"])
def api_get_customer_app(customer_id):
    """Get saved customer-level credentials for a specific customer."""
    msp_omadac_id = session.get("omadac_id", "")
    profiles = load_credentials()
    for p in profiles:
        if p.get("omadac_id") == msp_omadac_id:
            apps = p.get("customer_apps", {})
            if customer_id in apps:
                return jsonify(apps[customer_id])
    return jsonify({}), 204


@app.route("/api/credentials/<int:index>", methods=["DELETE"])
def api_delete_credential(index):
    """Delete a single credential profile by index."""
    profiles = load_credentials()
    if 0 <= index < len(profiles):
        profiles.pop(index)
        save_credentials(profiles)
    return jsonify({"success": True})


@app.route("/api/credentials", methods=["DELETE"])
def api_delete_credentials():
    """Delete all credential profiles."""
    try:
        os.remove(CREDENTIALS_FILE)
    except OSError:
        pass
    return jsonify({"success": True})


# ---------------------------------------------------------------------------
# API : Authentication
# ---------------------------------------------------------------------------

@app.route("/api/login", methods=["POST"])
def api_login():
    body = request.get_json(silent=True) or {}
    base_url = body.get("base_url", "").rstrip("/")
    omadac_id = body.get("omadac_id", "")
    client_id = body.get("client_id", "")
    client_secret = body.get("client_secret", "")
    username = body.get("username", "")
    password = body.get("password", "")
    ac_client_id = body.get("ac_client_id", "")
    ac_client_secret = body.get("ac_client_secret", "")

    if not all([base_url, omadac_id, client_id, client_secret]):
        return jsonify({"error": "Tous les champs sont obligatoires"}), 400

    try:
        resp = http_requests.post(
            f"{base_url}/openapi/authorize/token",
            params={"grant_type": "client_credentials"},
            json={
                "omadacId": omadac_id,
                "client_id": client_id,
                "client_secret": client_secret,
            },
            timeout=15,
            verify=False,
        )
    except http_requests.RequestException as e:
        return jsonify({"error": f"Erreur de connexion : {e}"}), 502

    if resp.status_code != 200:
        return jsonify({"error": f"Echec auth (HTTP {resp.status_code})"}), resp.status_code

    data = resp.json()
    error_code = data.get("errorCode", -1)
    if error_code != 0:
        msg = data.get("msg", "Erreur inconnue")
        return jsonify({"error": f"Erreur Omada : {msg} (code {error_code})"}), 400

    result = data.get("result", {})
    session["base_url"] = base_url
    session["omadac_id"] = omadac_id
    session["client_id"] = client_id
    session["client_secret"] = client_secret
    session["username"] = username
    session["password"] = password
    session["ac_client_id"] = ac_client_id
    session["ac_client_secret"] = ac_client_secret
    session["mode"] = body.get("mode", "msp")
    session["access_token"] = result.get("accessToken", "")
    session["refresh_token"] = result.get("refreshToken", "")
    session["token_expires_at"] = time.time() + result.get("expiresIn", 3600)

    return jsonify({"success": True})


@app.route("/api/switch-customer", methods=["POST"])
@require_auth
def api_switch_customer():
    """Switch from MSP to Customer mode by authenticating with customer credentials."""
    body = request.get_json(silent=True) or {}
    customer_id = body.get("customer_id", "")
    client_id = body.get("client_id", "")
    client_secret = body.get("client_secret", "")
    customer_name = body.get("customer_name", "")
    # controller_id is the omadacId for the customer-level API (may differ from MSP customer_id)
    controller_id = body.get("controller_id", "") or customer_id

    if not all([customer_id, client_id, client_secret]):
        return jsonify({"error": "Tous les champs sont obligatoires"}), 400

    base_url = session.get("base_url", "")
    # Save MSP session info so we can go back
    msp_backup = {
        "omadac_id": session.get("omadac_id"),
        "client_id": session.get("client_id"),
        "client_secret": session.get("client_secret"),
        "access_token": session.get("access_token"),
        "refresh_token": session.get("refresh_token"),
        "token_expires_at": session.get("token_expires_at"),
        "username": session.get("username", ""),
        "password": session.get("password", ""),
        "ac_client_id": session.get("ac_client_id", ""),
        "ac_client_secret": session.get("ac_client_secret", ""),
        "ac_access_token": session.get("ac_access_token", ""),
        "ac_refresh_token": session.get("ac_refresh_token", ""),
        "ac_token_expires_at": session.get("ac_token_expires_at", 0),
    }

    # Authenticate as customer using controller_id as omadacId
    try:
        resp = http_requests.post(
            f"{base_url}/openapi/authorize/token",
            params={"grant_type": "client_credentials"},
            json={
                "omadacId": controller_id,
                "client_id": client_id,
                "client_secret": client_secret,
            },
            timeout=15,
            verify=False,
        )
    except http_requests.RequestException as e:
        return jsonify({"error": f"Erreur de connexion : {e}"}), 502

    if resp.status_code != 200:
        return jsonify({"error": f"Echec auth Customer (HTTP {resp.status_code})"}), resp.status_code

    data = resp.json()
    if data.get("errorCode", -1) != 0:
        return jsonify({"error": f"Erreur: {data.get('msg', 'Inconnue')}"}), 400

    result = data.get("result", {})
    session["msp_backup"] = msp_backup
    session["omadac_id"] = controller_id
    session["msp_customer_id"] = customer_id
    session["client_id"] = client_id
    session["client_secret"] = client_secret
    session["mode"] = "customer"
    session["customer_name"] = customer_name
    session["access_token"] = result.get("accessToken", "")
    session["refresh_token"] = result.get("refreshToken", "")
    session["token_expires_at"] = time.time() + result.get("expiresIn", 3600)

    return jsonify({"success": True})


@app.route("/api/back-to-msp", methods=["POST"])
@require_auth
def api_back_to_msp():
    """Switch back from Customer mode to MSP mode."""
    backup = session.get("msp_backup")
    if not backup:
        session.clear()
        return jsonify({"redirect": "/"})

    session["omadac_id"] = backup["omadac_id"]
    session["client_id"] = backup["client_id"]
    session["client_secret"] = backup["client_secret"]
    session["access_token"] = backup["access_token"]
    session["refresh_token"] = backup["refresh_token"]
    session["token_expires_at"] = backup["token_expires_at"]
    session["username"] = backup.get("username", "")
    session["password"] = backup.get("password", "")
    session["ac_client_id"] = backup.get("ac_client_id", "")
    session["ac_client_secret"] = backup.get("ac_client_secret", "")
    session["ac_access_token"] = backup.get("ac_access_token", "")
    session["ac_refresh_token"] = backup.get("ac_refresh_token", "")
    session["ac_token_expires_at"] = backup.get("ac_token_expires_at", 0)
    session["mode"] = "msp"
    session.pop("msp_backup", None)
    session.pop("customer_name", None)

    return jsonify({"success": True, "redirect": "/customers"})


@app.route("/api/logout")
def api_logout():
    # Clear only Omada-related session data, keep app authentication
    _OMADA_KEYS = [
        "access_token", "omada_url", "client_id", "client_secret",
        "token_expires_at", "mode", "customer_name", "customer_id",
        "site_id", "ac_token_expires_at", "msp_backup",
    ]
    for k in _OMADA_KEYS:
        session.pop(k, None)
    return redirect(url_for("login_page"))


@app.route("/api/test-authcode", methods=["POST"])
@require_auth
def api_test_authcode():
    """Test the Authorization Code flow step by step for debugging."""
    base_url = omada_base()
    ac_cid = session.get("ac_client_id", "") or session.get("client_id", "")
    ac_csecret = session.get("ac_client_secret", "") or session.get("client_secret", "")
    oid = omada_id()
    username = session.get("username", "")
    password = session.get("password", "")

    steps = {}
    steps["config"] = {
        "ac_client_id": ac_cid,
        "ac_client_secret_preview": ac_csecret[:6] + "..." + ac_csecret[-4:] if len(ac_csecret) > 10 else "***",
        "ac_client_secret_length": len(ac_csecret),
        "has_username": bool(username),
        "has_password": bool(password),
        "omadac_id": oid,
    }

    if not username or not password:
        return jsonify({"error": "Username/password non renseignes dans la session. Reconnectez-vous.", "steps": steps})
    if not ac_cid or not ac_csecret:
        return jsonify({"error": "Client ID/Secret de l'app Authorization Code non renseignes. Reconnectez-vous.", "steps": steps})

    # Use a persistent HTTP session for cookie sharing
    hs = http_requests.Session()
    hs.verify = False

    # Step 1: Login
    try:
        login_resp = hs.post(
            f"{base_url}/openapi/authorize/login",
            params={"client_id": ac_cid, "omadac_id": oid},
            json={"username": username, "password": password},
            timeout=15,
        )
        login_data = login_resp.json()
        steps["step1_login"] = {
            "status": login_resp.status_code,
            "params": {"client_id": ac_cid, "omadac_id": oid},
            "body": {"username": username, "password": "***"},
            "response": login_data,
            "cookies_received": dict(login_resp.cookies),
        }
        if login_data.get("errorCode", -1) != 0:
            return jsonify({"error": f"Step 1 failed: {login_data.get('msg')}", "steps": steps})
    except Exception as e:
        steps["step1_login"] = {"error": str(e)}
        return jsonify({"error": f"Step 1 exception: {e}", "steps": steps})

    csrf_token = login_data.get("result", {}).get("csrfToken", "")
    session_id_val = login_data.get("result", {}).get("sessionId", "")
    hs.cookies.set("TPOMADA_SESSIONID", session_id_val)

    # Step 2: Get code
    try:
        code_resp = hs.post(
            f"{base_url}/openapi/authorize/code",
            params={"client_id": ac_cid, "omadac_id": oid, "response_type": "code"},
            headers={"Content-Type": "application/json", "Csrf-Token": csrf_token},
            timeout=15,
        )
        code_data = code_resp.json()
        steps["step2_code"] = {
            "status": code_resp.status_code,
            "response": code_data,
            "cookies_received": dict(code_resp.cookies),
        }
        if code_data.get("errorCode", -1) != 0:
            return jsonify({"error": f"Step 2 failed: {code_data.get('msg')}", "steps": steps})
    except Exception as e:
        steps["step2_code"] = {"error": str(e)}
        return jsonify({"error": f"Step 2 exception: {e}", "steps": steps})

    auth_code = code_data.get("result", "")

    # Step 3: Exchange code for token
    try:
        token_resp = hs.post(
            f"{base_url}/openapi/authorize/token",
            params={"grant_type": "authorization_code", "code": auth_code},
            json={"client_id": ac_cid, "client_secret": ac_csecret},
            timeout=15,
        )
        token_data = token_resp.json()
        steps["step3_token"] = {
            "status": token_resp.status_code,
            "response": token_data,
            "request_body_sent": {"client_id": ac_cid, "client_secret": ac_csecret[:4] + "***" + ac_csecret[-4:]},
            "all_cookies": {k: v for k, v in hs.cookies.items()},
        }
        if token_data.get("errorCode", -1) != 0:
            return jsonify({"error": f"Step 3 failed: {token_data.get('msg')}", "steps": steps})
    except Exception as e:
        steps["step3_token"] = {"error": str(e)}
        return jsonify({"error": f"Step 3 exception: {e}", "steps": steps})

    return jsonify({"success": True, "steps": steps})


# ---------------------------------------------------------------------------
# API : Sites
# ---------------------------------------------------------------------------

@app.route("/api/sites", methods=["GET"])
@require_auth
def api_list_sites():
    refresh_token_if_needed()
    all_sites = []
    page = 1
    page_size = 200
    while True:
        params = {"page": str(page), "pageSize": str(page_size)}
        if is_direct_site_mode():
            resp = omada_get(std("/sites"), params)
        else:
            resp = omada_get(msp("/sites"), params)
        data = resp.json()
        if data.get("errorCode", -1) != 0:
            return jsonify(data), resp.status_code
        result = data.get("result", {})
        items = result.get("data", [])
        all_sites.extend(items)
        total = result.get("totalRows", 0)
        if len(all_sites) >= total or not items:
            break
        page += 1
    return jsonify({
        "errorCode": 0,
        "msg": "Success.",
        "result": {
            "totalRows": len(all_sites),
            "currentPage": 1,
            "currentSize": len(all_sites),
            "data": all_sites,
        },
    })


@app.route("/api/sites/<site_id>", methods=["GET"])
@require_auth
def api_get_site(site_id):
    refresh_token_if_needed()
    if is_direct_site_mode():
        # Customer/Standard mode: direct endpoint
        resp = omada_get(std(f"/sites/{site_id}"))
        return jsonify(resp.json()), resp.status_code
    else:
        # MSP has no single-site endpoint, search in the full list
        resp = omada_get(msp("/sites"), {"page": "1", "pageSize": "1000"})
        if resp.status_code != 200:
            return jsonify(resp.json()), resp.status_code
        data = resp.json()
        sites = (data.get("result") or {}).get("data") or []
        for site in sites:
            if site.get("siteId") == site_id:
                return jsonify({"errorCode": 0, "result": site}), 200
        return jsonify({"errorCode": -1, "msg": "Site non trouve"}), 404


@app.route("/api/sites", methods=["POST"])
@require_auth
def api_create_site():
    refresh_token_if_needed()
    body = request.get_json(silent=True) or {}
    import json as _json
    with open("/tmp/omada_single_create_req.json", "w") as f:
        _json.dump({"mode": session.get("mode"), "url": f"{omada_base()}{std('/sites')}", "body": body}, f, indent=2)
    if is_direct_site_mode():
        resp = omada_post(std("/sites"), body)
    else:
        # Try MSP create, fallback to standard
        resp = omada_post(msp("/sites"), body)
        rdata = resp.json()
        if rdata.get("errorCode", -1) == 0:
            return jsonify(rdata), resp.status_code
        resp = omada_post(std("/sites"), body)
    return jsonify(resp.json()), resp.status_code


@app.route("/api/sites/<site_id>", methods=["DELETE"])
@require_auth
def api_delete_site(site_id):
    refresh_token_if_needed()
    if is_direct_site_mode():
        # Customer/Standard mode: direct delete
        resp = omada_delete(std(f"/sites/{site_id}"))
        return jsonify(resp.json()), resp.status_code
    else:
        # MSP mode: try MSP delete, fallback with customerId
        customer_id = request.args.get("customerId", "")
        resp = omada_delete(msp(f"/sites/{site_id}"))
        rdata = resp.json()
        if rdata.get("errorCode", -1) == 0:
            return jsonify(rdata), resp.status_code
        cid = customer_id if customer_id else omada_id()
        resp = omada_delete(f"/openapi/v1/{cid}/sites/{site_id}")
        return jsonify(resp.json()), resp.status_code


# ---------------------------------------------------------------------------
# API : Customers (MSP)
# ---------------------------------------------------------------------------

@app.route("/api/customers", methods=["GET"])
@require_auth
def api_list_customers():
    refresh_token_if_needed()
    all_customers = []
    page = 1
    page_size = 100
    while True:
        resp = omada_get(msp("/customers"), {"page": str(page), "pageSize": str(page_size)})
        data = resp.json()
        if data.get("errorCode", -1) != 0:
            return jsonify(data), resp.status_code
        result = data.get("result", {})
        items = result.get("data", [])
        all_customers.extend(items)
        total = result.get("totalRows", 0)
        if len(all_customers) >= total or not items:
            break
        page += 1
    # Return in same format as single-page response
    return jsonify({
        "errorCode": 0,
        "msg": "Success.",
        "result": {
            "totalRows": len(all_customers),
            "currentPage": 1,
            "currentSize": len(all_customers),
            "data": all_customers,
        },
    })


@app.route("/api/customers", methods=["POST"])
@require_auth
def api_create_customer():
    """MSP: Create a new customer (requires Authorization Code mode)."""
    refresh_token_if_needed()
    body = request.get_json(silent=True) or {}
    try:
        resp = omada_post_authcode(msp("/customers"), body)
    except (ValueError, RuntimeError) as e:
        return jsonify({"error": str(e), "errorCode": -44118}), 400
    return jsonify(resp.json()), resp.status_code


@app.route("/api/customers/<customer_id>", methods=["DELETE"])
@require_auth
def api_delete_customer(customer_id):
    """MSP: Delete a customer (requires Authorization Code mode)."""
    refresh_token_if_needed()
    try:
        resp = omada_delete_authcode(msp(f"/customers/{customer_id}"))
    except (ValueError, RuntimeError) as e:
        return jsonify({"error": str(e), "errorCode": -44118}), 400
    return jsonify(resp.json()), resp.status_code


@app.route("/api/customers/bulk-create", methods=["POST"])
@require_auth
def api_bulk_create_customers():
    """MSP: Create multiple customers with incremental names (requires Authorization Code mode)."""
    refresh_token_if_needed()
    body = request.get_json(silent=True) or {}
    prefix = body.get("prefix", "Client")
    count = body.get("count", 1)
    start = body.get("start", 1)
    description = body.get("description", "")

    if count < 1 or count > 100:
        return jsonify({"error": "Le nombre de clients doit etre entre 1 et 100"}), 400

    # Pre-obtain auth code token once (will be cached for subsequent calls)
    try:
        get_auth_code_token()
    except (ValueError, RuntimeError) as e:
        return jsonify({"error": str(e), "errorCode": -44118}), 400

    results = []
    for i in range(count):
        num = start + i
        name = f"{prefix} {num}"
        cust_body = {"customerName": name}
        if description:
            cust_body["description"] = description
        try:
            resp = omada_post_authcode(msp("/customers"), cust_body)
            rdata = resp.json()
        except Exception as e:
            rdata = {"msg": str(e)}
        results.append({
            "name": name,
            "success": rdata.get("errorCode", -1) == 0,
            "msg": rdata.get("msg", ""),
            "result": rdata.get("result"),
        })
    return jsonify({"results": results})


# ---------------------------------------------------------------------------
# API : Scenarios
# ---------------------------------------------------------------------------

@app.route("/api/scenarios", methods=["GET"])
@require_auth
def api_list_scenarios():
    refresh_token_if_needed()
    resp = omada_get(f"/openapi/v1/{omada_id()}/scenarios")
    import json as _json
    with open("/tmp/omada_scenarios.json", "w") as f:
        try:
            _json.dump(resp.json(), f, indent=2)
        except Exception:
            f.write(resp.text)
    return jsonify(resp.json()), resp.status_code


# ---------------------------------------------------------------------------
# API : Devices
# ---------------------------------------------------------------------------

@app.route("/api/sites/<site_id>/devices", methods=["GET"])
@require_auth
def api_list_devices(site_id):
    refresh_token_if_needed()
    params = {
        "page": request.args.get("page", "1"),
        "pageSize": request.args.get("pageSize", "1000"),
    }
    if is_direct_site_mode():
        # Customer/Standard mode: direct endpoint
        resp = omada_get(std(f"/sites/{site_id}/devices"), params)
        rdata = resp.json()
        if rdata.get("errorCode", -1) == 0:
            return jsonify(rdata), 200
        return jsonify({"errorCode": 0, "result": {"data": [], "totalRows": 0}}), 200
    else:
        # MSP mode: try with customerId, fallback mspId
        oid = omada_id()
        customer_id = request.args.get("customerId", "")
        cid = customer_id if customer_id else oid
        resp = omada_get(f"/openapi/v1/{cid}/sites/{site_id}/devices", params)
        rdata = resp.json()
        if rdata.get("errorCode", -1) == 0:
            return jsonify(rdata), 200
        if customer_id:
            resp = omada_get(f"/openapi/v1/{oid}/sites/{site_id}/devices", params)
            rdata = resp.json()
            if rdata.get("errorCode", -1) == 0:
                return jsonify(rdata), 200
        return jsonify({"errorCode": 0, "result": {"data": [], "totalRows": 0}}), 200


@app.route("/api/sites/<site_id>/devices/<device_mac>/forget", methods=["POST"])
@require_auth
def api_forget_device(site_id, device_mac):
    refresh_token_if_needed()
    if is_direct_site_mode():
        # Customer/Standard mode: direct endpoint
        resp = omada_post(std(f"/sites/{site_id}/devices/{device_mac}/forget"))
        return jsonify(resp.json()), resp.status_code
    else:
        # MSP mode: try MSP forget, fallback standard with customerId
        oid = omada_id()
        customer_id = request.args.get("customerId", "")
        if customer_id:
            resp = omada_post(msp(f"/customers/{customer_id}/sites/{site_id}/devices/{device_mac}/forget"))
            rdata = resp.json()
            if rdata.get("errorCode", -1) == 0:
                return jsonify(rdata), 200
        cid = customer_id if customer_id else oid
        resp = omada_post(f"/openapi/v1/{cid}/sites/{site_id}/devices/{device_mac}/forget")
        return jsonify(resp.json()), resp.status_code


@app.route("/api/sites/<site_id>/forget-devices", methods=["POST"])
@require_auth
def api_forget_site_devices(site_id):
    """Forget all devices of a site without deleting the site."""
    refresh_token_if_needed()
    oid = omada_id()
    body = request.get_json(silent=True) or {}
    customer_id = body.get("customerId", "")

    if is_direct_site_mode():
        resp = omada_get(std(f"/sites/{site_id}/devices"), {"page": "1", "pageSize": "1000"})
        devices_data = []
        try:
            rdata = resp.json()
            if rdata.get("errorCode", -1) == 0:
                devices_data = (rdata.get("result") or {}).get("data") or []
        except Exception:
            pass

        forget_results = []
        for device in devices_data:
            mac = device.get("mac", "")
            if not mac:
                continue
            forget_resp = omada_post(std(f"/sites/{site_id}/devices/{mac}/forget"))
            try:
                forget_json = forget_resp.json()
            except Exception:
                forget_json = {}
            forget_results.append({
                "mac": mac, "name": device.get("name", mac),
                "status": forget_resp.status_code, "response": forget_json,
            })
    else:
        cid = customer_id if customer_id else oid

        resp = omada_get(f"/openapi/v1/{cid}/sites/{site_id}/devices", {"page": "1", "pageSize": "1000"})
        devices_data = []
        try:
            rdata = resp.json()
            if rdata.get("errorCode", -1) == 0:
                devices_data = (rdata.get("result") or {}).get("data") or []
        except Exception:
            pass

        forget_results = []
        for device in devices_data:
            mac = device.get("mac", "")
            if not mac:
                continue
            if customer_id:
                forget_resp = omada_post(msp(f"/customers/{customer_id}/sites/{site_id}/devices/{mac}/forget"))
                try:
                    forget_json = forget_resp.json()
                except Exception:
                    forget_json = {}
                if forget_json.get("errorCode", -1) != 0:
                    forget_resp = omada_post(f"/openapi/v1/{cid}/sites/{site_id}/devices/{mac}/forget")
                    try:
                        forget_json = forget_resp.json()
                    except Exception:
                        forget_json = {}
            else:
                forget_resp = omada_post(f"/openapi/v1/{oid}/sites/{site_id}/devices/{mac}/forget")
                try:
                    forget_json = forget_resp.json()
                except Exception:
                    forget_json = {}
            forget_results.append({
                "mac": mac, "name": device.get("name", mac),
                "status": forget_resp.status_code, "response": forget_json,
            })

    ok_count = sum(1 for r in forget_results if r.get("response", {}).get("errorCode", -1) == 0)
    return jsonify({
        "forget_results": forget_results,
        "total": len(forget_results),
        "ok": ok_count,
    })


@app.route("/api/sites/<site_id>/delete-with-forget", methods=["POST"])
@require_auth
def api_delete_site_with_forget(site_id):
    """Workflow: forget all devices, then delete site."""
    refresh_token_if_needed()
    oid = omada_id()
    body = request.get_json(silent=True) or {}
    customer_id = body.get("customerId", "")

    if is_direct_site_mode():
        # --- Customer/Standard mode: everything is direct ---
        # 1. Get devices
        resp = omada_get(std(f"/sites/{site_id}/devices"), {"page": "1", "pageSize": "1000"})
        devices_data = []
        try:
            rdata = resp.json()
            if rdata.get("errorCode", -1) == 0:
                devices_data = (rdata.get("result") or {}).get("data") or []
        except Exception:
            pass

        forget_results = []
        for device in devices_data:
            mac = device.get("mac", "")
            if not mac:
                continue
            forget_resp = omada_post(std(f"/sites/{site_id}/devices/{mac}/forget"))
            try:
                forget_json = forget_resp.json()
            except Exception:
                forget_json = {}
            forget_results.append({
                "mac": mac, "name": device.get("name", mac),
                "status": forget_resp.status_code, "response": forget_json,
            })

        if devices_data:
            time.sleep(5)

        delete_resp = omada_delete(std(f"/sites/{site_id}"))
        try:
            delete_json = delete_resp.json()
        except Exception:
            delete_json = {"msg": delete_resp.text}

    else:
        # --- MSP mode: cascading fallbacks ---
        cid = customer_id if customer_id else oid

        # 1. Get devices
        resp = omada_get(f"/openapi/v1/{cid}/sites/{site_id}/devices", {"page": "1", "pageSize": "1000"})
        devices_data = []
        try:
            rdata = resp.json()
            if rdata.get("errorCode", -1) == 0:
                devices_data = (rdata.get("result") or {}).get("data") or []
        except Exception:
            pass

        forget_results = []
        for device in devices_data:
            mac = device.get("mac", "")
            if not mac:
                continue
            if customer_id:
                forget_resp = omada_post(msp(f"/customers/{customer_id}/sites/{site_id}/devices/{mac}/forget"))
                try:
                    forget_json = forget_resp.json()
                except Exception:
                    forget_json = {}
                if forget_json.get("errorCode", -1) != 0:
                    forget_resp = omada_post(f"/openapi/v1/{cid}/sites/{site_id}/devices/{mac}/forget")
                    try:
                        forget_json = forget_resp.json()
                    except Exception:
                        forget_json = {}
            else:
                forget_resp = omada_post(f"/openapi/v1/{oid}/sites/{site_id}/devices/{mac}/forget")
                try:
                    forget_json = forget_resp.json()
                except Exception:
                    forget_json = {}
            forget_results.append({
                "mac": mac, "name": device.get("name", mac),
                "status": forget_resp.status_code, "response": forget_json,
            })

        if devices_data:
            time.sleep(5)

        # Delete: try MSP, fallback std with customerId
        delete_resp = omada_delete(msp(f"/sites/{site_id}"))
        try:
            delete_json = delete_resp.json()
        except Exception:
            delete_json = {"msg": delete_resp.text}
        if delete_json.get("errorCode", -1) != 0:
            delete_resp = omada_delete(f"/openapi/v1/{cid}/sites/{site_id}")
            try:
                delete_json = delete_resp.json()
            except Exception:
                delete_json = {"msg": delete_resp.text}

    return jsonify({
        "forget_results": forget_results,
        "delete_result": delete_json,
        "delete_status": delete_resp.status_code,
    })


# ---------------------------------------------------------------------------
# API : WAN Settings (Customer mode only)
# ---------------------------------------------------------------------------

@app.route("/api/sites/<site_id>/wan", methods=["GET"])
@require_auth
@require_direct_site_mode
def api_get_wan(site_id):
    refresh_token_if_needed()
    # Try multiple known paths for WAN info
    candidate_paths = [
        std(f"/sites/{site_id}/setting/wan"),
        std(f"/sites/{site_id}/wan"),
        std(f"/sites/{site_id}/setting/wan/ports"),
        std(f"/sites/{site_id}/setting/networkWan"),
    ]
    last_resp = None
    for path in candidate_paths:
        resp = omada_get(path)
        last_resp = resp
        if resp.status_code == 200:
            data = resp.json()
            if data.get("errorCode", -1) == 0:
                return jsonify(data), 200
    # Fallback: get WAN info from gateway device details
    gw_resp = omada_get(std(f"/sites/{site_id}/devices"), {"page": "1", "pageSize": "1000"})
    try:
        gw_data = gw_resp.json()
        if gw_data.get("errorCode", -1) == 0:
            devices = (gw_data.get("result") or {}).get("data") or []
            for d in devices:
                dtype = str(d.get("type", "")).lower()
                if dtype in ("gateway", "osg", "0"):
                    mac = d.get("mac", "")
                    if mac:
                        detail = omada_get(std(f"/sites/{site_id}/gateways/{mac}"))
                        if detail.status_code == 200:
                            detail_json = detail.json()
                            if detail_json.get("errorCode", -1) == 0:
                                gw_result = detail_json.get("result", {})
                                # Extract WAN port info from gateway
                                wan_info = gw_result.get("portStats") or gw_result.get("wanPortSettings") or gw_result.get("ports") or []
                                return jsonify({
                                    "errorCode": 0,
                                    "result": wan_info,
                                    "_source": "gateway",
                                    "_gateway": gw_result,
                                }), 200
    except Exception:
        pass
    return jsonify(last_resp.json()), last_resp.status_code


@app.route("/api/sites/<site_id>/wan", methods=["PUT"])
@require_auth
@require_direct_site_mode
def api_update_wan(site_id):
    refresh_token_if_needed()
    body = request.get_json(silent=True) or {}
    for suffix in ["setting/wan", "wan", "setting/wan/ports"]:
        resp = omada_put(std(f"/sites/{site_id}/{suffix}"), body)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("errorCode", -1) == 0:
                return jsonify(data), 200
    return jsonify(resp.json()), resp.status_code


# ---------------------------------------------------------------------------
# API : WAN ports / public IPs (Customer mode only)
# ---------------------------------------------------------------------------

@app.route("/api/sites/<site_id>/wan/ports", methods=["GET"])
@require_auth
@require_direct_site_mode
def api_get_wan_ports(site_id):
    """Return WAN port list from all site gateways using /gateways/{mac}/ports."""
    refresh_token_if_needed()
    try:
        resp = omada_get(std(f"/sites/{site_id}/devices"), {"page": "1", "pageSize": "1000"})
        rdata = resp.json()
        if rdata.get("errorCode", -1) != 0:
            return jsonify({"errorCode": -1, "msg": "Impossible de lister les devices"}), 502
        devices = (rdata.get("result") or {}).get("data") or []

        all_wan_ports = []
        primary_gw = None

        for d in devices:
            dtype = str(d.get("type", "")).lower()
            is_gateway = dtype in ("gateway", "osg", "3") or d.get("type") == 3
            if not is_gateway:
                continue
            mac = d.get("mac", "")
            if not mac:
                continue

            gw_name = d.get("name", "")
            gw_model = d.get("model") or d.get("showModel", "")

            # Get base gateway info (for portConfigs — link speed / status)
            port_configs = {}
            base_resp = omada_get(std(f"/sites/{site_id}/gateways/{mac}"))
            if base_resp.status_code == 200:
                base_j = base_resp.json()
                if base_j.get("errorCode", -1) == 0:
                    gw_base = base_j.get("result", {})
                    gw_name = gw_base.get("name") or gw_name
                    for pc in (gw_base.get("portConfigs") or []):
                        port_configs[pc["port"]] = pc

            # Get port list with WAN/LAN mode
            ports_resp = omada_get(std(f"/sites/{site_id}/gateways/{mac}/ports"))
            if ports_resp.status_code != 200:
                continue
            ports_j = ports_resp.json()
            if ports_j.get("errorCode", -1) != 0:
                continue

            for p in (ports_j.get("result") or []):
                if p.get("mode", 1) != 0:  # mode 0 = WAN
                    continue
                port_num = p.get("port")
                pc = port_configs.get(port_num, {})
                link_speed = pc.get("linkSpeed", 0)
                port_admin_up = pc.get("status", 1) == 1  # status=1 means port enabled
                # "online" = active link, "backup" = enabled but no active link, "offline" = disabled
                if link_speed and link_speed > 0:
                    conn_state = "online"
                elif port_admin_up:
                    conn_state = "backup"
                else:
                    conn_state = "offline"
                wan_port = {
                    "portName": p.get("name", f"Port {port_num}"),
                    "port": port_num,
                    "portType": p.get("type"),
                    "physicalType": p.get("physicalType"),
                    "linkSpeed": link_speed,
                    "connState": conn_state,
                    "_gateway_name": gw_name,
                    "_gateway_model": gw_model,
                    "_gateway_mac": mac,
                }
                all_wan_ports.append(wan_port)

                if primary_gw is None or gw_model in ("ER8411 v1.0",):
                    primary_gw = {"name": gw_name, "model": gw_model, "mac": mac}

        if not all_wan_ports:
            return jsonify({"errorCode": -1, "msg": "Aucun port WAN détecté"}), 404

        gw_info = primary_gw or {"name": "", "model": "", "mac": ""}
        return jsonify({
            "errorCode": 0,
            "result": {
                "gateway_name": gw_info["name"],
                "gateway_model": gw_info["model"],
                "gateway_mac": gw_info["mac"],
                "wan_ports": all_wan_ports,
            },
        }), 200
    except Exception as e:
        return jsonify({"errorCode": -1, "msg": str(e)}), 500


# ---------------------------------------------------------------------------
# API : WAN debug — retourne la réponse brute du gateway
# ---------------------------------------------------------------------------

@app.route("/api/sites/<site_id>/wan/debug", methods=["GET"])
@require_auth
@require_direct_site_mode
def api_get_wan_debug(site_id):
    """Retourne la réponse brute de tous les gateways pour diagnostic WAN."""
    refresh_token_if_needed()
    resp = omada_get(std(f"/sites/{site_id}/devices"), {"page": "1", "pageSize": "1000"})
    try:
        rdata = resp.json()
        devices = (rdata.get("result") or {}).get("data") or []

        # Show all devices with their types to help diagnose
        all_devices_summary = [
            {
                "name": d.get("name", ""),
                "mac": d.get("mac", ""),
                "model": d.get("model") or d.get("showModel", ""),
                "type": d.get("type"),
                "category": d.get("category"),
            }
            for d in devices
        ]

        gateways_debug = []
        for d in devices:
            dtype = str(d.get("type", "")).lower()
            category = str(d.get("category", "")).lower()
            is_gateway = (
                dtype in ("gateway", "osg", "3")
                or category in ("gateway",)
                or d.get("type") == 3
            )
            if not is_gateway:
                continue
            mac = d.get("mac", "")
            if not mac:
                continue
            detail = omada_get(std(f"/sites/{site_id}/gateways/{mac}"))
            dj = detail.json()
            gw = dj.get("result", {})
            gateways_debug.append({
                "mac": mac,
                "model": gw.get("model") or gw.get("modelName") or d.get("model", ""),
                "name": gw.get("name") or d.get("name", ""),
                "device_type_raw": d.get("type"),
                "device_category_raw": d.get("category"),
                "keys": list(gw.keys()),
                "portStats": gw.get("portStats"),
                "wanPortSetting": gw.get("wanPortSetting"),
                "wanSetting": gw.get("wanSetting"),
                "ports": gw.get("ports"),
                "wanStatus": gw.get("wanStatus"),
                "wanPortStats": gw.get("wanPortStats"),
                "networkSetting": gw.get("networkSetting"),
                "_raw": gw,
            })
        # Probe multiple potential WAN endpoints
        probe_results = {}
        probe_endpoints = [
            ("gateways_list",          std(f"/sites/{site_id}/gateways"),                    {"page": "1", "pageSize": "100"}),
            ("networks",               std(f"/sites/{site_id}/networks"),                    {"page": "1", "pageSize": "100"}),
            ("setting_wan",            std(f"/sites/{site_id}/setting/wan"),                 None),
            ("setting_wans",           std(f"/sites/{site_id}/setting/wans"),                None),
            ("setting_internet",       std(f"/sites/{site_id}/setting/internet"),            None),
            ("setting_networks",       std(f"/sites/{site_id}/setting/networks"),            None),
            ("stat_gateway",           std(f"/sites/{site_id}/stat/gateway"),                None),
            ("stat_site",              std(f"/sites/{site_id}/stat/site"),                   None),
            ("wan_status",             std(f"/sites/{site_id}/wan/status"),                  None),
            ("wan",                    std(f"/sites/{site_id}/wan"),                         None),
        ]
        # Probe per-gateway endpoints — get port list + per-port detail for WAN IP discovery
        gw_macs = [d.get("mac", "") for d in devices if str(d.get("type", "")).lower() in ("gateway", "osg", "3") or d.get("type") == 3]
        for mac in gw_macs:
            if not mac:
                continue
            probe_endpoints += [
                (f"gateways_ports_{mac}",   std(f"/sites/{site_id}/gateways/{mac}/ports"),   None),
                (f"gateways_wan_{mac}",     std(f"/sites/{site_id}/gateways/{mac}/wan"),     None),
                (f"gateways_status_{mac}",  std(f"/sites/{site_id}/gateways/{mac}/status"), None),
            ]
            # Try per-port detail for ports 1–4 (WAN ports are typically low-numbered)
            for port_num in range(1, 5):
                probe_endpoints.append(
                    (f"port_detail_{mac}_p{port_num}", std(f"/sites/{site_id}/gateways/{mac}/ports/{port_num}"), None)
                )
        for key, path, params in probe_endpoints:
            try:
                r = omada_get(path, params)
                probe_results[key] = {"status": r.status_code, "body": r.json()}
            except Exception as ex:
                probe_results[key] = {"status": -1, "error": str(ex)}

        result = {
            "errorCode": 0,
            "all_devices": all_devices_summary,
            "gateway_count": len(gateways_debug),
            "gateways": gateways_debug,
            "probe_results": probe_results,
        }
        # Save to file for server-side inspection
        try:
            with open(f"/tmp/wan_debug_{site_id}.json", "w") as f:
                json.dump(result, f, indent=2)
        except Exception:
            pass
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"errorCode": -1, "msg": str(e)}), 500


# ---------------------------------------------------------------------------
# API : Gateway info (Customer mode only)
# ---------------------------------------------------------------------------

@app.route("/api/sites/<site_id>/gateway", methods=["GET"])
@require_auth
@require_direct_site_mode
def api_get_gateway(site_id):
    """Get gateway device details for this site."""
    refresh_token_if_needed()
    # List devices and find the gateway
    resp = omada_get(std(f"/sites/{site_id}/devices"), {"page": "1", "pageSize": "1000"})
    try:
        rdata = resp.json()
        if rdata.get("errorCode", -1) == 0:
            devices = (rdata.get("result") or {}).get("data") or []
            for d in devices:
                dtype = (d.get("type") or "").lower()
                if dtype in ("gateway", "osg"):
                    # Get detailed info for this gateway
                    mac = d.get("mac", "")
                    if mac:
                        detail_resp = omada_get(std(f"/sites/{site_id}/gateways/{mac}"))
                        return jsonify(detail_resp.json()), detail_resp.status_code
                    return jsonify({"errorCode": 0, "result": d}), 200
    except Exception:
        pass
    return jsonify({"errorCode": -1, "msg": "Aucun gateway trouve"}), 404


# ---------------------------------------------------------------------------
# API : VPN WireGuard (Customer mode only)
# ---------------------------------------------------------------------------

@app.route("/api/sites/<site_id>/vpn/wireguards", methods=["GET"])
@require_auth
@require_direct_site_mode
def api_list_wireguards(site_id):
    refresh_token_if_needed()
    params = {"page": request.args.get("page", "1"), "pageSize": request.args.get("pageSize", "100")}
    resp = omada_get(std(f"/sites/{site_id}/vpn/wireguards"), params)
    return jsonify(resp.json()), resp.status_code


@app.route("/api/sites/<site_id>/vpn/wireguards/<wg_id>", methods=["PUT"])
@require_auth
@require_direct_site_mode
def api_update_wireguard(site_id, wg_id):
    refresh_token_if_needed()
    body = request.get_json(silent=True) or {}
    resp = omada_put(std(f"/sites/{site_id}/vpn/wireguards/{wg_id}"), body)
    return jsonify(resp.json()), resp.status_code


@app.route("/api/sites/<site_id>/vpn/wireguards/<wg_id>", methods=["DELETE"])
@require_auth
@require_direct_site_mode
def api_delete_wireguard(site_id, wg_id):
    refresh_token_if_needed()
    resp = omada_delete(std(f"/sites/{site_id}/vpn/wireguards/{wg_id}"))
    return jsonify(resp.json()), resp.status_code


@app.route("/api/sites/<site_id>/vpn/wireguard-peers", methods=["GET"])
@require_auth
@require_direct_site_mode
def api_list_wireguard_peers(site_id):
    refresh_token_if_needed()
    params = {"page": request.args.get("page", "1"), "pageSize": request.args.get("pageSize", "100")}
    resp = omada_get(std(f"/sites/{site_id}/vpn/wireguard-peers"), params)
    return jsonify(resp.json()), resp.status_code


@app.route("/api/sites/<site_id>/vpn/wireguard-peers/<peer_id>", methods=["PUT"])
@require_auth
@require_direct_site_mode
def api_update_wireguard_peer(site_id, peer_id):
    refresh_token_if_needed()
    body = request.get_json(silent=True) or {}
    resp = omada_put(std(f"/sites/{site_id}/vpn/wireguard-peers/{peer_id}"), body)
    return jsonify(resp.json()), resp.status_code


# ---------------------------------------------------------------------------
# API : WiFi / SSIDs (Customer mode only)
# ---------------------------------------------------------------------------

def omada_patch(path, body=None):
    return http_requests.patch(
        f"{omada_base()}{path}",
        json=body,
        headers=omada_headers(),
        timeout=30,
        verify=False,
    )


@app.route("/api/sites/<site_id>/wifi/ssids", methods=["GET"])
@require_auth
@require_direct_site_mode
def api_list_ssids(site_id):
    """List all SSIDs: first get WLAN groups, then SSIDs per group."""
    refresh_token_if_needed()
    params = {"page": "1", "pageSize": "100"}

    # Step 1: get WLAN groups
    wlans_resp = omada_get(std(f"/sites/{site_id}/wireless-network/wlans"), params)
    if wlans_resp.status_code != 200:
        return jsonify(wlans_resp.json()), wlans_resp.status_code
    wlans_data = wlans_resp.json()
    if wlans_data.get("errorCode", -1) != 0:
        return jsonify(wlans_data), 200

    raw_result = wlans_data.get("result") or []
    if isinstance(raw_result, list):
        wlan_list = raw_result
    elif isinstance(raw_result, dict):
        wlan_list = raw_result.get("data") or []
    else:
        wlan_list = []

    # Step 2: for each WLAN group, get SSIDs
    all_ssids = []
    for wlan in wlan_list:
        wlan_id = wlan.get("id") or wlan.get("wlanId") or ""
        wlan_name = wlan.get("name") or wlan.get("wlanName") or ""
        if not wlan_id:
            continue
        ssids_resp = omada_get(std(f"/sites/{site_id}/wireless-network/wlans/{wlan_id}/ssids"), params)
        if ssids_resp.status_code == 200:
            ssids_data = ssids_resp.json()
            if ssids_data.get("errorCode", -1) == 0:
                ssid_items = ((ssids_data.get("result") or {}).get("data")) or []
                if isinstance(ssids_data.get("result"), list):
                    ssid_items = ssids_data["result"]
                for s in ssid_items:
                    s["_wlanId"] = wlan_id
                    s["_wlanName"] = wlan_name
                all_ssids.extend(ssid_items)

    return jsonify({"errorCode": 0, "result": {"data": all_ssids, "_wlans": wlan_list}}), 200


@app.route("/api/sites/<site_id>/wifi/ssids/<wlan_id>/<ssid_id>", methods=["GET"])
@require_auth
@require_direct_site_mode
def api_get_ssid(site_id, wlan_id, ssid_id):
    refresh_token_if_needed()
    resp = omada_get(std(f"/sites/{site_id}/wireless-network/wlans/{wlan_id}/ssids/{ssid_id}"))
    return jsonify(resp.json()), resp.status_code


@app.route("/api/sites/<site_id>/wifi/ssids/<wlan_id>/<ssid_id>", methods=["PATCH"])
@require_auth
@require_direct_site_mode
def api_update_ssid(site_id, wlan_id, ssid_id):
    refresh_token_if_needed()
    body = request.get_json(silent=True) or {}

    # Step 1: fetch the full SSID detail (listing endpoint omits required fields)
    detail_resp = omada_get(std(f"/sites/{site_id}/wireless-network/wlans/{wlan_id}/ssids/{ssid_id}"))
    import json as _json
    if detail_resp.status_code == 200:
        detail_data = detail_resp.json()
        with open("/tmp/omada_ssid_detail.json", "w") as f:
            _json.dump(detail_data, f, indent=2)
        if detail_data.get("errorCode", -1) == 0:
            full_ssid = detail_data.get("result") or {}
            # Merge: start with full SSID, override with caller's changes
            merged = {**full_ssid, **body}
            # Remove any internal/meta fields
            for key in list(merged.keys()):
                if key.startswith("_"):
                    del merged[key]
            body = merged

    # Ensure required fields have defaults if still missing
    body.setdefault("mloEnable", False)
    body.setdefault("enable11r", False)
    body.setdefault("pmfMode", 0)

    with open("/tmp/omada_ssid_update_req.json", "w") as f:
        _json.dump({"site_id": site_id, "wlan_id": wlan_id, "ssid_id": ssid_id, "body": body}, f, indent=2)

    resp = omada_patch(
        std(f"/sites/{site_id}/wireless-network/wlans/{wlan_id}/ssids/{ssid_id}/update-basic-config"),
        body,
    )
    resp_data = resp.json()

    with open("/tmp/omada_ssid_update_resp.json", "w") as f:
        _json.dump(resp_data, f, indent=2)

    return jsonify(resp_data), resp.status_code


# ---------------------------------------------------------------------------
# API : Site defaults (get region/timezone from existing site)
# ---------------------------------------------------------------------------

@app.route("/api/site-defaults", methods=["GET"])
@require_auth
@require_direct_site_mode
def api_site_defaults():
    """Get default values for site creation from an existing site."""
    refresh_token_if_needed()
    defaults = {"region": "France", "timeZone": "Europe/Paris", "scenario": "Home"}
    sites_resp = omada_get(std("/sites"), {"page": "1", "pageSize": "1"})
    sites_data = sites_resp.json()
    if sites_data.get("errorCode", -1) == 0:
        site_list = (sites_data.get("result") or {}).get("data") or []
        if site_list:
            sid = site_list[0].get("siteId") or site_list[0].get("id")
            if sid:
                detail_resp = omada_get(std(f"/sites/{sid}"))
                detail_data = detail_resp.json()
                if detail_data.get("errorCode", -1) == 0:
                    es = detail_data.get("result", {})
                    defaults["region"] = es.get("region", defaults["region"])
                    defaults["timeZone"] = es.get("timeZone", defaults["timeZone"])
                    defaults["scenario"] = es.get("scenario", defaults["scenario"])
    return jsonify(defaults)


# ---------------------------------------------------------------------------
# API : Bulk site creation (Customer mode)
# ---------------------------------------------------------------------------

@app.route("/api/sites/bulk-create", methods=["POST"])
@require_auth
@require_direct_site_mode
def api_bulk_create_sites():
    """Create multiple sites with incremental names."""
    refresh_token_if_needed()
    body = request.get_json(silent=True) or {}
    prefix = body.get("prefix", "Site")
    count = body.get("count", 1)
    start = body.get("start", 1)
    extra = body.get("extra", {})  # extra fields like region, timeZone, scenario

    if count < 1 or count > 100:
        return jsonify({"error": "Le nombre de sites doit etre entre 1 et 100"}), 400

    import json as _json

    results = []
    for i in range(count):
        num = start + i
        site_name = f"{prefix} {num}"
        site_body = {"name": site_name, **extra}

        api_path = std("/sites")
        with open("/tmp/omada_bulk_create_req.json", "w") as f:
            _json.dump({"url": f"{omada_base()}{api_path}", "body": site_body}, f, indent=2)

        resp = omada_post(api_path, site_body)

        with open("/tmp/omada_bulk_create_resp.json", "w") as f:
            try:
                _json.dump({"status": resp.status_code, "data": resp.json()}, f, indent=2)
            except Exception:
                f.write(resp.text)
        try:
            rdata = resp.json()
        except Exception:
            rdata = {"msg": resp.text}
        results.append({
            "name": site_name,
            "success": rdata.get("errorCode", -1) == 0,
            "msg": rdata.get("msg", ""),
            "result": rdata.get("result"),
        })

    return jsonify({"results": results})


# ---------------------------------------------------------------------------
# API : Device adoption (Standard / Customer mode)
# ---------------------------------------------------------------------------

@app.route("/api/sites/<site_id>/devices/adopt", methods=["POST"])
@require_auth
@require_direct_site_mode
def api_adopt_device(site_id):
    """Adopt a single device into a site via device key.
    Body: {"key": "XXXX-XXXX-XXXX", "mac": "AA:BB:CC:DD:EE:FF"}  (mac optional)
    Tries multiple Omada API paths since it varies by firmware version.
    """
    refresh_token_if_needed()
    body = request.get_json(silent=True) or {}
    device_key = body.get("key", "").strip()
    mac = body.get("mac", "").strip()

    if not device_key:
        return jsonify({"error": "Le champ 'key' (device key) est obligatoire"}), 400

    adopt_body = {"key": device_key}
    if mac:
        adopt_body["mac"] = mac

    # Try several known Omada API adoption endpoints (differs by version)
    candidate_paths = [
        std(f"/sites/{site_id}/cmd/adopt"),
        std(f"/sites/{site_id}/devices"),
        std(f"/sites/{site_id}/devices/adopt"),
    ]

    last_resp = None
    for path in candidate_paths:
        try:
            resp = omada_post(path, adopt_body)
            last_resp = resp
            rdata = resp.json()
            if rdata.get("errorCode", -1) == 0:
                return jsonify(rdata), 200
            # errorCode -1301 = device already adopted elsewhere, still return it
        except Exception:
            continue

    if last_resp is not None:
        try:
            return jsonify(last_resp.json()), last_resp.status_code
        except Exception:
            pass
    return jsonify({"error": "Echec adoption — aucun endpoint disponible"}), 502


@app.route("/api/devices/bulk-adopt", methods=["POST"])
@require_auth
@require_direct_site_mode
def api_bulk_adopt_devices():
    """Adopt multiple devices across multiple sites from a list.
    Body: {"entries": [{"site_id": "...", "key": "...", "mac": "...", "label": "..."}, ...]}
    """
    refresh_token_if_needed()
    body = request.get_json(silent=True) or {}
    entries = body.get("entries", [])

    if not entries:
        return jsonify({"error": "Aucune entree fournie"}), 400
    if len(entries) > 500:
        return jsonify({"error": "Maximum 500 devices par operation"}), 400

    results = []
    for entry in entries:
        site_id = entry.get("site_id", "").strip()
        device_key = entry.get("key", "").strip()
        mac = entry.get("mac", "").strip()
        label = entry.get("label", "").strip()

        if not site_id or not device_key:
            results.append({
                "site_id": site_id, "key": device_key, "mac": mac, "label": label,
                "success": False, "msg": "site_id et key sont obligatoires",
            })
            continue

        adopt_body = {"key": device_key}
        if mac:
            adopt_body["mac"] = mac

        candidate_paths = [
            f"/openapi/v1/{omada_id()}/sites/{site_id}/cmd/adopt",
            f"/openapi/v1/{omada_id()}/sites/{site_id}/devices",
            f"/openapi/v1/{omada_id()}/sites/{site_id}/devices/adopt",
        ]

        success = False
        msg = ""
        for path in candidate_paths:
            try:
                resp = http_requests.post(
                    f"{omada_base()}{path}",
                    json=adopt_body,
                    headers=omada_headers(),
                    timeout=20,
                    verify=False,
                )
                rdata = resp.json()
                if rdata.get("errorCode", -1) == 0:
                    success = True
                    msg = "Adopte"
                    break
                else:
                    msg = rdata.get("msg", f"Erreur code {rdata.get('errorCode')}")
            except Exception as e:
                msg = str(e)

        results.append({
            "site_id": site_id,
            "key": device_key,
            "mac": mac,
            "label": label,
            "success": success,
            "msg": msg,
        })

    ok = sum(1 for r in results if r["success"])
    return jsonify({"results": results, "total": len(results), "success": ok, "failed": len(results) - ok})


# ---------------------------------------------------------------------------
# API : Export devices (MAC / serial / adoptKey) across all sites
# ---------------------------------------------------------------------------

@app.route("/api/export/devices", methods=["GET"])
@require_auth
def api_export_devices():
    """Collect all devices from all sites and return mac, serialNo, adoptKey, model, name, site."""
    refresh_token_if_needed()
    oid = omada_id()

    # ── 1. Fetch all sites ───────────────────────────────────────────────────
    all_sites = []
    page = 1
    while True:
        params = {"page": str(page), "pageSize": "200"}
        if is_direct_site_mode():
            resp = omada_get(std("/sites"), params)
        else:
            resp = omada_get(msp("/sites"), params)
        rdata = resp.json()
        if rdata.get("errorCode", -1) != 0:
            break
        batch = (rdata.get("result") or {}).get("data") or []
        all_sites.extend(batch)
        total = (rdata.get("result") or {}).get("totalRows", 0)
        if len(all_sites) >= total or not batch:
            break
        page += 1

    # ── 2. For each site, fetch devices ──────────────────────────────────────
    export = []
    for site in all_sites:
        site_id   = site.get("id") or site.get("siteId") or ""
        site_name = site.get("name") or site.get("siteName") or ""
        customer  = site.get("customerName") or ""
        if not site_id:
            continue
        try:
            if is_direct_site_mode():
                resp = omada_get(std(f"/sites/{site_id}/devices"), {"page": "1", "pageSize": "1000"})
            else:
                customer_id = site.get("customerId") or ""
                cid = customer_id if customer_id else oid
                resp = omada_get(f"/openapi/v1/{cid}/sites/{site_id}/devices",
                                 {"page": "1", "pageSize": "1000"})
            rdata = resp.json()
            if rdata.get("errorCode", -1) != 0:
                continue
            for dev in (rdata.get("result") or {}).get("data") or []:
                export.append({
                    "site_id":       site_id,
                    "site_name":     site_name,
                    "customer_name": customer,
                    "name":          dev.get("name", ""),
                    "mac":           dev.get("mac", ""),
                    "model":         dev.get("model") or dev.get("modelName", ""),
                    "serial":        dev.get("serialNo") or dev.get("sn", ""),
                    "adopt_key":     dev.get("adoptKey") or dev.get("key", ""),
                    "ip":            dev.get("ip", ""),
                    "firmware":      dev.get("version") or dev.get("firmwareVersion", ""),
                    "status":        dev.get("status", ""),
                    "type":          dev.get("type", ""),
                })
        except Exception:
            continue

    return jsonify({"devices": export, "total": len(export)})


# ---------------------------------------------------------------------------
# API : MSP Bulk delete all sites for a customer
# ---------------------------------------------------------------------------

@app.route("/api/customers/<msp_customer_id>/delete-all-sites", methods=["POST"])
@require_auth
def api_delete_all_customer_sites(msp_customer_id):
    """MSP: Forget all devices and delete all sites for a given customer, one by one."""
    refresh_token_if_needed()
    oid = omada_id()

    # Get all sites from MSP and filter by customerId
    resp = omada_get(msp("/sites"), {"page": "1", "pageSize": "1000"})
    if resp.status_code != 200:
        return jsonify({"error": f"Erreur API sites (HTTP {resp.status_code})"}), 502
    data = resp.json()
    if data.get("errorCode", -1) != 0:
        return jsonify({"error": data.get("msg", "Erreur inconnue")}), 400

    all_sites = (data.get("result") or {}).get("data") or []
    customer_sites = [s for s in all_sites if s.get("customerId") == msp_customer_id]

    results = []
    for site in customer_sites:
        site_id = site.get("siteId") or site.get("id")
        site_name = site.get("siteName") or site.get("name") or site_id
        if not site_id:
            continue

        # 1. Get devices
        dev_resp = omada_get(f"/openapi/v1/{msp_customer_id}/sites/{site_id}/devices",
                             {"page": "1", "pageSize": "1000"})
        devices_data = []
        try:
            dev_json = dev_resp.json()
            if dev_json.get("errorCode", -1) == 0:
                devices_data = (dev_json.get("result") or {}).get("data") or []
        except Exception:
            pass

        # 2. Forget each device
        forget_results = []
        for device in devices_data:
            mac = device.get("mac", "")
            if not mac:
                continue
            # Try MSP path first, fallback to direct
            f_resp = omada_post(msp(f"/customers/{msp_customer_id}/sites/{site_id}/devices/{mac}/forget"))
            try:
                f_json = f_resp.json()
            except Exception:
                f_json = {}
            if f_json.get("errorCode", -1) != 0:
                f_resp = omada_post(f"/openapi/v1/{msp_customer_id}/sites/{site_id}/devices/{mac}/forget")
                try:
                    f_json = f_resp.json()
                except Exception:
                    f_json = {}
            forget_results.append({
                "mac": mac,
                "name": device.get("name", mac),
                "success": f_json.get("errorCode", -1) == 0,
            })

        if devices_data:
            time.sleep(3)

        # 3. Delete site
        del_resp = omada_delete(msp(f"/sites/{site_id}"))
        try:
            del_json = del_resp.json()
        except Exception:
            del_json = {"msg": del_resp.text}
        if del_json.get("errorCode", -1) != 0:
            del_resp = omada_delete(f"/openapi/v1/{msp_customer_id}/sites/{site_id}")
            try:
                del_json = del_resp.json()
            except Exception:
                del_json = {"msg": del_resp.text}

        results.append({
            "site_id": site_id,
            "site_name": site_name,
            "devices_forgotten": len(forget_results),
            "forget_errors": sum(1 for f in forget_results if not f["success"]),
            "delete_success": del_json.get("errorCode", -1) == 0,
            "delete_msg": del_json.get("msg", ""),
        })

    return jsonify({"results": results, "total_sites": len(customer_sites)})


# ---------------------------------------------------------------------------
# Settings & version
# ---------------------------------------------------------------------------

_VERSION_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "VERSION")
_GITHUB_REPO  = "YakuMawi/omada-api-hub"


def _current_version():
    try:
        with open(_VERSION_FILE) as f:
            return f.read().strip()
    except OSError:
        return "unknown"


@app.route("/settings")
@require_app_login
def settings_page():
    return render_template("settings.html", current_version=_current_version())


@app.route("/api/account/change-password", methods=["POST"])
@require_app_login
def api_change_password():
    body = request.get_json(silent=True) or {}
    current_pw = body.get("current_password", "")
    new_pw     = body.get("new_password", "")
    if not current_pw or not new_pw:
        return jsonify({"error": "Champs requis"}), 400
    if len(new_pw) < 8:
        return jsonify({"error": "Mot de passe trop court (8 caractères minimum)"}), 400
    uid = session.get("user_id")
    db = get_db()
    row = db.execute("SELECT password_hash FROM users WHERE id=?", (uid,)).fetchone()
    if not row:
        return jsonify({"error": "Utilisateur introuvable"}), 404
    try:
        if not bcrypt.checkpw(current_pw.encode(), row[0].encode()):
            return jsonify({"error": "Mot de passe actuel incorrect"}), 403
    except Exception:
        return jsonify({"error": "Erreur de vérification"}), 500
    new_hash = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
    db.execute("UPDATE users SET password_hash=? WHERE id=?", (new_hash, uid))
    db.commit()
    return jsonify({"success": True})


@app.route("/api/settings/smtp", methods=["GET"])
@require_app_login
def api_get_smtp():
    cfg = get_smtp_config()
    if cfg.get("smtp_password"):
        cfg["smtp_password"] = "***"
    return jsonify(cfg)


@app.route("/api/settings/smtp", methods=["POST"])
@require_app_login
def api_save_smtp():
    body = request.get_json(silent=True) or {}
    keys = ["smtp_host", "smtp_port", "smtp_user", "smtp_password", "smtp_from", "smtp_tls"]
    db = get_db()
    for k in keys:
        if k in body:
            val = body[k]
            # Don't overwrite password if placeholder sent
            if k == "smtp_password" and val == "***":
                continue
            db.execute(
                "INSERT INTO app_settings (key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (k, str(val)),
            )
    db.commit()
    return jsonify({"success": True})


@app.route("/api/settings/smtp/test", methods=["POST"])
@require_app_login
def api_test_smtp():
    uid = session.get("user_id")
    db  = get_db()
    row = db.execute("SELECT email FROM users WHERE id=?", (uid,)).fetchone()
    to_email = row[0] if row and row[0] else None
    if not to_email:
        return jsonify({"error": "Aucune adresse email associée à votre compte. Ajoutez-en une dans les paramètres."}), 400
    if not smtp_is_configured():
        return jsonify({"error": "SMTP non configuré."}), 400
    ok = send_reset_email(to_email, "TEST-EMAIL")
    if ok:
        return jsonify({"success": True, "sent_to": to_email})
    return jsonify({"error": "Échec de l'envoi. Vérifiez la configuration SMTP."}), 502


@app.route("/api/account/email", methods=["POST"])
@require_app_login
def api_update_email():
    body  = request.get_json(silent=True) or {}
    email = body.get("email", "").strip().lower()
    if email and "@" not in email:
        return jsonify({"error": "Adresse email invalide"}), 400
    db = get_db()
    db.execute("UPDATE users SET email=? WHERE id=?", (email, session.get("user_id")))
    db.commit()
    return jsonify({"success": True})


@app.route("/api/update", methods=["POST"])
@require_app_login
def api_do_update():
    """Pull latest code from GitHub then restart the process."""
    import subprocess, threading
    app_dir = os.path.dirname(os.path.abspath(__file__))
    try:
        pull = subprocess.run(
            ["git", "pull", "origin", "main"],
            cwd=app_dir, capture_output=True, text=True, timeout=30
        )
        output = (pull.stdout + pull.stderr).strip()
        if pull.returncode != 0:
            return jsonify({"success": False, "output": output}), 500

        # Install/upgrade packages (handles externally-managed envs)
        subprocess.run(
            ["pip3", "install", "--break-system-packages", "-q", "-r",
             os.path.join(app_dir, "requirements.txt")],
            capture_output=True, timeout=60
        )

        new_version = open(os.path.join(app_dir, "VERSION")).read().strip()

        # Restart the process after 1.5 s (gives time to send the response)
        def _restart():
            import time as _t, sys as _s
            _t.sleep(1.5)
            os.execv(_s.executable, [_s.executable] + _s.argv)

        threading.Thread(target=_restart, daemon=True).start()
        return jsonify({"success": True, "output": output, "new_version": new_version})
    except Exception as e:
        return jsonify({"success": False, "output": str(e)}), 500


@app.route("/api/version/check", methods=["GET"])
@require_app_login
def api_version_check():
    """Compare current version against latest GitHub release."""
    current = _current_version()
    try:
        resp = http_requests.get(
            f"https://api.github.com/repos/{_GITHUB_REPO}/releases/latest",
            timeout=8,
            headers={"Accept": "application/vnd.github+json"},
        )
        if resp.status_code == 404:
            return jsonify({"current": current, "latest": None, "up_to_date": True, "no_release": True})
        data = resp.json()
        latest = data.get("tag_name", "").lstrip("v")
        html_url = data.get("html_url", "")
        body = data.get("body", "")
        def _ver(v):
            try:
                return tuple(int(x) for x in v.split("."))
            except Exception:
                return (0,)
        up_to_date = _ver(current) >= _ver(latest)
        return jsonify({
            "current": current,
            "latest": latest,
            "up_to_date": up_to_date,
            "release_url": html_url,
            "release_notes": body,
        })
    except Exception as e:
        return jsonify({"current": current, "error": str(e)}), 502


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


init_db()

if __name__ == "__main__":
    import ssl as _ssl
    _base = os.path.dirname(os.path.abspath(__file__))
    _cert = os.path.join(_base, "ssl", "cert.pem")
    _key  = os.path.join(_base, "ssl", "key.pem")
    if os.path.exists(_cert) and os.path.exists(_key):
        ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(_cert, _key)
        app.run(host="0.0.0.0", port=443, ssl_context=ctx, debug=False)
    else:
        app.run(host="0.0.0.0", port=5000, debug=False)
