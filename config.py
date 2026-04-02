"""
Constantes partagées entre app.py et les blueprints.
"""
import os

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DB_FILE          = os.path.join(_BASE_DIR, "users.db")
CREDENTIALS_FILE = os.path.join(_BASE_DIR, ".omada-credentials.json")
VERSION_FILE     = os.path.join(_BASE_DIR, "VERSION")
GITHUB_REPO      = "YakuMawi/omada-api-hub"
