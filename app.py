# pip install streamlit gspread gspread-dataframe extra-streamlit-components pandas google-auth google-api-python-client

import os
import re
import glob
import base64
import json
import hmac
import hashlib
import time
import io
from datetime import datetime, timedelta

import streamlit as st
import pandas as pd
import gspread
from google.oauth2.service_account import Credentials
from gspread_dataframe import set_with_dataframe
import extra_streamlit_components as stx
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload

# =============================================================================
# CONFIG
# =============================================================================
APP_TITLE = "Tracking Inventory Management System"
SUBTITLE  = "Advanced Construction"
DATE_FMT  = "%Y-%m-%d %H:%M:%S"

SESSION_TTL_DAYS = 30
SESSION_TTL_SECONDS = SESSION_TTL_DAYS * 24 * 60 * 60
COOKIE_NAME = "ac_auth_v2"
COOKIE_PATH = "/"

# If you embed the app (or see logout-on-refresh), keep SameSite=None + Secure=True (HTTPS required).
COOKIE_SECURE   = st.secrets.get("auth", {}).get("cookie_secure", True)
COOKIE_SAMESITE = st.secrets.get("auth", {}).get("cookie_samesite", "Lax")  # use "None" only when embedded

SHEET_URL_DEFAULT = "https://docs.google.com/spreadsheets/d/1SHp6gOW4ltsyOT41rwo85e_LELrHkwSwKN33K6XNHFI/edit"

INVENTORY_WS    = "truckinventory"
TRANSFERLOG_WS  = "transfer_log"
EMPLOYEE_WS     = "mainlists"

# New: Pending approvals sheets
PENDING_DEVICE_WS    = "pending_device_reg"
PENDING_TRANSFER_WS  = "pending_transfers"

INVENTORY_COLS = [
    "Serial Number","Device Type","Brand","Model","CPU",
    "Hard Drive 1","Hard Drive 2","Memory","GPU","Screen Size",
    "Current user","Previous User","TO",
    "Department","Email Address","Contact Number","Location","Office",
    "Notes","Date issued","Registered by"
]
LOG_COLS = ["Device Type","Serial Number","From owner","To owner","Date issued","Registered by"]

# Employees sheet columns (canonical). Keep both name columns, remove APLUS from schema.
EMPLOYEE_CANON_COLS = [
    "New Employeer","Employee ID","New Signature","Name","Address",
    "Active","Position","Department","Location (KSA)",
    "Project","Microsoft Teams","Mobile Number"
]

# New: Pending approvals columns
APPROVAL_META_COLS = [
    "Approval Status",              # Pending / Approved / Rejected
    "Approval PDF",                 # Drive webViewLink
    "Approval File ID",             # Drive file id
    "Submitted by",
    "Submitted at",
    "Approver",
    "Decision at"
]
PENDING_DEVICE_COLS   = INVENTORY_COLS + APPROVAL_META_COLS
PENDING_TRANSFER_COLS = LOG_COLS + APPROVAL_META_COLS

# Label used when a device is not assigned yet
UNASSIGNED_LABEL = "Unassigned (Stock)"

HEADER_SYNONYMS = {
    "new employee": "New Employeer",
    "new employeer": "New Employeer",
    "employeeid": "Employee ID",
    "newsignature": "New Signature",
    "locationksa": "Location (KSA)",
    "microsoftteams": "Microsoft Teams",
    "microsoftteam": "Microsoft Teams",
    "mobile": "Mobile Number",
    "mobilenumber": "Mobile Number",
}

INVENTORY_HEADER_SYNONYMS = {
    "user": "Current user",
    "currentuser": "Current user",
    "previoususer": "Previous User",
    "to": "TO",
    "department1": None,
}

st.set_page_config(page_title=APP_TITLE, layout="wide")
COOKIE_MGR = stx.CookieManager(key="ac_cookie_mgr")

# =============================================================================
# AUTH (users + cookie)
# =============================================================================

def _load_users_from_secrets():
    users_cfg = st.secrets.get("auth", {}).get("users", [])
    users = {}
    for u in users_cfg:
        users[u["username"]] = {
            "password": u.get("password", ""),
            "role": u.get("role", "Staff"),
        }
    return users

USERS = _load_users_from_secrets()

def _verify_password(raw: str, stored: str) -> bool:
    return hmac.compare_digest(str(stored), str(raw))

def do_logout():
    try:
        COOKIE_MGR.delete(COOKIE_NAME)
        COOKIE_MGR.set(COOKIE_NAME, "", expires_at=datetime.utcnow() - timedelta(days=1))
    except Exception:
        pass
    for k in ["authenticated", "role", "username", "name"]:
        st.session_state.pop(k, None)
    st.session_state.just_logged_out = True
    st.rerun()

if "cookie_bootstrapped" not in st.session_state:
    st.session_state.cookie_bootstrapped = True
    _ = COOKIE_MGR.get_all()  # ensure JS-side cookie store is loaded
    st.rerun()

def _cookie_key() -> str:
    return st.secrets.get("auth", {}).get("cookie_key", "PLEASE_SET_auth.cookie_key_IN_SECRETS")

def _cookie_keys() -> list[str]:
    keys = [st.secrets.get("auth", {}).get("cookie_key", "")]
    keys += st.secrets.get("auth", {}).get("legacy_cookie_keys", [])
    return [k for k in keys if k]

def _sign(raw: bytes, *, key: str | None = None) -> str:
    use = key or st.secrets.get("auth", {}).get("cookie_key", "")
    return hmac.new(use.encode(), raw, hashlib.sha256).hexdigest()

def _verify_sig(sig: str, raw: bytes) -> bool:
    for k in _cookie_keys():
        if hmac.compare_digest(sig, _sign(raw, key=k)):
            return True
    return False

def _issue_session_cookie(username: str, role: str):
    iat = int(time.time())
    exp = iat + (SESSION_TTL_SECONDS if SESSION_TTL_SECONDS > 0 else 0)
    payload = {"u": username, "r": role, "iat": iat, "exp": exp, "v": 1}
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    token = base64.urlsafe_b64encode(raw).decode() + "." + _sign(raw)

    COOKIE_MGR.set(
        COOKIE_NAME, token,
        expires_at=(datetime.utcnow() + timedelta(seconds=SESSION_TTL_SECONDS)) if SESSION_TTL_SECONDS > 0 else None,
        secure=COOKIE_SECURE,
    )

def _read_cookie():
    token = COOKIE_MGR.get(COOKIE_NAME)
    if not token:
        return None
    try:
        data_b64, sig = token.split(".", 1)
        raw = base64.urlsafe_b64decode(data_b64.encode())
        if not _verify_sig(sig, raw):
            COOKIE_MGR.delete(COOKIE_NAME)
            return None
        payload = json.loads(raw.decode())
        exp = int(payload.get("exp", 0))
        now = int(time.time())
        if exp and now > exp:
            COOKIE_MGR.delete(COOKIE_NAME)
            return None
        return payload
    except Exception:
        COOKIE_MGR.delete(COOKIE_NAME)
        return None

def do_login(username: str, role: str):
    st.session_state.authenticated = True
    st.session_state.username = username
    st.session_state.name = username
    st.session_state.role = role
    st.session_state.just_logged_out = False
    _issue_session_cookie(username, role)
    st.rerun()

# =============================================================================
# STYLE
# =============================================================================

def _inject_font_css(font_path: str, family: str = "ACBrandFont"):
    if not os.path.exists(font_path):
        return
    ext = os.path.splitext(font_path)[1].lower()
    mime = "font/ttf" if ext == ".ttf" else "font/otf"
    fmt  = "truetype" if ext == ".ttf" else "opentype"
    try:
        with open(font_path, "rb") as f:
            b64 = base64.b64encode(f.read()).decode("utf-8")
    except Exception:
        return
    st.markdown(
        f"""
        <style>
          @font-face {{
            font-family: '{family}';
            src: url(data:{mime};base64,{b64}) format('{fmt}');
            font-weight: normal; font-style: normal; font-display: swap;
          }}
          html, body, [class*="css"] {{
            font-family: '{family}', -apple-system, BlinkMacSystemFont, "Segoe UI",
                         Roboto, "Helvetica Neue", Arial, "Noto Sans", sans-serif !important;
          }}
          h1,h2,h3,h4,h5,h6, .stTabs [role="tab"] {{
            font-family: '{family}', sans-serif !important;
          }}
          section.main > div {{ padding-top: 0.6rem; }}
        </style>
        """,
        unsafe_allow_html=True,
    )

def _font_candidates():
    cands = []
    secrets_font = st.secrets.get("branding", {}).get("font_file")
    if secrets_font:
        cands.append(secrets_font)
    cands += [
        "company_font.ttf", "company_font.otf",
        "ACBrandFont.ttf", "ACBrandFont.otf",
        "FounderGroteskCondensed-Regular.otf",
        "Cairo-Regular.ttf",
    ]
    try:
        cands += sorted(glob.glob("fonts/*.ttf")) + sorted(glob.glob("fonts/*.otf"))
    except Exception:
        pass
    return cands

def _apply_brand_font():
    fam = st.secrets.get("branding", {}).get("font_family", "ACBrandFont")
    for p in _font_candidates():
        if os.path.exists(p):
            _inject_font_css(p, family=fam)
            return

def render_header():
    _apply_brand_font()
    c_logo, c_title, c_user = st.columns([1.2, 6, 3], gap="small")
    with c_logo:
        if os.path.exists("company_logo.jpeg"):
            try:
                st.image("company_logo.jpeg", use_container_width=True)
            except TypeError:
                st.image("company_logo.jpeg", use_column_width=True)
    with c_title:
        st.markdown(f"### {APP_TITLE}")
        st.caption(SUBTITLE)
    with c_user:
        username = st.session_state.get("username", "")
        role = st.session_state.get("role", "")
        st.markdown(
            f"""<div style=\"display:flex; align-items:center; justify-content:flex-end; gap:1rem;\">\
                   <div>\
                     <div style=\"font-weight:600;\">Welcome, {username or '—'}</div>\
                     <div>Role: <b>{role or '—'}</b></div>\
                   </div>\
                 </div>""",
            unsafe_allow_html=True,
        )
        if st.session_state.get("authenticated") and st.button("Logout"):
            do_logout()

    st.markdown("<hr style='margin-top:0.8rem;'>", unsafe_allow_html=True)

def hide_table_toolbar_for_non_admin():
    if st.session_state.get("role") != "Admin":
        st.markdown(
            """
            <style>
              div[data-testid="stDataFrame"] div[data-testid="stElementToolbar"] { display:none !important; }
              div[data-testid="stDataEditor"]  div[data-testid="stElementToolbar"] { display:none !important; }
              div[data-testid="stElementToolbar"] { display:none !important; }
            </style>
            """,
            unsafe_allow_html=True
        )

# =============================================================================
# GOOGLE SHEETS & DRIVE
# =============================================================================

# ---- Scopes ----
SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive",
]

# ---- FIXED: Service Account loader ----
def _load_sa_info() -> dict:
    """
    Load service account JSON from Streamlit secrets or env, and normalize newlines in private_key.
    Supported sources:
      - st.secrets['gcp_service_account'] (dict or JSON string)
      - env GOOGLE_SERVICE_ACCOUNT_JSON (JSON string)
    """
    sa = st.secrets["gcp_service_account"]
    sa[private_key = """-----BEGIN PRIVATE KEY-----
\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDbUw5JakRNW47X
\njAKWa8xkBHl5+Z8I4q5z6vK2UhAjOcJWKBHNB+XvWDUowr0d2FYmrvSfbIVK3K7w
\n1xncl0t5OwDx1quJKcoZnUoirf5mPkbiPw6FNAT3Gzdyyts7ChShPNHbKWOvzrI2
\nwQzaeA+M+sRQ18lEShtzSqCtDuRgwL6YhRzj9WeFlbZXnR+jLA1E2KMfJT2TTmC5
\nTN+BWBzXRsXuYCl+B1s+zuIPPDXyv0p1z34pNtJb4fmzoyToSSU4FYbfw3YXu2+C
\new//YLGpKBG/X8PudSWg4c9Lsamczv+I30m8tRNEIHmTJQVpPS/N3ZJQ9Ey+rSpz
\n0Y/F058zAgMBAAECggEAXI+sX2J4SfeCjMhbjTUYcPuMcuRc8GiOfIBjB3wRsHQf
\nZrIJdTDIox7kbHvnSXG0RiYfOisYA/Sn5h+5m+XEJfk3WFkjUsNutimyEHnC/E57
\nJt+61o+SKuFzIMCpDj0eYL/kxywsFJXUk5QcwxTZZ0Or13yCRg5KkHkl33OCAax+
\njoGUtW7O254l2Ued+V5Gpfv7LKOlANp/a68wjoW5cn4aGQcyNQxL2nelXSvSjir1
\n7YVpx5thVuSpRzjm6wznSwY2caf5Kn6Gn0Kc52U8/6r6olWhf0WLEIbbmqOtwnE0
\nM8SAqOVBBX5bpDG18y3EERS8FVAxDiXdNWu3j6IH7QKBgQDzn3AMCHKG7c2WoXal
\nBs/oI2vtLLYUvE/uULxpLlMkxPBqBCEZs/MToWblQsonzzvEHqiyikv9wBFL+Fy5
\nwrU9BSlGxKHOoP2aJUdnoXLaDmZUf3ojkbMnT3nx47/OF21j1lHo1x5EJ79MlBu6
\ncjRRZvaKqUwBHRD8Gfs8L0695wKBgQDmd5fY925Yax9qRGgjCHb30RCpL9V4oQTg
\ninZi9GZkAWdL1PuxCmp1/QNvRU4oy5ygHiuG5F3GAVPYRtJ/kL4PI3TaAv90sRaF
\nWtIlmzb0TYW+z5g2gooTjM4gMN2nNNjukayItOxWZlfmd4wmMpMpQ4rwOAtiTzFs
\nCH+YgfOy1QKBgF+lnxX6UwyKXIbhCXWtAP9AuOS7AxmM/UyxQeeBmn77GvBkgqJW
\ntf5lBcLIwBl1ER/kcZL3HPKY77GF5tG/kexNFHGGTYiUSDy2mhwjlLXrpV1TVx6T
\n22R5nYTMR8egBwCFak8h9e4INODZ3TEMGWJELFMwOHjPcpWnla2BXUbNAoGBALQK
\nBzCykpw2CxOcHvIHQdD0nJxextf2ifXTlQpWvMoxIn3mAz1Z0rMblZxOOvG5pkCb
\ncQtuySbOkK5rHTQUYbU30KgjIWcKlHpW6cYBDBwrl2jpiZJDxhPhsoEJS468xR8R
\n5APjuqEAUHi1OWH5rmbU4ewpDBOfpA8uUGdWVYeFAoGAVSobeFTS3zImrkQzqkhK
\neIlPOcJAzpv4bK/K0A/kgbRQvAJ/W/ybDfbnnPk9tibDfBz3Kuh4NTPxE9PUTSvc
\n5tc+7tik8j8XN9t1zNCZtfU4C/5efuD0g96x0zsBPwEsRjNTQLVQJtyhItssv+tI
\n92jEgIErZzvy2Ny/BUYx2eM=\n
-----END PRIVATE KEY-----\n"""] = sa[private_key = """-----BEGIN PRIVATE KEY-----
\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDbUw5JakRNW47X
\njAKWa8xkBHl5+Z8I4q5z6vK2UhAjOcJWKBHNB+XvWDUowr0d2FYmrvSfbIVK3K7w
\n1xncl0t5OwDx1quJKcoZnUoirf5mPkbiPw6FNAT3Gzdyyts7ChShPNHbKWOvzrI2
\nwQzaeA+M+sRQ18lEShtzSqCtDuRgwL6YhRzj9WeFlbZXnR+jLA1E2KMfJT2TTmC5
\nTN+BWBzXRsXuYCl+B1s+zuIPPDXyv0p1z34pNtJb4fmzoyToSSU4FYbfw3YXu2+C
\new//YLGpKBG/X8PudSWg4c9Lsamczv+I30m8tRNEIHmTJQVpPS/N3ZJQ9Ey+rSpz
\n0Y/F058zAgMBAAECggEAXI+sX2J4SfeCjMhbjTUYcPuMcuRc8GiOfIBjB3wRsHQf
\nZrIJdTDIox7kbHvnSXG0RiYfOisYA/Sn5h+5m+XEJfk3WFkjUsNutimyEHnC/E57
\nJt+61o+SKuFzIMCpDj0eYL/kxywsFJXUk5QcwxTZZ0Or13yCRg5KkHkl33OCAax+
\njoGUtW7O254l2Ued+V5Gpfv7LKOlANp/a68wjoW5cn4aGQcyNQxL2nelXSvSjir1
\n7YVpx5thVuSpRzjm6wznSwY2caf5Kn6Gn0Kc52U8/6r6olWhf0WLEIbbmqOtwnE0
\nM8SAqOVBBX5bpDG18y3EERS8FVAxDiXdNWu3j6IH7QKBgQDzn3AMCHKG7c2WoXal
\nBs/oI2vtLLYUvE/uULxpLlMkxPBqBCEZs/MToWblQsonzzvEHqiyikv9wBFL+Fy5
\nwrU9BSlGxKHOoP2aJUdnoXLaDmZUf3ojkbMnT3nx47/OF21j1lHo1x5EJ79MlBu6
\ncjRRZvaKqUwBHRD8Gfs8L0695wKBgQDmd5fY925Yax9qRGgjCHb30RCpL9V4oQTg
\ninZi9GZkAWdL1PuxCmp1/QNvRU4oy5ygHiuG5F3GAVPYRtJ/kL4PI3TaAv90sRaF
\nWtIlmzb0TYW+z5g2gooTjM4gMN2nNNjukayItOxWZlfmd4wmMpMpQ4rwOAtiTzFs
\nCH+YgfOy1QKBgF+lnxX6UwyKXIbhCXWtAP9AuOS7AxmM/UyxQeeBmn77GvBkgqJW
\ntf5lBcLIwBl1ER/kcZL3HPKY77GF5tG/kexNFHGGTYiUSDy2mhwjlLXrpV1TVx6T
\n22R5nYTMR8egBwCFak8h9e4INODZ3TEMGWJELFMwOHjPcpWnla2BXUbNAoGBALQK
\nBzCykpw2CxOcHvIHQdD0nJxextf2ifXTlQpWvMoxIn3mAz1Z0rMblZxOOvG5pkCb
\ncQtuySbOkK5rHTQUYbU30KgjIWcKlHpW6cYBDBwrl2jpiZJDxhPhsoEJS468xR8R
\n5APjuqEAUHi1OWH5rmbU4ewpDBOfpA8uUGdWVYeFAoGAVSobeFTS3zImrkQzqkhK
\neIlPOcJAzpv4bK/K0A/kgbRQvAJ/W/ybDfbnnPk9tibDfBz3Kuh4NTPxE9PUTSvc
\n5tc+7tik8j8XN9t1zNCZtfU4C/5efuD0g96x0zsBPwEsRjNTQLVQJtyhItssv+tI
\n92jEgIErZzvy2Ny/BUYx2eM=\n
-----END PRIVATE KEY-----\n"""].replace("\n", "\n")

    raw = st.secrets.get("gcp_service_account", {})
    if isinstance(raw, dict):
        sa = dict(raw)
    elif isinstance(raw, str) and raw.strip():
        try:
            sa = json.loads(raw)
        except Exception:
            sa = {}

    # Optional env fallback
    if not sa:
        env_json = os.environ.get("GOOGLE_SERVICE_ACCOUNT_JSON", "")
        if env_json:
            try:
                sa = json.loads(env_json)
            except Exception:
                pass

    # FIX: Ensure the expected key name and unescape newlines
    pk = sa.get("private_key", "")
    if isinstance(pk, str) and "\\n" in pk:
        sa["private_key"] = pk.replace("\\n", "\n")

    return sa

@st.cache_resource(show_spinner=False)
def _get_creds():
    sa_info = _load_sa_info()
    if not sa_info or "private_key" not in sa_info:
        raise RuntimeError("Service account JSON not found or missing 'private_key'. Put it in secrets as `gcp_service_account`.")
    return Credentials.from_service_account_info(sa_info, scopes=SCOPES)

@st.cache_resource(show_spinner=False)
def _get_gc():
    return gspread.authorize(_get_creds())

@st.cache_resource(show_spinner=False)
def _get_drive():
    return build("drive", "v3", credentials=_get_creds())

@st.cache_resource(show_spinner=False)
def _get_sheet_url():
    return st.secrets.get("sheets", {}).get("url", SHEET_URL_DEFAULT)

def get_sh():
    gc = _get_gc()
    url = _get_sheet_url()
    last_exc = None
    for attempt in range(3):
        try:
            return gc.open_by_url(url)
        except gspread.exceptions.APIError as e:
            last_exc = e
            time.sleep(0.6 * (attempt + 1))
    st.error("Google Sheets API error while opening the spreadsheet. Please confirm access and try again.")
    raise last_exc

# ---- Drive upload helpers ----

def _drive_make_public(file_id: str):
    """Best-effort: make the file viewable by anyone with the link."""
    try:
        drive = _get_drive()
        drive.permissions().create(
            fileId=file_id,
            body={"role": "reader", "type": "anyone"},
            fields="id",
            supportsAllDrives=True,
        ).execute()
    except Exception:
        pass

# FIX: add PDF header sniff
def _is_pdf_bytes(data: bytes) -> bool:
    return isinstance(data, (bytes, bytearray)) and data[:4] == b"%PDF"

def upload_pdf_and_link(uploaded_file, *, prefix: str) -> tuple[str, str]:
    """Upload a PDF to a Shared-drive folder. Return (webViewLink, file_id)."""
    if uploaded_file is None:
        return "", ""

    # Validate MIME and header (defends against renamed files)
    if getattr(uploaded_file, "type", "") not in ("application/pdf", "application/x-pdf", "binary/octet-stream"):
        st.error("Only PDF files are allowed.")
        return "", ""

    data = uploaded_file.getvalue()
    if not _is_pdf_bytes(data):
        st.error("The uploaded file doesn't look like a real PDF.")
        return "", ""

    fname = f"{prefix}_{int(time.time())}.pdf"

    folder_id = st.secrets.get("drive", {}).get("approvals_folder_id", "")
    metadata = {"name": fname}
    if folder_id:
        metadata["parents"] = [folder_id]

    drive = _get_drive()

    media = MediaIoBaseUpload(io.BytesIO(data), mimetype="application/pdf", resumable=False)
    file = drive.files().create(
        body=metadata,
        media_body=media,
        fields="id, webViewLink",
        supportsAllDrives=True,
    ).execute()

    file_id = file.get("id", "")
    link = file.get("webViewLink", "")

    if st.secrets.get("drive", {}).get("public", True):
        _drive_make_public(file_id)

    return link, file_id

# ---- Sheet helpers ----

def _norm_title(t: str) -> str:
    return (t or "").strip().lower()

def _norm_header(h: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (h or "").strip().lower())

def _canon_header(h: str) -> str:
    key = _norm_header(h)
    return HEADER_SYNONYMS.get(key, h.strip())

def canon_inventory_columns(df: pd.DataFrame) -> pd.DataFrame:
    rename = {}
    drop_cols = []
    for c in df.columns:
        key = _norm_header(c)
        if key in INVENTORY_HEADER_SYNONYMS:
            new = INVENTORY_HEADER_SYNONYMS[key]
            if new:
                rename[c] = new
            else:
                drop_cols.append(c)
    if rename:
        df = df.rename(columns=rename)
    if drop_cols:
        df = df.drop(columns=drop_cols)
    # 🔧 Cast ALL columns to string to avoid Arrow serialization issues
    df = df.astype(str)
    return df

def reorder_columns(df: pd.DataFrame, desired: list[str]) -> pd.DataFrame:
    for c in desired:
        if c not in df.columns:
            df[c] = ""
    tail = [c for c in df.columns if c not in desired]
    return df[desired + tail]

def _find_ws_candidates(title: str):
    sh = get_sh()
    target = _norm_title(title)
    return [ws for ws in sh.worksheets() if _norm_title(ws.title) == target]

def _score_header(values: list[list[str]], expected_canon: set[str]) -> tuple[int, int]:
    best_idx, best_count = 0, 0
    rows_to_scan = min(len(values), 10)
    for i in range(rows_to_scan):
        row = values[i]
        canon = {_canon_header(c) for c in row if str(c).strip()}
        overlap = len(canon & expected_canon)
        if overlap > best_count:
            best_idx, best_count = i, overlap
    return best_idx, best_count

def _read_ws_as_dataframe(ws: gspread.Worksheet, expected_cols: list[str]) -> tuple[pd.DataFrame, int, int]:
    values = ws.get_all_values() or []
    if not values:
        return pd.DataFrame(columns=expected_cols), 0, 0

    expected_canon = set(expected_cols)
    header_idx, score = _score_header(values, expected_canon)
    headers_raw = values[header_idx]
    preferred = [HEADER_SYNONYMS.get(_norm_header(h), h) for h in headers_raw]

    data_rows = values[header_idx + 1 :]
    df = pd.DataFrame(data_rows, columns=preferred).replace({None: ""})
    df = df.dropna(how="all").reset_index(drop=True)
    df = reorder_columns(df, expected_cols)
    return df, header_idx, score

def get_employee_ws() -> gspread.Worksheet:
    sh = get_sh()
    ws_id = st.session_state.get("emp_ws_id")
    if ws_id:
        ws = sh.get_worksheet_by_id(ws_id)
        if ws is not None:
            return ws

    cands = _find_ws_candidates(EMPLOYEE_WS)
    if not cands:
        ws = sh.add_worksheet(title=EMPLOYEE_WS, rows=500, cols=80)
        st.session_state.emp_ws_id = ws.id
        return ws

    if len(cands) == 1:
        ws = cands[0]
        st.session_state.emp_ws_id = ws.id
        return ws

    best_ws, best_score = None, -1
    for ws in cands:
        try:
            _, _, score = _read_ws_as_dataframe(ws, EMPLOYEE_CANON_COLS)
            if score > best_score:
                best_ws, best_score = ws, score
        except Exception:
            continue

    ws = best_ws or cands[0]
    st.session_state.emp_ws_id = ws.id
    return ws

def get_or_create_ws(title, rows=500, cols=80):
    sh = get_sh()
    try:
        return sh.worksheet(title)
    except gspread.exceptions.WorksheetNotFound:
        return sh.add_worksheet(title=title, rows=rows, cols=cols)

@st.cache_data(ttl=120, show_spinner=False)
def _read_worksheet_cached(ws_title: str) -> pd.DataFrame:
    if ws_title == EMPLOYEE_WS:
        ws = get_employee_ws()
        df, header_idx, overlap = _read_ws_as_dataframe(ws, EMPLOYEE_CANON_COLS)
        st.session_state.emp_debug = {
            "title": ws.title, "gid": ws.id,
            "header_row": header_idx + 1, "overlap": overlap, "rows": len(df),
        }
        return df
    if ws_title == PENDING_DEVICE_WS:
        ws = get_or_create_ws(PENDING_DEVICE_WS)
        df = pd.DataFrame(ws.get_all_records())
        return reorder_columns(df, PENDING_DEVICE_COLS)
    if ws_title == PENDING_TRANSFER_WS:
        ws = get_or_create_ws(PENDING_TRANSFER_WS)
        df = pd.DataFrame(ws.get_all_records())
        return reorder_columns(df, PENDING_TRANSFER_COLS)

    ws = get_or_create_ws(ws_title)
    data = ws.get_all_records()
    df = pd.DataFrame(data)
    if ws_title == INVENTORY_WS:
        df = canon_inventory_columns(df)
        return reorder_columns(df, INVENTORY_COLS)
    if ws_title == TRANSFERLOG_WS:
        return reorder_columns(df, LOG_COLS)
    return df

def read_worksheet(ws_title):
    try:
        return _read_worksheet_cached(ws_title)
    except Exception as e:
        st.error(f"Error reading sheet '{ws_title}': {e}")
        if ws_title == INVENTORY_WS:   return pd.DataFrame(columns=INVENTORY_COLS)
        if ws_title == TRANSFERLOG_WS: return pd.DataFrame(columns=LOG_COLS)
        if ws_title == EMPLOYEE_WS:    return pd.DataFrame(columns=EMPLOYEE_CANON_COLS)
        if ws_title == PENDING_DEVICE_WS: return pd.DataFrame(columns=PENDING_DEVICE_COLS)
        if ws_title == PENDING_TRANSFER_WS: return pd.DataFrame(columns=PENDING_TRANSFER_COLS)
        return pd.DataFrame()

def write_worksheet(ws_title, df):
    if ws_title == INVENTORY_WS:
        df = canon_inventory_columns(df)
        df = reorder_columns(df, INVENTORY_COLS)
    if ws_title == PENDING_DEVICE_WS:
        df = reorder_columns(df, PENDING_DEVICE_COLS)
    if ws_title == PENDING_TRANSFER_WS:
        df = reorder_columns(df, PENDING_TRANSFER_COLS)
    ws = get_employee_ws() if ws_title == EMPLOYEE_WS else get_or_create_ws(ws_title)
    ws.clear()
    set_with_dataframe(ws, df)
    st.cache_data.clear()

def append_to_worksheet(ws_title, new_data):
    ws = get_employee_ws() if ws_title == EMPLOYEE_WS else get_or_create_ws(ws_title)
    df_existing = pd.DataFrame(ws.get_all_records())
    if ws_title == INVENTORY_WS:
        df_existing = canon_inventory_columns(df_existing)
        df_existing = reorder_columns(df_existing, INVENTORY_COLS)
    if ws_title == PENDING_DEVICE_WS:
        df_existing = reorder_columns(df_existing, PENDING_DEVICE_COLS)
    if ws_title == PENDING_TRANSFER_WS:
        df_existing = reorder_columns(df_existing, PENDING_TRANSFER_COLS)
    df_combined = pd.concat([df_existing, new_data], ignore_index=True)
    set_with_dataframe(ws, df_combined)
    st.cache_data.clear()

# =============================================================================
# HELPERS
# =============================================================================

def normalize_serial(s: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", (s or "").strip().upper())

def levenshtein(a: str, b: str, max_dist: int = 1) -> int:
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if abs(la - lb) > max_dist:
        return max_dist + 1
    if la > lb:
        a, b = b, a
        la, lb = lb, la
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        row_min = cur[0]
        ai = a[i - 1]
        for j in range(1, lb + 1):
            cost = 0 if ai == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            row_min = min(row_min, cur[j])
        if row_min > max_dist:
            return max_dist + 1
        prev = cur
    return prev[-1]

def unique_nonempty(df: pd.DataFrame, col: str) -> list[str]:
    if df.empty or col not in df.columns:
        return []
    vals = [str(x).strip() for x in df[col].dropna().astype(str).tolist()]
    return sorted({v for v in vals if v})

def select_with_other(label: str, base_options: list[str], existing_values: list[str]) -> str:
    merged = [o for o in base_options if o]
    for v in existing_values:
        if v and v not in merged:
            merged.append(v)
    sel = st.selectbox(label, ["— Select —"] + merged + ["Other…"])
    if sel == "Other…":
        return st.text_input(f"{label} (Other)")
    return "" if sel == "— Select —" else sel

# =============================================================================
# VIEWS
# =============================================================================

def employees_view_tab():
    st.subheader("📇 Employees (mainlists)")
    df = read_worksheet(EMPLOYEE_WS)
    if df.empty:
        st.info("No employees found in 'mainlists'.")
    else:
        st.dataframe(df, use_container_width=True, hide_index=True)

def inventory_tab():
    st.subheader("📋 Inventory")
    df = read_worksheet(INVENTORY_WS)
    if df.empty:
        st.warning("Inventory is empty.")
    else:
        if st.session_state.role == "Admin":
            st.dataframe(df, use_container_width=True)
        else:
            st.dataframe(df, use_container_width=True, hide_index=True)

def register_device_tab():
    st.subheader("📝 Register New Device")

    # Pull employee names for quick assignment options
    emp_df = read_worksheet(EMPLOYEE_WS)
    emp_names = sorted({
        *unique_nonempty(emp_df, "New Employeer"),
        *unique_nonempty(emp_df, "Name"),
    })

    with st.form("register_device", clear_on_submit=True):
        r1c1, r1c2, r1c3 = st.columns(3)
        with r1c1:
            serial = st.text_input("Serial Number *")
        with r1c2:
            assigned_choice = st.selectbox(
                "Assigned to",
                [UNASSIGNED_LABEL] + emp_names + ["Type a new name…"],
                help="Choose 'Unassigned (Stock)' if the device has no owner yet."
            )
            if assigned_choice == "Type a new name…":
                assigned_to = st.text_input("Assignee name")
            elif assigned_choice == UNASSIGNED_LABEL:
                assigned_to = UNASSIGNED_LABEL
            else:
                assigned_to = assigned_choice
        with r1c3:
            device = st.text_input("Device Type *")

        r2c1, r2c2, r2c3 = st.columns(3)
        with r2c1:
            brand  = st.text_input("Brand")
        with r2c2:
            model  = st.text_input("Model")
        with r2c3:
            cpu    = st.text_input("CPU")

        r3c1, r3c2, r3c3 = st.columns(3)
        with r3c1:
            mem    = st.text_input("Memory")
        with r3c2:
            hdd1   = st.text_input("Hard Drive 1")
        with r3c3:
            hdd2   = st.text_input("Hard Drive 2")

        r4c1, r4c2, r4c3 = st.columns(3)
        with r4c1:
            gpu    = st.text_input("GPU")
        with r4c2:
            screen = st.text_input("Screen Size")
        with r4c3:
            email  = st.text_input("Email Address")

        r5c1, r5c2, r5c3 = st.columns(3)
        with r5c1:
            contact = st.text_input("Contact Number")
        with r5c2:
            dept   = st.text_input("Department")
        with r5c3:
            location = st.text_input("Location")

        r6c1, r6c2 = st.columns([1, 2])
        with r6c1:
            office = st.text_input("Office")
        with r6c2:
            notes  = st.text_area("Notes", height=60)

        # Require approval PDF for non-admin submissions
        pdf_file = st.file_uploader("Approval PDF (required for non-admin)", type=["pdf"])

        submitted = st.form_submit_button("Save Device", type="primary")

    if submitted:
        if not serial.strip() or not device.strip():
            st.error("Serial Number and Device Type are required.")
            return
        s_norm = normalize_serial(serial)
        if not s_norm:
            st.error("Serial Number cannot be blank after normalization.")
            return

        inv = read_worksheet(INVENTORY_WS)
        if not inv.empty:
            inv["__snorm"] = inv["Serial Number"].astype(str).map(normalize_serial)
            if s_norm in set(inv["__snorm"]):
                existing = inv[inv["__snorm"] == s_norm].iloc[0]
                st.error(
                    f"Duplicate serial. Already exists as '{existing['Serial Number']}' ("
                    f"{existing.get('Device Type','')} {existing.get('Brand','')}/{existing.get('Model','')})."
                )
                return
            near_mask = inv["__snorm"].apply(lambda x: levenshtein(s_norm, x, max_dist=1) <= 1)
            near = inv[near_mask]
            if not near.empty:
                similar_list = near["Serial Number"].astype(str).unique().tolist()
                st.warning("Near-duplicate serials: " + ", ".join(similar_list))

        now_str = datetime.now().strftime(DATE_FMT)
        actor   = st.session_state.get("username", "")

        row = {
            "Serial Number": serial.strip(),
            "Device Type": device.strip(),
            "Brand": brand.strip(),
            "Model": model.strip(),
            "CPU": cpu.strip(),
            "Hard Drive 1": hdd1.strip(),
            "Hard Drive 2": hdd2.strip(),
            "Memory": mem.strip(),
            "GPU": gpu.strip(),
            "Screen Size": screen.strip(),
            "Current user": assigned_to.strip(),
            "Previous User": "",
            "TO": assigned_to.strip() if assigned_to.strip() and assigned_to.strip() != UNASSIGNED_LABEL else "",
            "Department": dept.strip(),
            "Email Address": email.strip(),
            "Contact Number": contact.strip(),
            "Location": location.strip(),
            "Office": office.strip(),
            "Notes": notes.strip(),
            "Date issued": now_str,
            "Registered by": actor,
        }

        is_admin = st.session_state.get("role") == "Admin"
        if not is_admin and pdf_file is None:
            st.error("Approval PDF is required for submission.")
            return

        if is_admin and pdf_file is None:
            inv_fresh = read_worksheet(INVENTORY_WS)
            inv_out = pd.concat([
                inv_fresh if not inv_fresh.empty else pd.DataFrame(columns=INVENTORY_COLS),
                pd.DataFrame([row])
            ], ignore_index=True)
            inv_out = reorder_columns(inv_out, INVENTORY_COLS)
            write_worksheet(INVENTORY_WS, inv_out)
            st.success("✅ Device registered and added to Inventory.")
        else:
            link, fid = upload_pdf_and_link(pdf_file, prefix=f"device_{s_norm}")
            if not fid:
                return
            pending = {**row,
                "Approval Status": "Pending",
                "Approval PDF": link,
                "Approval File ID": fid,
                "Submitted by": actor,
                "Submitted at": now_str,
                "Approver": "",
                "Decision at": "",
            }
            append_to_worksheet(PENDING_DEVICE_WS, pd.DataFrame([pending]))
            st.success("🕒 Submitted for admin approval. You'll see it in Inventory once approved.")

def transfer_tab():
    st.subheader("🔁 Transfer Device")
    inventory_df = read_worksheet(INVENTORY_WS)
    if inventory_df.empty:
        st.warning("Inventory is empty.")
        return

    serial_list = sorted(inventory_df["Serial Number"].dropna().astype(str).unique().tolist())
    serial = st.selectbox("Serial Number", ["— Select —"] + serial_list)
    chosen_serial = None if serial == "— Select —" else serial

    existing_users = sorted([u for u in inventory_df["Current user"].dropna().astype(str).tolist() if u.strip()])
    new_owner_choice = st.selectbox("New Owner", ["— Select —"] + existing_users + ["Type a new name…"])
    if new_owner_choice == "Type a new name…":
        new_owner = st.text_input("Enter new owner name")
    else:
        new_owner = new_owner_choice if new_owner_choice != "— Select —" else ""

    pdf_file = st.file_uploader("Approval PDF (required for non-admin)", type=["pdf"], key="transfer_pdf")

    is_admin = st.session_state.get("role") == "Admin"
    do_transfer = st.button("Transfer Now", type="primary", disabled=not (chosen_serial and new_owner.strip()))

    if do_transfer:
        match = inventory_df[inventory_df["Serial Number"].astype(str) == chosen_serial]
        if match.empty:
            st.warning("Serial number not found.")
            return

        idx = match.index[0]
        prev_user = str(inventory_df.loc[idx, "Current user"] or "")
        now_str   = datetime.now().strftime(DATE_FMT)
        actor     = st.session_state.get("username", "")

        if not is_admin and pdf_file is None:
            st.error("Approval PDF is required for submission.")
            return

        if is_admin and pdf_file is None:
            inventory_df.loc[idx, "Previous User"] = prev_user
            inventory_df.loc[idx, "Current user"]  = new_owner.strip()
            inventory_df.loc[idx, "TO"]            = new_owner.strip()
            inventory_df.loc[idx, "Date issued"]   = now_str
            inventory_df.loc[idx, "Registered by"] = actor

            inventory_df = reorder_columns(inventory_df, INVENTORY_COLS)
            write_worksheet(INVENTORY_WS, inventory_df)

            log_row = {
                "Device Type": inventory_df.loc[idx, "Device Type"],
                "Serial Number": chosen_serial,
                "From owner": prev_user,
                "To owner": new_owner.strip(),
                "Date issued": now_str,
                "Registered by": actor,
            }
            append_to_worksheet(TRANSFERLOG_WS, pd.DataFrame([log_row]))
            st.success(f"✅ Transfer saved: {prev_user or '(blank)'} → {new_owner.strip()}")
        else:
            link, fid = upload_pdf_and_link(pdf_file, prefix=f"transfer_{normalize_serial(chosen_serial)}")
            if not fid:
                return
            pend = {
                "Device Type": inventory_df.loc[idx, "Device Type"],
                "Serial Number": chosen_serial,
                "From owner": prev_user,
                "To owner": new_owner.strip(),
                "Date issued": now_str,
                "Registered by": actor,
                "Approval Status": "Pending",
                "Approval PDF": link,
                "Approval File ID": fid,
                "Submitted by": actor,
                "Submitted at": now_str,
                "Approver": "",
                "Decision at": "",
            }
            append_to_worksheet(PENDING_TRANSFER_WS, pd.DataFrame([pend]))
            st.success("🕒 Transfer submitted for admin approval.")

def history_tab():
    st.subheader("📜 Transfer Log")
    df = read_worksheet(TRANSFERLOG_WS)
    if df.empty:
        st.info("No transfer history found.")
    else:
        st.dataframe(df, use_container_width=True, hide_index=True)

# =============================================================================
# Employee Register (updated)
# =============================================================================

def employee_register_tab():
    st.subheader("🧑‍💼 Register New Employee (mainlists)")
    emp_df = read_worksheet(EMPLOYEE_WS)

    # Suggested numeric ID
    try:
        ids = pd.to_numeric(emp_df["Employee ID"], errors="coerce").dropna().astype(int)
        next_id_suggestion = str(ids.max() + 1) if len(ids) else str(len(emp_df) + 1)
    except Exception:
        next_id_suggestion = str(len(emp_df) + 1)

    # Dropdown sources from existing data
    dept_existing = unique_nonempty(emp_df, "Department")
    pos_existing  = unique_nonempty(emp_df, "Position")
    proj_existing = unique_nonempty(emp_df, "Project")
    loc_existing  = unique_nonempty(emp_df, "Location (KSA)")

    ksa_cities = [
        "Riyadh", "Jeddah", "Dammam", "Khobar", "Dhahran", "Jubail",
        "Mecca", "Medina", "Abha", "Tabuk", "Hail", "Buraidah"
    ]

    with st.form("register_employee", clear_on_submit=True):
        r1c1, r1c2, r1c3 = st.columns(3)
        with r1c1:
            emp_name = st.text_input("New Employeer *")
        with r1c2:
            emp_id = st.text_input("Employee ID", help=f"Suggested next ID: {next_id_suggestion}")
        with r1c3:
            new_sig = st.selectbox("New Signature", ["— Select —", "Yes", "No", "Requested"])

        r2c1, r2c2 = st.columns(2)
        with r2c1:
            Email = st.text_input("Email")
        with r2c2:
            active = st.selectbox("Active", ["Active", "Inactive", "Onboarding", "Resigned"])

        r3c1, r3c2, r3c3 = st.columns(3)
        with r3c1:
            position = select_with_other("Position", ["Engineer", "Technician", "Manager", "Coordinator"], pos_existing)
        with r3c2:
            department = select_with_other("Department", ["IT", "HR", "Finance", "Operations", "Procurement"], dept_existing)
        with r3c3:
            location_ksa = select_with_other("Location (KSA)", ksa_cities, loc_existing)

        r4c1, r4c2, r4c3 = st.columns(3)
        with r4c1:
            project = select_with_other("Project", ["Head Office", "Site"], proj_existing)
        with r4c2:
            teams = st.selectbox("Microsoft Teams", ["— Select —", "Yes", "No", "Requested"])
        with r4c3:
            mobile = st.text_input("Mobile Number")

        submitted = st.form_submit_button("Save Employee", type="primary")

    if submitted:
        if not emp_name.strip():
            st.error("New Employeer is required.")
            return
        if emp_id.strip() and not emp_df.empty and emp_id.strip() in emp_df["Employee ID"].astype(str).values:
            st.error(f"Employee ID '{emp_id}' already exists.")
            return

        row = {
            "New Employeer": emp_name.strip(),
            "Name": emp_name.strip(),
            "Employee ID": emp_id.strip() if emp_id.strip() else next_id_suggestion,
            "New Signature": new_sig if new_sig != "— Select —" else "",
            "Email": Email.strip(),
            "Active": active.strip(),
            "Position": position.strip(),
            "Department": department.strip(),
            "Location (KSA)": location_ksa.strip(),
            "Project": project.strip(),
            "Microsoft Teams": teams if teams != "— Select —" else "",
            "Mobile Number": mobile.strip(),
        }
        new_df = pd.concat([emp_df, pd.DataFrame([row])], ignore_index=True) if not emp_df.empty else pd.DataFrame([row])
        new_df = reorder_columns(new_df, EMPLOYEE_CANON_COLS)
        write_worksheet(EMPLOYEE_WS, new_df)
        st.success("✅ Employee saved to 'mainlists'.")

# =============================================================================
# Approvals dashboard (Admin only)
# =============================================================================

def approvals_tab():
    st.subheader("✅ Approvals (Admin)")
    if st.session_state.get("role") != "Admin":
        st.info("Only Admins can view approvals.")
        return

    pending_dev = read_worksheet(PENDING_DEVICE_WS)
    pending_tr  = read_worksheet(PENDING_TRANSFER_WS)

    # Devices
    st.markdown("### Pending Device Registrations")
    df_dev = pending_dev[pending_dev["Approval Status"].isin(["", "Pending"])].reset_index(drop=True)
    if df_dev.empty:
        st.success("No pending device registrations.")
    else:
        for i, row in df_dev.iterrows():
            with st.expander(f"{row['Device Type']} — SN {row['Serial Number']} (by {row['Submitted by']})", expanded=False):
                c1, c2 = st.columns([3,2])
                with c1:
                    info = {k: row.get(k, "") for k in INVENTORY_COLS}
                    st.json(info)
                    if row.get("Approval PDF"):
                        st.markdown(f"[Open Approval PDF]({row['Approval PDF']})")
                with c2:
                    a_col, r_col = st.columns(2)
                    if a_col.button("Approve", key=f"approve_dev_{i}"):
                        _approve_device_row(row)
                    if r_col.button("Reject", key=f"reject_dev_{i}"):
                        _reject_row(PENDING_DEVICE_WS, i, row)

    st.markdown("---")
    # Transfers
    st.markdown("### Pending Transfers")
    df_tr = pending_tr[pending_tr["Approval Status"].isin(["", "Pending"])].reset_index(drop=True)
    if df_tr.empty:
        st.success("No pending transfers.")
    else:
        for i, row in df_tr.iterrows():
            with st.expander(f"SN {row['Serial Number']}: {row['From owner']} → {row['To owner']} (by {row['Submitted by']})", expanded=False):
                c1, c2 = st.columns([3,2])
                with c1:
                    info = {k: row.get(k, "") for k in LOG_COLS}
                    st.json(info)
                    if row.get("Approval PDF"):
                        st.markdown(f"[Open Approval PDF]({row['Approval PDF']})")
                with c2:
                    a_col, r_col = st.columns(2)
                    if a_col.button("Approve", key=f"approve_tr_{i}"):
                        _approve_transfer_row(row)
                    if r_col.button("Reject", key=f"reject_tr_{i}"):
                        _reject_row(PENDING_TRANSFER_WS, i, row)

def _approve_device_row(row: pd.Series):
    inv = read_worksheet(INVENTORY_WS)
    now_str = datetime.now().strftime(DATE_FMT)
    approver = st.session_state.get("username", "")

    new_row = {k: row.get(k, "") for k in INVENTORY_COLS}
    new_row["Registered by"] = approver or new_row.get("Registered by", "")
    new_row["Date issued"] = now_str

    inv_out = pd.concat([
        inv if not inv.empty else pd.DataFrame(columns=INVENTORY_COLS),
        pd.DataFrame([new_row])
    ], ignore_index=True)
    write_worksheet(INVENTORY_WS, inv_out)

    _mark_decision(PENDING_DEVICE_WS, row, status="Approved")
    st.success("✅ Device approved and added to Inventory.")

def _approve_transfer_row(row: pd.Series):
    inv = read_worksheet(INVENTORY_WS)
    if inv.empty:
        st.error("Inventory is empty; cannot apply transfer.")
        return
    sn = str(row.get("Serial Number", ""))
    match = inv[inv["Serial Number"].astype(str) == sn]
    if match.empty:
        st.error("Serial not found in Inventory.")
        return

    idx = match.index[0]
    now_str = datetime.now().strftime(DATE_FMT)
    approver = st.session_state.get("username", "")

    prev_user = str(inv.loc[idx, "Current user"] or "")
    inv.loc[idx, "Previous User"] = prev_user
    inv.loc[idx, "Current user"]  = str(row.get("To owner", ""))
    inv.loc[idx, "TO"]            = str(row.get("To owner", ""))
    inv.loc[idx, "Date issued"]   = now_str
    inv.loc[idx, "Registered by"] = approver
    write_worksheet(INVENTORY_WS, inv)

    log_row = {k: row.get(k, "") for k in LOG_COLS}
    log_row["Date issued"] = now_str
    log_row["Registered by"] = approver
    append_to_worksheet(TRANSFERLOG_WS, pd.DataFrame([log_row]))

    _mark_decision(PENDING_TRANSFER_WS, row, status="Approved")
    st.success("✅ Transfer approved and applied.")

def _mark_decision(ws_title: str, row: pd.Series, *, status: str):
    df = read_worksheet(ws_title)
    key_cols = [c for c in ["Serial Number", "Submitted at", "Submitted by", "To owner"] if c in df.columns]
    mask = pd.Series([True] * len(df))
    for c in key_cols:
        mask &= df[c].astype(str) == str(row.get(c, ""))
    if not mask.any():
        if "Serial Number" in df.columns:
            mask = df["Serial Number"].astype(str) == str(row.get("Serial Number", ""))
    idxs = df[mask].index.tolist()
    if not idxs:
        return
    idx = idxs[0]
    df.loc[idx, "Approval Status"] = status
    df.loc[idx, "Approver"] = st.session_state.get("username", "")
    df.loc[idx, "Decision at"] = datetime.now().strftime(DATE_FMT)
    write_worksheet(ws_title, df)

def _reject_row(ws_title: str, i: int, row: pd.Series):
    _mark_decision(ws_title, row, status="Rejected")
    st.info("❌ Request rejected.")

# =============================================================================
# Export
# =============================================================================

def export_tab():
    st.subheader("⬇️ Export (always fresh)")
    inv = read_worksheet(INVENTORY_WS)
    log = read_worksheet(TRANSFERLOG_WS)
    emp = read_worksheet(EMPLOYEE_WS)

    st.caption(f"Last fetched: {datetime.now().strftime(DATE_FMT)}")
    c1, c2, c3 = st.columns(3)
    with c1:
        st.download_button("Inventory CSV", inv.to_csv(index=False).encode("utf-8"), "inventory.csv", "text/csv")
    with c2:
        st.download_button("Transfer Log CSV", log.to_csv(index=False).encode("utf-8"), "transfer_log.csv", "text/csv")
    with c3:
        st.download_button("Employees CSV", emp.to_csv(index=False).encode("utf-8"), "employees.csv", "text/csv")

    st.markdown("---")
    st.markdown("**Approvals (Accepted)**")
    approved_dev = read_worksheet(PENDING_DEVICE_WS)
    approved_tr  = read_worksheet(PENDING_TRANSFER_WS)
    approved_dev = approved_dev[approved_dev.get("Approval Status", "").astype(str) == "Approved"] if not approved_dev.empty else approved_dev
    approved_tr  = approved_tr[approved_tr.get("Approval Status", "").astype(str) == "Approved"] if not approved_tr.empty else approved_tr

    c4, c5 = st.columns(2)
    with c4:
        if not approved_dev.empty:
            st.download_button(
                "Approved Device Submissions CSV",
                approved_dev.to_csv(index=False).encode("utf-8"),
                "approved_device_submissions.csv",
                "text/csv",
            )
        else:
            st.caption("No approved device submissions yet.")
    with c5:
        if not approved_tr.empty:
            st.download_button(
                "Approved Transfer Submissions CSV",
                approved_tr.to_csv(index=False).encode("utf-8"),
                "approved_transfer_submissions.csv",
                "text/csv",
            )
        else:
            st.caption("No approved transfer submissions yet.")

# =============================================================================
# MAIN
# =============================================================================

def run_app():
    render_header()
    hide_table_toolbar_for_non_admin()

    if st.session_state.role == "Admin":
        tabs = st.tabs([
            "🧑‍💼 Employee Register",
            "📇 View Employees",
            "📝 Register Device",
            "📋 View Inventory",
            "🔁 Transfer Device",
            "📜 Transfer Log",
            "✅ Approvals",
            "⬇️ Export",
        ])
        with tabs[0]: employee_register_tab()
        with tabs[1]: employees_view_tab()
        with tabs[2]: register_device_tab()
        with tabs[3]: inventory_tab()
        with tabs[4]: transfer_tab()
        with tabs[5]: history_tab()
        with tabs[6]: approvals_tab()
        with tabs[7]: export_tab()
    else:
        tabs = st.tabs(["📝 Register Device", "🔁 Transfer Device", "📋 View Inventory", "📜 Transfer Log"])
        with tabs[0]: register_device_tab()
        with tabs[1]: transfer_tab()
        with tabs[2]: inventory_tab()
        with tabs[3]: history_tab()

# =============================================================================
# ENTRY
# =============================================================================
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "just_logged_out" not in st.session_state:
    st.session_state.just_logged_out = False

# Try to restore session from cookie when not logged in and not just logged out
if not st.session_state.authenticated and not st.session_state.get("just_logged_out"):
    payload = _read_cookie()
    if payload:
        st.session_state.authenticated = True
        st.session_state.username = payload["u"]
        st.session_state.name = payload["u"]
        st.session_state.role = payload.get("r", "")

if st.session_state.authenticated:
    run_app()
else:
    st.subheader("🔐 Sign In")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login", type="primary"):
        user = USERS.get(username)
        if user and _verify_password(password, user["password"]):
            do_login(username, user.get("role", "Staff"))  # sets cookie + rerun
        else:
            st.error("❌ Invalid username or password.")
