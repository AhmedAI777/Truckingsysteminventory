# =============================================================================
# IMPORTS
# =============================================================================
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

import pandas as pd
import requests
import streamlit as st
import gspread
import extra_streamlit_components as stx
from streamlit import session_state as ss
from streamlit_pdf_viewer import pdf_viewer
from gspread_dataframe import set_with_dataframe

from google.oauth2.service_account import Credentials
from google.oauth2.credentials import Credentials as UserCredentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload
from googleapiclient.errors import HttpError

# --- Streamlit must call set_page_config first ---
st.set_page_config(page_title="Tracking Inventory Management System", layout="wide")

# =============================================================================
# CONFIG
# =============================================================================
APP_TITLE = "Tracking Inventory Management System"
SUBTITLE = "Advanced Construction"

DATE_FMT = "%Y-%m-%d %H:%M:%S"
SESSION_TTL_DAYS = 30
SESSION_TTL_SECONDS = SESSION_TTL_DAYS * 24 * 60 * 60
COOKIE_NAME = "ac_auth_v2"

SHEET_URL_DEFAULT = "https://docs.google.com/spreadsheets/d/1SHp6gOW4ltsyOT41rwo85e_LELrHkwSwKN33K6XNHFI/edit"

INVENTORY_WS = "truckinventory"
TRANSFERLOG_WS = "transfer_log"
EMPLOYEE_WS = "mainlists"
PENDING_DEVICE_WS = "pending_device_reg"
PENDING_TRANSFER_WS = "pending_transfers"

INVENTORY_COLS = [
    "Serial Number", "Device Type", "Brand", "Model", "CPU",
    "Hard Drive 1", "Hard Drive 2", "Memory", "GPU", "Screen Size",
    "Current user", "Previous User", "TO", "Department",
    "Email Address", "Contact Number", "Location", "Office",
    "Notes", "Date issued", "Registered by"
]

LOG_COLS = [
    "Device Type", "Serial Number", "From owner",
    "To owner", "Date issued", "Registered by"
]

EMPLOYEE_CANON_COLS = [
    "New Employeer", "Employee ID", "New Signature", "Name", "Address",
    "Active", "Position", "Department", "Location (KSA)",
    "Project", "Microsoft Teams", "Mobile Number"
]

APPROVAL_META_COLS = [
    "Approval Status", "Approval PDF", "Approval File ID",
    "Submitted by", "Submitted at", "Approver", "Decision at"
]

PENDING_DEVICE_COLS = INVENTORY_COLS + APPROVAL_META_COLS
PENDING_TRANSFER_COLS = LOG_COLS + APPROVAL_META_COLS

UNASSIGNED_LABEL = "Unassigned (Stock)"
REQUIRE_REVIEW_CHECK = True

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

COOKIE_MGR = stx.CookieManager(key="ac_cookie_mgr")

# Pre-init session keys for PDF previews
for k in ("reg_pdf_ref", "transfer_pdf_ref"):
    if k not in ss:
        ss[k] = None

# =============================================================================
# AUTH HELPERS
# =============================================================================
def _load_users_from_secrets():
    users_cfg = st.secrets.get("auth", {}).get("users", [])
    users = {}
    for u in users_cfg:
        users[u["username"]] = {
            "password": u.get("password", ""),
            "role": u.get("role", "Staff")
        }
    return users

USERS = _load_users_from_secrets()

def _verify_password(raw: str, stored: str) -> bool:
    return hmac.compare_digest(str(stored), str(raw))

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
        COOKIE_NAME,
        token,
        expires_at=(datetime.utcnow() + timedelta(seconds=SESSION_TTL_SECONDS))
        if SESSION_TTL_SECONDS > 0 else None,
        secure=st.secrets.get("auth", {}).get("cookie_secure", True),
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


# =============================================================================
# STYLE / BRANDING
# =============================================================================
def _inject_font_css(font_path: str, family: str = "ACBrandFont"):
    """Inject a custom font into Streamlit app from a local file."""
    if not os.path.exists(font_path):
        return
    ext = os.path.splitext(font_path)[1].lower()
    mime = "font/ttf" if ext == ".ttf" else "font/otf"
    fmt = "truetype" if ext == ".ttf" else "opentype"
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
            font-weight: normal;
            font-style: normal;
            font-display: swap;
        }}
        html, body, [class*="css"] {{
            font-family: '{family}', -apple-system, BlinkMacSystemFont, "Segoe UI",
                          Roboto, "Helvetica Neue", Arial, "Noto Sans", sans-serif !important;
        }}
        h1,h2,h3,h4,h5,h6, .stTabs [role="tab"] {{
            font-family: '{family}', sans-serif !important;
        }}
        section.main > div {{
            padding-top: 0.6rem;
        }}
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
    """Top header with logo, title, and user info."""
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
            f"""
            <div style="display:flex; align-items:center; justify-content:flex-end; gap:1rem;">
                <div>
                    <div style="font-weight:600;">Welcome, {username or '—'}</div>
                    <div>Role: <b>{role or '—'}</b></div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.session_state.get("authenticated") and st.button("Logout"):
            do_logout()
    st.markdown("<hr style='margin-top:0.8rem;'>", unsafe_allow_html=True)

def hide_table_toolbar_for_non_admin():
    """Hide the edit toolbar in tables for non-admin users."""
    if st.session_state.get("role") != "Admin":
        st.markdown(
            """
            <style>
            div[data-testid="stDataFrame"] div[data-testid="stElementToolbar"] { display:none !important; }
            div[data-testid="stDataEditor"] div[data-testid="stElementToolbar"] { display:none !important; }
            div[data-testid="stElementToolbar"] { display:none !important; }
            </style>
            """,
            unsafe_allow_html=True,
        )

# =============================================================================
# GOOGLE SHEETS & DRIVE (Service Account + OAuth token fallback)
# =============================================================================
SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive",
]
OAUTH_SCOPES = ["https://www.googleapis.com/auth/drive.file"]  # user upload to My Drive
ALLOW_OAUTH_FALLBACK = st.secrets.get("drive", {}).get("allow_oauth_fallback", True)

def _proj_display_name(code: str) -> str:
    """Pretty project names from code."""
    code = (code or "").upper()
    mapping = {
        "HO": "Head Office (HO)",
        "ST": "Site (ST)",
        "FIN": "Finance (FIN)",
        "IT": "IT (IT)",
    }
    return mapping.get(code, f"{code} ({code})" if code else "Unknown")

def _city_display_name(code: str) -> str:
    """Pretty city names from code."""
    code = (code or "").upper()
    mapping = {
        "RUH": "Riyadh (RUH)",
        "JED": "Jeddah (JED)",
        "TIF": "Taif (TIF)",
        "MED": "Madinah (MED)",
    }
    return mapping.get(code, f"{code} ({code})" if code else "Unknown")

def _type_display_name(type_code: str) -> str:
    """Readable name for register/transfer."""
    return "Register" if (type_code or "").upper() == "REG" else "Transfer"

def _load_sa_info() -> dict:
    """Load Google Service Account credentials from secrets/env."""
    raw = st.secrets.get("gcp_service_account", {})
    sa: dict = {}
    if isinstance(raw, dict):
        sa = dict(raw)
    elif isinstance(raw, str) and raw.strip():
        try:
            sa = json.loads(raw)
        except Exception:
            sa = {}
    if not sa:
        env_json = os.environ.get("GOOGLE_SERVICE_ACCOUNT_JSON", "")
        if env_json:
            try:
                sa = json.loads(env_json)
            except Exception:
                sa = {}
    pk = sa.get("private_key", "")
    if isinstance(pk, str) and "\\n" in pk:
        sa["private_key"] = pk.replace("\\n", "\n")
    if "private_key" not in sa:
        raise RuntimeError("Service account JSON not found or missing 'private_key'.")
    return sa

@st.cache_resource(show_spinner=False)
def _get_creds():
    return Credentials.from_service_account_info(_load_sa_info(), scopes=SCOPES)

@st.cache_resource(show_spinner=False)
def _get_gc():
    return gspread.authorize(_get_creds())

@st.cache_resource(show_spinner=False)
def _get_drive():
    return build("drive", "v3", credentials=_get_creds())

@st.cache_resource(show_spinner=False)
def _get_user_creds():
    """Get user OAuth creds if SA fails."""
    cfg = st.secrets.get("google_oauth", {})
    token_json = cfg.get("token_json")
    if token_json:
        try:
            info = json.loads(token_json)
        except Exception:
            info = None
        if not info:
            st.error("google_oauth.token_json is not valid JSON.")
            st.stop()
        creds = UserCredentials.from_authorized_user_info(info, OAUTH_SCOPES)
        if not creds.valid and creds.refresh_token:
            creds.refresh(Request())
        return creds
    if os.environ.get("LOCAL_OAUTH", "0") == "1":
        client_id = cfg.get("client_id")
        client_secret = cfg.get("client_secret")
        if not client_id or not client_secret:
            st.error("[google_oauth] client_id/client_secret required for local OAuth.")
            st.stop()
        flow = InstalledAppFlow.from_client_config(
            {
                "installed": {
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": ["http://localhost"],
                }
            },
            scopes=OAUTH_SCOPES,
        )
        creds = flow.run_local_server(port=0)
        return creds
    st.error("OAuth token not configured. Add [google_oauth].token_json to secrets.")
    st.stop()

@st.cache_resource(show_spinner=False)
def _get_user_drive():
    return build("drive", "v3", credentials=_get_user_creds())

@st.cache_resource(show_spinner=False)
def _get_sheet_url():
    return st.secrets.get("sheets", {}).get("url", SHEET_URL_DEFAULT)

def get_sh():
    """Open the Google Sheet with retries."""
    gc = _get_gc()
    url = _get_sheet_url()
    last_exc = None
    for attempt in range(3):
        try:
            return gc.open_by_url(url)
        except gspread.exceptions.APIError as e:
            last_exc = e
            time.sleep(0.6 * (attempt + 1))
    st.error("Google Sheets API error while opening the spreadsheet.")
    raise last_exc

# =============================================================================
# GOOGLE DRIVE HELPERS
# =============================================================================
def _drive_make_public(file_id: str, drive_client=None):
    """Make a file public on Drive."""
    try:
        cli = drive_client or _get_drive()
        cli.permissions().create(
            fileId=file_id,
            body={"role": "reader", "type": "anyone"},
            fields="id",
            supportsAllDrives=True,
        ).execute()
    except Exception:
        pass

def _get_drive_client_for_writes():
    try:
        return _get_drive()
    except Exception:
        return _get_user_drive()

def _find_child_folder_id(parent_id: str, name: str) -> str | None:
    """Find exact child folder name under a parent."""
    if not parent_id or not name:
        return None
    drive = _get_drive_client_for_writes()
    q = (
        f"'{parent_id}' in parents and "
        f"name='{name}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
    )
    res = drive.files().list(
        q=q,
        spaces="drive",
        fields="files(id,name)",
        supportsAllDrives=True,
        includeItemsFromAllDrives=True,
    ).execute()
    files = res.get("files", [])
    return files[0]["id"] if files else None

def _create_child_folder(parent_id: str, name: str) -> str:
    drive = _get_drive_client_for_writes()
    file_metadata = {
        "name": name,
        "mimeType": "application/vnd.google-apps.folder",
        "parents": [parent_id],
    }
    folder = drive.files().create(
        body=file_metadata, fields="id", supportsAllDrives=True
    ).execute()
    return folder["id"]

def _ensure_child_folder(parent_id: str, name: str) -> str:
    fid = _find_child_folder_id(parent_id, name)
    return fid or _create_child_folder(parent_id, name)

def _approvals_root_id_from_secrets() -> str:
    drive_cfg = st.secrets.get("drive", {})
    return (
        drive_cfg.get("approvals_root_id")
        or drive_cfg.get("approvals_folder_id")
        or drive_cfg.get("approvals")  # backward-compat key
        or ""
    )

def ensure_folder_tree(project_code: str, city_code: str, type_code: str, status: str | None = None) -> str:
    """
    Ensure Drive tree exists and return the leaf folder ID.

    Structure:
        Approvals/
            Head Office (HO) / Site (ST) / ...
                Riyadh (RUH) / ...
                    Register / Transfer /
                        [Status: Pending/Approved/Rejected]
    """
    root_id = _approvals_root_id_from_secrets()
    if not root_id:
        st.error("[drive] approvals_root_id not configured in secrets.")
        return ""

    proj_name = _proj_display_name(project_code)
    city_name = _city_display_name(city_code)
    type_name = _type_display_name(type_code)

    pid = _ensure_child_folder(root_id, proj_name)
    cid = _ensure_child_folder(pid, city_name)
    tid = _ensure_child_folder(cid, type_name)
    if status:
        sid = _ensure_child_folder(tid, status)
        return sid
    return tid

def move_drive_file(file_id: str, new_parent_id: str):
    if not file_id or not new_parent_id:
        return
    drive = _get_drive_client_for_writes()
    f = drive.files().get(fileId=file_id, fields="parents", supportsAllDrives=True).execute()
    prev_parents = ",".join(f.get("parents", []))
    drive.files().update(
        fileId=file_id,
        addParents=new_parent_id,
        removeParents=prev_parents,
        fields="id, parents",
        supportsAllDrives=True,
    ).execute()

def delete_drive_file(file_id: str):
    try:
        if not file_id:
            return
        drive = _get_drive_client_for_writes()
        drive.files().delete(fileId=file_id, supportsAllDrives=True).execute()
    except Exception as e:
        st.warning(f"Failed to delete Drive file: {e}")

def _is_pdf_bytes(data: bytes) -> bool:
    return isinstance(data, (bytes, bytearray)) and data[:4] == b"%PDF"

def upload_pdf_and_link(uploaded_file, *, prefix: str, parent_folder_id: str | None = None) -> tuple[str, str]:
    """Upload PDF to Drive into desired folder. Try SA first; on 403 quota, fall back to OAuth."""
    if uploaded_file is None:
        return "", ""
    if getattr(uploaded_file, "type", "") not in ("application/pdf", "application/x-pdf", "binary/octet-stream"):
        st.error("Only PDF files are allowed.")
        return "", ""
    data = uploaded_file.getvalue()
    if not _is_pdf_bytes(data):
        st.error("The uploaded file doesn't look like a real PDF.")
        return "", ""

    fname = f"{prefix}.pdf"
    folder_id = parent_folder_id or (
        st.secrets.get("drive", {}).get("approvals_folder_id")
        or st.secrets.get("drive", {}).get("approvals", "")
    )
    metadata = {"name": fname}
    if folder_id:
        metadata["parents"] = [folder_id]

    media = MediaIoBaseUpload(io.BytesIO(data), mimetype="application/pdf", resumable=False)
    drive_cli = _get_drive()

    try:
        file = drive_cli.files().create(
            body=metadata,
            media_body=media,
            fields="id, webViewLink, parents",
            supportsAllDrives=True,
        ).execute()
    except HttpError as e:
        if e.resp.status == 403 and "storageQuotaExceeded" in str(e):
            if not ALLOW_OAUTH_FALLBACK:
                st.error("Service Account cannot upload to My Drive. Move folder or enable OAuth fallback.")
                st.stop()
            drive_cli = _get_user_drive()
            file = drive_cli.files().create(
                body=metadata,
                media_body=media,
                fields="id, webViewLink, parents",
                supportsAllDrives=False,
            ).execute()
        else:
            raise

    file_id = file.get("id", "")
    link = file.get("webViewLink", "")
    if st.secrets.get("drive", {}).get("public", True) and file_id:
        _drive_make_public(file_id, drive_client=drive_cli)
    return link, file_id

def _fetch_public_pdf_bytes(file_id: str, link: str) -> bytes:
    try:
        if file_id:
            url = f"https://drive.google.com/uc?export=download&id={file_id}"
            r = requests.get(url, timeout=15)
            if r.ok and r.content[:4] == b"%PDF":
                return r.content
    except Exception:
        pass
    return b""

# =============================================================================
# SHEETS HELPERS
# =============================================================================
def _norm_title(t: str) -> str:
    return (t or "").strip().lower()

def _norm_header(h: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (h or "").strip().lower())

def _canon_header(h: str) -> str:
    key = _norm_header(h)
    return HEADER_SYNONYMS.get(key, h.strip())

def canon_inventory_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Standardize inventory column names."""
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
    return df.astype(str)

def reorder_columns(df: pd.DataFrame, desired: list[str]) -> pd.DataFrame:
    for c in desired:
        if c not in df.columns:
            df[c] = ""
    tail = [c for c in df.columns if c not in desired]
    return df[desired + tail]

def get_or_create_ws(title, rows=500, cols=80):
    sh = get_sh()
    try:
        return sh.worksheet(title)
    except gspread.exceptions.WorksheetNotFound:
        return sh.add_worksheet(title=title, rows=rows, cols=cols)

def get_employee_ws():
    sh = get_sh()
    wanted = EMPLOYEE_WS.strip().lower()
    matches = [ws for ws in sh.worksheets() if ws.title.strip().lower() == wanted]
    if not matches:
        raise RuntimeError(f"Worksheet '{EMPLOYEE_WS}' not found.")
    if len(matches) > 1:
        for ws in matches:
            try:
                if len(ws.get_all_values()) > 1:
                    return ws
            except Exception:
                pass
        st.warning(f"Multiple worksheets named '{EMPLOYEE_WS}' found; using the first.")
    return matches[0]

@st.cache_data(ttl=120, show_spinner=False)
def _read_worksheet_cached(ws_title: str) -> pd.DataFrame:
    if ws_title == PENDING_DEVICE_WS:
        ws = get_or_create_ws(PENDING_DEVICE_WS)
        df = pd.DataFrame(ws.get_all_records())
        return reorder_columns(df, PENDING_DEVICE_COLS)
    if ws_title == PENDING_TRANSFER_WS:
        ws = get_or_create_ws(PENDING_TRANSFER_WS)
        df = pd.DataFrame(ws.get_all_records())
        return reorder_columns(df, PENDING_TRANSFER_COLS)
    if ws_title == EMPLOYEE_WS:
        ws = get_employee_ws()
        df = pd.DataFrame(ws.get_all_records())
        return reorder_columns(df, EMPLOYEE_CANON_COLS)
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
        if ws_title == INVENTORY_WS:
            return pd.DataFrame(columns=INVENTORY_COLS)
        if ws_title == TRANSFERLOG_WS:
            return pd.DataFrame(columns=LOG_COLS)
        if ws_title == EMPLOYEE_WS:
            return pd.DataFrame(columns=EMPLOYEE_CANON_COLS)
        if ws_title == PENDING_DEVICE_WS:
            return pd.DataFrame(columns=PENDING_DEVICE_COLS)
        if ws_title == PENDING_TRANSFER_WS:
            return pd.DataFrame(columns=PENDING_TRANSFER_COLS)
        return pd.DataFrame()

def write_worksheet(ws_title, df):
    if ws_title == INVENTORY_WS:
        df = canon_inventory_columns(df)
        df = reorder_columns(df, INVENTORY_COLS)
    if ws_title == PENDING_DEVICE_WS:
        df = reorder_columns(df, PENDING_DEVICE_COLS)
    if ws_title == PENDING_TRANSFER_WS:
        df = reorder_columns(df, PENDING_TRANSFER_COLS)
    if ws_title == EMPLOYEE_WS:
        ws = get_employee_ws()
    else:
        ws = get_or_create_ws(ws_title)
    ws.clear()
    set_with_dataframe(ws, df)
    st.cache_data.clear()

def append_to_worksheet(ws_title, new_data):
    ws = get_or_create_ws(ws_title)
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
    """Normalize serial number to uppercase alphanumeric only."""
    return re.sub(r"[^A-Z0-9]", "", (s or "").strip().upper())

def levenshtein(a: str, b: str, max_dist: int = 1) -> int:
    """Compute Levenshtein distance with cutoff."""
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

# === File naming helpers ===
def project_code_from(text: str) -> str:
    """Derive HO/ST/FIN/IT from text, defaults to HO."""
    s = (text or "").strip().lower()
    if not s:
        return "HO"
    if re.search(r"\b(ho|head\s*office|hq|head\s*quarters)\b", s):
        return "HO"
    if re.search(r"\b(st|site|field|project|yard)\b", s):
        return "ST"
    if "finance" in s:
        return "FIN"
    if re.fullmatch(r"(it|i\\.t\\.|information\\s*technology)", s):
        return "IT"
    return "HO"

def city_code_from(text: str) -> str:
    """Map variants to RUH/JED/TIF/MED, defaults to RUH."""
    s = (text or "").strip().lower()
    if not s:
        return "RUH"
    pairs = [
        (("riyadh", "ruh", "riyad"), "RUH"),
        (("jeddah", "jed", "jdh", "jda"), "JED"),
        (("taif", "tif"), "TIF"),
        (("madinah", "medina", "med", "al madinah", "al-madinah"), "MED"),
    ]
    for keys, code in pairs:
        if any(k in s for k in keys):
            return code
    return "RUH"

def get_next_order_number(type_: str) -> str:
    """Keeps a counter per type in 'counters' worksheet."""
    ws = get_or_create_ws("counters", rows=10, cols=2)
    df = pd.DataFrame(ws.get_all_records())
    default_start = 1 if type_ == "REG" else 2
    if "Type" not in df.columns or "LastUsed" not in df.columns:
        df = pd.DataFrame([{"Type": "REG", "LastUsed": default_start - 1}])
    if type_ not in df.get("Type", pd.Series(dtype=str)).values:
        df = pd.concat([df, pd.DataFrame([{"Type": type_, "LastUsed": default_start - 1}])], ignore_index=True)
    idx = df[df["Type"] == type_].index[0]
    current = int(df.at[idx, "LastUsed"]) + 1
    df.at[idx, "LastUsed"] = current
    ws.clear()
    set_with_dataframe(ws, df)
    return str(current).zfill(4)

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

def history_tab():
    st.subheader("📜 Transfer Log")
    df = read_worksheet(TRANSFERLOG_WS)
    if df.empty:
        st.info("No transfer history found.")
    else:
        st.dataframe(df, use_container_width=True, hide_index=True)

def register_device_tab():
    st.subheader("📝 Register New Device")

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
                assigned_to = st.text_input("Name")
            elif assigned_choice == UNASSIGNED_LABEL:
                assigned_to = UNASSIGNED_LABEL
            else:
                assigned_to = assigned_choice
        with r1c3:
            device = st.text_input("Device Type *")

        brand = st.text_input("Brand")
        model = st.text_input("Model")

        pdf_file = st.file_uploader("Upload signed Approval PDF", type=["pdf"], key="reg_signed_pdf")

        # --- Generate draft PDF ---
        if serial.strip() and device.strip():
            from io import BytesIO
            from PyPDF2 import PdfReader, PdfWriter

            draft_data = {
                "SerialNumber": serial.strip(),
                "DeviceType": device.strip(),
                "Brand": brand.strip(),
                "Model": model.strip(),
                "AssignedTo": assigned_to.strip(),
            }
            try:
                template_path = "forms/Register and Transfer Device.pdf"
                reader = PdfReader(template_path)
                writer = PdfWriter()
                page = reader.pages[0]
                writer.add_page(page)
                writer.update_page_form_field_values(writer.pages[0], draft_data)

                buf = BytesIO()
                writer.write(buf)
                buf.seek(0)

                st.download_button(
                    "⬇️ Download Draft PDF",
                    data=buf,
                    file_name=f"{serial.strip()}_draft.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )
                st.caption("Download, print & sign before uploading the signed version below.")
            except Exception as e:
                st.warning(f"Could not generate draft PDF: {e}")

        # ✅ Submit button is required
        submitted = st.form_submit_button("Submit for Approval", type="primary")

    # --- Handle submission ---
    if submitted:
        if not serial.strip() or not device.strip():
            st.error("Serial Number and Device Type are required.")
            return
        if pdf_file is None:
            st.error("Signed PDF is required.")
            return

        s_norm = normalize_serial(serial)
        inv = read_worksheet(INVENTORY_WS)
        if not inv.empty and s_norm in set(inv["Serial Number"].astype(str).map(normalize_serial)):
            st.error("Duplicate serial number already exists.")
            return

        now_str = datetime.now().strftime(DATE_FMT)
        actor = st.session_state.get("username", "")

        base_row = {
            "Serial Number": serial.strip(),
            "Device Type": device.strip(),
            "Brand": brand.strip(),
            "Model": model.strip(),
            "Current user": assigned_to.strip(),
            "Previous User": "",
            "TO": assigned_to.strip() if assigned_to != UNASSIGNED_LABEL else "",
            "Date issued": now_str,
            "Registered by": actor,
        }

        project_code = project_code_from("HO")
        city_code = city_code_from("RUH")
        order_number = get_next_order_number("REG")
        today_str = datetime.now().strftime("%Y%m%d")
        prefix = f"{project_code}-{city_code}-REG-{s_norm}-{order_number}-{today_str}"

        pending_folder = ensure_folder_tree(project_code, city_code, "REG", "Pending")
        link, fid = upload_pdf_and_link(pdf_file, prefix=prefix, parent_folder_id=pending_folder)
        if not fid:
            st.error("Failed to upload signed PDF.")
            return

        pending = {**base_row,
                   "Approval Status": "Pending",
                   "Approval PDF": link,
                   "Approval File ID": fid,
                   "Submitted by": actor,
                   "Submitted at": now_str,
                   "Approver": "",
                   "Decision at": ""}

        append_to_worksheet(PENDING_DEVICE_WS, pd.DataFrame([pending]))
        st.success("✅ Signed device registration submitted for admin approval.")
        
    # --- Handle submission ---
    if submitted:
        if not serial.strip() or not device.strip():
            st.error("Serial Number and Device Type are required.")
            return
        if pdf_file is None:
            st.error("Signed PDF is required.")
            return

        s_norm = normalize_serial(serial)
        inv = read_worksheet(INVENTORY_WS)
        if not inv.empty and s_norm in set(inv["Serial Number"].astype(str).map(normalize_serial)):
            st.error("Duplicate serial number already exists.")
            return

        now_str = datetime.now().strftime(DATE_FMT)
        actor = st.session_state.get("username", "")

        base_row = {
            "Serial Number": serial.strip(),
            "Device Type": device.strip(),
            "Brand": brand.strip(),
            "Model": model.strip(),
            "Current user": assigned_to.strip(),
            "Previous User": "",
            "TO": assigned_to.strip() if assigned_to != UNASSIGNED_LABEL else "",
            "Date issued": now_str,
            "Registered by": actor,
        }

        project_code = project_code_from("HO")
        city_code = city_code_from("RUH")
        order_number = get_next_order_number("REG")
        today_str = datetime.now().strftime("%Y%m%d")
        prefix = f"{project_code}-{city_code}-REG-{s_norm}-{order_number}-{today_str}"

        pending_folder = ensure_folder_tree(project_code, city_code, "REG", "Pending")
        link, fid = upload_pdf_and_link(pdf_file, prefix=prefix, parent_folder_id=pending_folder)
        if not fid:
            st.error("Failed to upload signed PDF.")
            return

        pending = {**base_row,
                   "Approval Status": "Pending",
                   "Approval PDF": link,
                   "Approval File ID": fid,
                   "Submitted by": actor,
                   "Submitted at": now_str,
                   "Approver": "",
                   "Decision at": ""}

        append_to_worksheet(PENDING_DEVICE_WS, pd.DataFrame([pending]))
        st.success("✅ Signed device registration submitted for admin approval.")

def transfer_tab():
    st.subheader("🔁 Transfer Device")

    inventory_df = read_worksheet(INVENTORY_WS)
    if inventory_df.empty:
        st.warning("Inventory is empty.")
        return

    serial_list = sorted(inventory_df["Serial Number"].dropna().astype(str).unique().tolist())
    serial = st.selectbox("Serial Number", ["— Select —"] + serial_list)
    chosen_serial = None if serial == "— Select —" else serial

    new_owner = st.text_input("New Owner *")
    pdf_file = st.file_uploader("Upload signed Transfer PDF", type=["pdf"], key="transfer_signed_pdf")
    do_transfer = st.button("Submit Transfer", type="primary", disabled=not (chosen_serial and new_owner.strip()))

    # --- Draft PDF ---
    if chosen_serial and new_owner.strip():
        from io import BytesIO
        from PyPDF2 import PdfReader, PdfWriter

        draft_data = {
            "SerialNumber": chosen_serial.strip(),
            "FromOwner": inventory_df[inventory_df["Serial Number"] == chosen_serial]["Current user"].values[0],
            "ToOwner": new_owner.strip(),
        }
        try:
            template_path = "forms/Register and Transfer Device.pdf"
            reader = PdfReader(template_path)
            writer = PdfWriter()
            page = reader.pages[0]
            writer.add_page(page)
            writer.update_page_form_field_values(writer.pages[0], draft_data)

            buf = BytesIO()
            writer.write(buf)
            buf.seek(0)

            st.download_button(
    "⬇️ Download Transfer Draft PDF",
    data=buf,
    file_name=f"{chosen_serial.strip()}_transfer_draft.pdf",
    mime="application/pdf",
    use_container_width=True
)

            st.caption("Download, print & sign this form. Then scan & upload as the signed Transfer PDF below.")
        except Exception as e:
            st.warning(f"Could not generate draft transfer PDF: {e}")

    # --- Submission ---
    if do_transfer:
        if pdf_file is None:
            st.error("You must upload the signed transfer PDF.")
            return

        project_code = project_code_from("HO")
        city_code = city_code_from("RUH")
        order_number = get_next_order_number("TRF")
        today_str = datetime.now().strftime("%Y%m%d")
        prefix = f"{project_code}-{city_code}-TRF-{normalize_serial(chosen_serial)}-{order_number}-{today_str}"
        pending_folder = ensure_folder_tree(project_code, city_code, "TRF", "Pending")

        link, fid = upload_pdf_and_link(pdf_file, prefix=prefix, parent_folder_id=pending_folder)
        if not fid:
            return

        now_str = datetime.now().strftime(DATE_FMT)
        actor = st.session_state.get("username", "")
        pend = {
            "Serial Number": chosen_serial,
            "From owner": inventory_df[inventory_df["Serial Number"] == chosen_serial]["Current user"].values[0],
            "To owner": new_owner.strip(),
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

def employee_register_tab():
    st.subheader("🧑‍💼 Register New Employee (mainlists)")
    emp_df = read_worksheet(EMPLOYEE_WS)
    try:
        ids = pd.to_numeric(emp_df["Employee ID"], errors="coerce").dropna().astype(int)
        next_id_suggestion = str(ids.max() + 1) if len(ids) else str(len(emp_df) + 1)
    except Exception:
        next_id_suggestion = str(len(emp_df) + 1)

    dept_existing = unique_nonempty(emp_df, "Department")
    pos_existing = unique_nonempty(emp_df, "Position")
    proj_existing = unique_nonempty(emp_df, "Project")
    loc_existing = unique_nonempty(emp_df, "Location (KSA)")
    ksa_cities = ["Riyadh","Jeddah","Dammam","Khobar","Dhahran","Jubail","Mecca","Medina","Abha","Tabuk","Hail","Buraidah"]

    with st.form("register_employee", clear_on_submit=True):
        r1c1, r1c2, r1c3 = st.columns(3)
        with r1c1: emp_name = st.text_input("New Employeer *")
        with r1c2: emp_id = st.text_input("Employee ID", help=f"Suggested next ID: {next_id_suggestion}")
        with r1c3: new_sig = st.selectbox("New Signature", ["— Select —", "Yes", "No", "Requested"])

        r2c1, r2c2 = st.columns(2)
        with r2c1: Email = st.text_input("Email")
        with r2c2: active = st.selectbox("Active", ["Active", "Inactive", "Onboarding", "Resigned"])

        r3c1, r3c2, r3c3 = st.columns(3)
        with r3c1: position = select_with_other("Position", ["Engineer","Technician","Manager","Coordinator"], pos_existing)
        with r3c2: department = select_with_other("Department", ["IT","HR","Finance","Operations","Procurement"], dept_existing)
        with r3c3: location_ksa = select_with_other("Location (KSA)", ksa_cities, loc_existing)

        r4c1, r4c2, r4c3 = st.columns(3)
        with r4c1: project = select_with_other("Project", ["Head Office", "Site"], proj_existing)
        with r4c2: teams = st.selectbox("Microsoft Teams", ["— Select —", "Yes", "No", "Requested"])
        with r4c3: mobile = st.text_input("Mobile Number")

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
# APPROVALS (Admin)
# =============================================================================
def approvals_tab():
    st.subheader("✅ Approvals (Admin)")
    if st.session_state.get("role") != "Admin":
        st.info("Only Admins can view approvals.")
        return

    pending_dev = read_worksheet(PENDING_DEVICE_WS)
    pending_tr = read_worksheet(PENDING_TRANSFER_WS)

    # Pending Devices
    st.markdown("### Pending Device Registrations")
    df_dev = pending_dev[pending_dev["Approval Status"].isin(["", "Pending"])].reset_index(drop=True)
    if df_dev.empty:
        st.success("No pending device registrations.")
    else:
        for i, row in df_dev.iterrows():
            with st.expander(f"{row['Device Type']} — SN {row['Serial Number']} (by {row['Submitted by']})"):
                c1, c2 = st.columns([3, 2])
                with c1:
                    info = {k: row.get(k, "") for k in INVENTORY_COLS}
                    st.json(info)

                    pdf_bytes = _fetch_public_pdf_bytes(row.get("Approval File ID", ""), row.get("Approval PDF", ""))

                    # Show only signed PDFs
                    if pdf_bytes and b"/Sig" in pdf_bytes:
                        st.caption("✅ Signed Approval PDF Preview")
                        try:
                            pdf_viewer(input=pdf_bytes, width=700, key=f"viewer_dev_{i}")
                        except Exception:
                            pass
                    elif row.get("Approval PDF"):
                        st.warning("⚠️ The uploaded PDF might not be signed. Please double-check before approving.")
                        st.markdown(f"[Open PDF Manually]({row['Approval PDF']})")

                with c2:
                    reviewed = st.checkbox("I reviewed the attached PDF", key=f"review_dev_{i}") if REQUIRE_REVIEW_CHECK else True
                    a_col, r_col = st.columns(2)
                    if a_col.button("Approve", key=f"approve_dev_{i}", disabled=not reviewed):
                        _approve_device_row(row)
                    if r_col.button("Reject", key=f"reject_dev_{i}"):
                        _reject_row(PENDING_DEVICE_WS, i, row)

    # Pending Transfers
    st.markdown("---")
    st.markdown("### Pending Transfers")
    df_tr = pending_tr[pending_tr["Approval Status"].isin(["", "Pending"])].reset_index(drop=True)
    if df_tr.empty:
        st.success("No pending transfers.")
    else:
        for i, row in df_tr.iterrows():
            with st.expander(f"SN {row['Serial Number']}: {row['From owner']} → {row['To owner']} (by {row['Submitted by']})"):
                c1, c2 = st.columns([3, 2])
                with c1:
                    info = {k: row.get(k, "") for k in LOG_COLS}
                    st.json(info)

                    pdf_bytes = _fetch_public_pdf_bytes(row.get("Approval File ID", ""), row.get("Approval PDF", ""))

                    # Show only signed PDFs
                    if pdf_bytes and b"/Sig" in pdf_bytes:
                        st.caption("✅ Signed Approval PDF Preview")
                        try:
                            pdf_viewer(input=pdf_bytes, width=700, key=f"viewer_tr_{i}")
                        except Exception:
                            pass
                    elif row.get("Approval PDF"):
                        st.warning("⚠️ The uploaded PDF might not be signed. Please double-check before approving.")
                        st.markdown(f"[Open PDF Manually]({row['Approval PDF']})")

                with c2:
                    reviewed = st.checkbox("I reviewed the attached PDF", key=f"review_tr_{i}") if REQUIRE_REVIEW_CHECK else True
                    a_col, r_col = st.columns(2)
                    if a_col.button("Approve", key=f"approve_tr_{i}", disabled=not reviewed):
                        _approve_transfer_row(row)
                    if r_col.button("Reject", key=f"reject_tr_{i}"):
                        _reject_row(PENDING_TRANSFER_WS, i, row)


# --- Approve/Reject Helpers ---
def _approve_device_row(row: pd.Series):
    inv = read_worksheet(INVENTORY_WS)
    now_str = datetime.now().strftime(DATE_FMT)
    approver = st.session_state.get("username", "")

    # Add new row to inventory
    new_row = {k: row.get(k, "") for k in INVENTORY_COLS}
    new_row["Registered by"] = approver or new_row.get("Registered by", "")
    new_row["Date issued"] = now_str
    inv_out = pd.concat(
        [inv if not inv.empty else pd.DataFrame(columns=INVENTORY_COLS),
         pd.DataFrame([new_row])],
        ignore_index=True
    )
    write_worksheet(INVENTORY_WS, inv_out)

    # Move files to Drive folders
    try:
        project_code = project_code_from(row.get("Department", "") or "UNK")
        city_code = city_code_from(row.get("Location", "") or "UNK")
        approved_folder = ensure_folder_tree(project_code, city_code, "REG", "Approved")
        move_drive_file(str(row.get("Approval File ID", "")), approved_folder)
    except Exception:
        pass

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
    inv.loc[idx, "Current user"] = str(row.get("To owner", ""))
    inv.loc[idx, "TO"] = str(row.get("To owner", ""))
    inv.loc[idx, "Date issued"] = now_str
    inv.loc[idx, "Registered by"] = approver
    write_worksheet(INVENTORY_WS, inv)

    log_row = {k: row.get(k, "") for k in LOG_COLS}
    log_row["Date issued"] = now_str
    log_row["Registered by"] = approver
    append_to_worksheet(TRANSFERLOG_WS, pd.DataFrame([log_row]))

    try:
        dep = row.get("Department", "") or inv.loc[idx].get("Department", "")
        loc = row.get("Location", "") or inv.loc[idx].get("Location", "")
        project_code = project_code_from(dep or "UNK")
        city_code = city_code_from(loc or "UNK")
        dest_folder = ensure_folder_tree(project_code, city_code, "TRF", "Approved")
        move_drive_file(str(row.get("Approval File ID", "")), dest_folder)
    except Exception:
        pass

    _mark_decision(PENDING_TRANSFER_WS, row, status="Approved")
    st.success("✅ Transfer approved and applied.")


def _mark_decision(ws_title: str, row: pd.Series, *, status: str):
    df = read_worksheet(ws_title)
    key_cols = [c for c in ["Serial Number", "Submitted at", "Submitted by", "To owner"] if c in df.columns]
    mask = pd.Series([True] * len(df))
    for c in key_cols:
        mask &= df[c].astype(str) == str(row.get(c, ""))
    idxs = df[mask].index.tolist()
    if not idxs and "Serial Number" in df.columns:
        idxs = df[df["Serial Number"].astype(str) == str(row.get("Serial Number", ""))].index.tolist()
    if not idxs:
        return
    idx = idxs[0]
    df.loc[idx, "Approval Status"] = status
    df.loc[idx, "Approver"] = st.session_state.get("username", "")
    df.loc[idx, "Decision at"] = datetime.now().strftime(DATE_FMT)
    write_worksheet(ws_title, df)


def _reject_row(ws_title: str, i: int, row: pd.Series):
    reason = st.text_input(f"Reason for rejecting SN {row.get('Serial Number','')}", key=f"reason_{i}")
    confirm = st.button("Confirm Reject", key=f"confirm_reject_{i}")

    if not confirm:
        return

    try:
        type_code = "REG" if ws_title == PENDING_DEVICE_WS else "TRF"
        dep = row.get("Department", "") or ""
        loc = row.get("Location", "") or ""
        project_code = project_code_from(dep or "UNK")
        city_code = city_code_from(loc or "UNK")
        dest_folder = ensure_folder_tree(project_code, city_code, type_code, "Rejected")

        fid = str(row.get("Approval File ID", ""))
        if fid:
            move_drive_file(fid, dest_folder)
        else:
            st.warning("No Approval File ID; cannot move PDF to Rejected folder.")
    except Exception as e:
        st.warning(f"Could not move PDF to Rejected folder: {e}")

    # Mark decision in sheet
    df = read_worksheet(ws_title)
    idxs = df[df["Serial Number"].astype(str) == str(row.get("Serial Number", ""))].index.tolist()
    if idxs:
        idx = idxs[0]
        df.loc[idx, "Approval Status"] = "Rejected"
        df.loc[idx, "Approver"] = st.session_state.get("username", "")
        df.loc[idx, "Decision at"] = datetime.now().strftime(DATE_FMT)
        df.loc[idx, "Rejection Reason"] = reason.strip() if reason else "No reason provided"
        write_worksheet(ws_title, df)

    st.info(f"❌ Request rejected. Reason: {reason or 'No reason provided'}.")



# =============================================================================
# EXPORT
# =============================================================================
def export_tab():
    st.subheader("⬇️ Export (always fresh)")

    inv = read_worksheet(INVENTORY_WS)
    log = read_worksheet(TRANSFERLOG_WS)
    emp = read_worksheet(EMPLOYEE_WS)

    st.caption(f"Last fetched: {datetime.now().strftime(DATE_FMT)}")

    # Normal exports
    c1, c2, c3 = st.columns(3)
    with c1:
        st.download_button("Inventory CSV", inv.to_csv(index=False).encode("utf-8"),
                           "inventory.csv", "text/csv")
    with c2:
        st.download_button("Transfer Log CSV", log.to_csv(index=False).encode("utf-8"),
                           "transfer_log.csv", "text/csv")
    with c3:
        st.download_button("Employees CSV", emp.to_csv(index=False).encode("utf-8"),
                           "employees.csv", "text/csv")

    st.markdown("---")
    st.markdown("**Approvals (Accepted / Rejected)**")

    dev_df = read_worksheet(PENDING_DEVICE_WS)
    trf_df = read_worksheet(PENDING_TRANSFER_WS)

    approved_dev = dev_df[dev_df.get("Approval Status", "").astype(str) == "Approved"]
    rejected_dev = dev_df[dev_df.get("Approval Status", "").astype(str) == "Rejected"]

    approved_trf = trf_df[trf_df.get("Approval Status", "").astype(str) == "Approved"]
    rejected_trf = trf_df[trf_df.get("Approval Status", "").astype(str) == "Rejected"]

    c4, c5 = st.columns(2)
    with c4:
        if not approved_dev.empty:
            st.download_button("Approved Device Submissions CSV",
                               approved_dev.to_csv(index=False).encode("utf-8"),
                               "approved_device_submissions.csv", "text/csv")
        else:
            st.caption("No approved device submissions yet.")

        if not rejected_dev.empty:
            st.download_button("❌ Rejected Device Submissions CSV",
                               rejected_dev.to_csv(index=False).encode("utf-8"),
                               "rejected_device_submissions.csv", "text/csv")
        else:
            st.caption("No rejected device submissions yet.")

    with c5:
        if not approved_trf.empty:
            st.download_button("Approved Transfer Submissions CSV",
                               approved_trf.to_csv(index=False).encode("utf-8"),
                               "approved_transfer_submissions.csv", "text/csv")
        else:
            st.caption("No approved transfer submissions yet.")

        if not rejected_trf.empty:
            st.download_button("❌ Rejected Transfer Submissions CSV",
                               rejected_trf.to_csv(index=False).encode("utf-8"),
                               "rejected_transfer_submissions.csv", "text/csv")
        else:
            st.caption("No rejected transfer submissions yet.")

# =============================================================================
# CONFIG CHECK & MAIN RUNNER
# =============================================================================
def _config_check_ui():
    """Fail fast with a clear message if SA config is missing."""
    try:
        sa = _load_sa_info()
        sa_email = sa.get("client_email", "(unknown)")
        st.caption(f"Service Account: {sa_email}")
    except Exception as e:
        st.error("Google Service Account credentials are missing.")
        st.code(str(e))
        st.markdown(
            "- Put your Service Account JSON under `st.secrets['gcp_service_account']` "
            "or env `GOOGLE_SERVICE_ACCOUNT_JSON`.\n"
            "- Ensure it includes **private_key** and **client_email**.\n"
            "- Share the Google Sheet URL in `st.secrets['sheets']['url']` with the SA email (Editor).\n"
            "- For Drive uploads to **My Drive**, add `[google_oauth].token_json` to secrets (Option B)."
        )
        st.stop()

    # Try opening the spreadsheet once so errors surface early
    try:
        _ = get_sh()
    except Exception as e:
        st.error("Cannot open the spreadsheet with the configured Service Account.")
        st.code(str(e))
        st.info("Share the sheet with the Service Account email above and try again.")
        st.stop()


def run_app():
    render_header()
    hide_table_toolbar_for_non_admin()
    _config_check_ui()

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
        tabs = st.tabs([
            "📝 Register Device",
            "🔁 Transfer Device",
            "📋 View Inventory",
            "📜 Transfer Log"
        ])
        with tabs[0]: register_device_tab()
        with tabs[1]: transfer_tab()
        with tabs[2]: inventory_tab()
        with tabs[3]: history_tab()


# =============================================================================
# ENTRYPOINT
# =============================================================================
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "just_logged_out" not in st.session_state:
    st.session_state.just_logged_out = False

# Try restoring session from cookie
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
            do_login(username, user.get("role", "Staff"))
        else:
            st.error("❌ Invalid username or password.")
