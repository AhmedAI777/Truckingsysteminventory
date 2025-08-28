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

# --- Streamlit FIRST command must be set_page_config ---
import streamlit as st
st.set_page_config(page_title="Tracking Inventory Management System", layout="wide")

# After page_config, it's safe to import/use Streamlit components
import gspread
from gspread_dataframe import set_with_dataframe
import extra_streamlit_components as stx
from streamlit import session_state as ss
from streamlit_pdf_viewer import pdf_viewer

from google.oauth2.service_account import Credentials
from google.oauth2.credentials import Credentials as UserCredentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload
from googleapiclient.errors import HttpError

# =============================================================================
# CONFIG
# =============================================================================
APP_TITLE = "Tracking Inventory Management System"
SUBTITLE  = "Advanced Construction"
DATE_FMT  = "%Y-%m-%d %H:%M:%S"

SESSION_TTL_DAYS = 30
SESSION_TTL_SECONDS = SESSION_TTL_DAYS * 24 * 60 * 60
COOKIE_NAME = "ac_auth_v2"

SHEET_URL_DEFAULT = "https://docs.google.com/spreadsheets/d/1SHp6gOW4ltsyOT41rwo85e_LELrHkwSwKN33K6XNHFI/edit"

INVENTORY_WS    = "truckinventory"
TRANSFERLOG_WS  = "transfer_log"
EMPLOYEE_WS     = "mainlists"
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
EMPLOYEE_CANON_COLS = [
    "New Employeer","Employee ID","New Signature","Name","Address",
    "Active","Position","Department","Location (KSA)",
    "Project","Microsoft Teams","Mobile Number"
]
APPROVAL_META_COLS = [
    "Approval Status","Approval PDF","Approval File ID",
    "Submitted by","Submitted at","Approver","Decision at"
]
PENDING_DEVICE_COLS   = INVENTORY_COLS + APPROVAL_META_COLS
PENDING_TRANSFER_COLS = LOG_COLS + APPROVAL_META_COLS

UNASSIGNED_LABEL = "Unassigned (Stock)"
REQUIRE_REVIEW_CHECK = True  # gate Approve behind a review checkbox

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

# Pre-init session keys for PDF previews (optional)
for k in ("reg_pdf_ref", "transfer_pdf_ref"):
    if k not in ss:
        ss[k] = None

# =============================================================================
# AUTH (users + cookie)
# =============================================================================
def _load_users_from_secrets():
    users_cfg = st.secrets.get("auth", {}).get("users", [])
    users = {}
    for u in users_cfg:
        users[u["username"]] = {"password": u.get("password", ""), "role": u.get("role", "Staff")}
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
        COOKIE_NAME, token,
        expires_at=(datetime.utcnow() + timedelta(seconds=SESSION_TTL_SECONDS)) if SESSION_TTL_SECONDS > 0 else None,
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

if "cookie_bootstrapped" not in st.session_state:
    st.session_state.cookie_bootstrapped = True
    _ = COOKIE_MGR.get_all()
    st.rerun()
# =============================================================================
# STYLE
# =============================================================================

def _inject_font_css(font_path: str, family: str = "ACBrandFont"):
    """Embed a local .ttf/.otf font and apply it globally."""
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
    """Possible font file locations (local + /fonts folder + secrets)."""
    cands = []
    secrets_font = st.secrets.get("branding", {}).get("font_file")
    if secrets_font:
        cands.append(secrets_font)
    cands += [
        "company_font.ttf","company_font.otf",
        "ACBrandFont.ttf","ACBrandFont.otf",
        "FounderGroteskCondensed-Regular.otf",
        "Cairo-Regular.ttf",
    ]
    try:
        cands += sorted(glob.glob("fonts/*.ttf")) + sorted(glob.glob("fonts/*.otf"))
    except Exception:
        pass
    return cands


def _apply_brand_font():
    """Apply the first available font candidate (or skip silently)."""
    fam = st.secrets.get("branding", {}).get("font_family", "ACBrandFont")
    for p in _font_candidates():
        if os.path.exists(p):
            _inject_font_css(p, family=fam)
            return


def render_header():
    """Top header with logo, title, and user badge + logout."""
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
            f"""<div style="display:flex; align-items:center; justify-content:flex-end; gap:1rem;">
                   <div>
                     <div style="font-weight:600;">Welcome, {username or '—'}</div>
                     <div>Role: <b>{role or '—'}</b></div>
                   </div>
                 </div>""",
            unsafe_allow_html=True,
        )
        if st.session_state.get("authenticated") and st.button("Logout"):
            do_logout()
    st.markdown("<hr style='margin-top:0.8rem;'>", unsafe_allow_html=True)


def hide_table_toolbar_for_non_admin():
    """Hide the dataframe toolbar for non-admins to reduce accidental edits."""
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
# GENERAL HELPERS
# =============================================================================

def _norm_title(t: str) -> str:
    return (t or "").strip().lower()

def _norm_header(h: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (h or "").strip().lower())

def _canon_header(h: str) -> str:
    """Map header to canonical name via HEADER_SYNONYMS (from Chunk 1)."""
    key = _norm_header(h)
    return HEADER_SYNONYMS.get(key, h.strip())

def normalize_serial(s: str) -> str:
    """Uppercase A-Z/0-9 only; remove all separators/spaces."""
    return re.sub(r"[^A-Z0-9]", "", (s or "").strip().upper())

def levenshtein(a: str, b: str, max_dist: int = 1) -> int:
    """
    Fast Levenshtein with early-exit when distance exceeds max_dist.
    Used to warn on near-duplicate serials.
    """
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
    """Unique, trimmed, non-empty values of a column (safe on empty frames)."""
    if df.empty or col not in df.columns:
        return []
    vals = [str(x).strip() for x in df[col].dropna().astype(str).tolist()]
    return sorted({v for v in vals if v})

def select_with_other(label: str, base_options: list[str], existing_values: list[str]) -> str:
    """
    Select box merged with existing values; returns '' for unselected,
    or the free-text value if 'Other…' is chosen.
    """
    merged = [o for o in base_options if o]
    for v in existing_values:
        if v and v not in merged:
            merged.append(v)
    sel = st.selectbox(label, ["— Select —"] + merged + ["Other…"])
    if sel == "Other…":
        return st.text_input(f"{label} (Other)")
    return "" if sel == "— Select —" else sel

# =============================================================================
# GOOGLE SHEETS & DRIVE (Service Account + OAuth token fallback)
# =============================================================================

SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive",
]
# Option B: allow OAuth fallback for Drive uploads to user's My Drive (no browser on Streamlit Cloud)
OAUTH_SCOPES = ["https://www.googleapis.com/auth/drive.file"]
ALLOW_OAUTH_FALLBACK = st.secrets.get("drive", {}).get("allow_oauth_fallback", True)

def _load_sa_info() -> dict:
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
    """
    Get user OAuth creds STRICTLY from secrets.google_oauth.token_json when running in the cloud.
    If token_json is missing and LOCAL_OAUTH=1, allow local interactive auth.
    """
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
            try:
                creds.refresh(Request())
            except Exception as e:
                st.error(f"OAuth token refresh failed: {e}")
                st.stop()
        return creds

    # No token_json present
    if os.environ.get("LOCAL_OAUTH", "0") == "1":
        # Local-only flow for developers
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

    st.error(
        "OAuth token not configured. Add [google_oauth].token_json to secrets (generated locally), "
        "or move the folder to a Shared drive and disable OAuth fallback."
    )
    st.stop()

@st.cache_resource(show_spinner=False)
def _get_user_drive():
    return build("drive", "v3", credentials=_get_user_creds())

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
    st.error("Google Sheets API error while opening the spreadsheet.")
    raise last_exc

def _drive_make_public(file_id: str, drive_client=None):
    try:
        cli = drive_client or _get_drive()
        cli.permissions().create(
            fileId=file_id,
            body={"role": "reader", "type": "anyone"},
            fields="id",
            supportsAllDrives=True,
        ).execute()
    except Exception:
        # being permissive here: if we can't make it public, we still proceed
        pass

def _is_pdf_bytes(data: bytes) -> bool:
    return isinstance(data, (bytes, bytearray)) and data[:4] == b"%PDF"

def upload_pdf_and_link(uploaded_file, *, prefix: str) -> tuple[str, str]:
    """
    Upload PDF to Drive. Try Service Account first; on 403 storage quota exceeded,
    fall back to OAuth user (My Drive).
    Returns (webViewLink, file_id).
    """
    if uploaded_file is None:
        return "", ""
    if getattr(uploaded_file, "type", "") not in ("application/pdf", "application/x-pdf", "binary/octet-stream"):
        st.error("Only PDF files are allowed.")
        return "", ""
    data = uploaded_file.getvalue()
    if not _is_pdf_bytes(data):
        st.error("The uploaded file doesn't look like a real PDF.")
        return "", ""

    fname = f"{prefix}_{int(time.time())}.pdf"
    folder_id = st.secrets.get("drive", {}).get("approvals", "")
    metadata = {"name": fname}
    if folder_id:
        metadata["parents"] = [folder_id]

    media = MediaIoBaseUpload(io.BytesIO(data), mimetype="application/pdf", resumable=False)

    drive_cli = _get_drive()
    try:
        file = drive_cli.files().create(
            body=metadata,
            media_body=media,
            fields="id, webViewLink",
            supportsAllDrives=True,
        ).execute()
    except HttpError as e:
        # If SA quota exceeded, fallback to user OAuth upload to My Drive
        if e.resp.status == 403 and "storageQuotaExceeded" in str(e):
            if not ALLOW_OAUTH_FALLBACK:
                st.error(
                    "Service Account cannot upload to My Drive. Either move folder to a Shared drive or enable OAuth token fallback."
                )
                st.stop()
            drive_cli = _get_user_drive()
            file = drive_cli.files().create(
                body=metadata,
                media_body=media,
                fields="id, webViewLink",
                supportsAllDrives=False,
            ).execute()
        else:
            raise

    file_id = file.get("id", "")
    link = file.get("webViewLink", "")
    if st.secrets.get("drive", {}).get("public", True) and file_id:
        _drive_make_public(file_id, drive_client=drive_cli)
    return link, file_id

def _fetch_public_pdf_bytes(file_id: str, link: str = "") -> bytes:
    """Fetch PDF bytes for preview when file is public (best-effort)."""
    try:
        if file_id:
            url = f"https://drive.google.com/uc?export=download&id={file_id}"
            r = requests.get(url, timeout=15)
            if r.ok and r.content[:4] == b"%PDF":
                return r.content
        # fallback to view link (won't usually return raw bytes)
    except Exception:
        pass
    return b""

# ---- Template Form: download the immutable ICT form from Drive and serve it for download ----

def _extract_drive_file_id(url_or_id: str) -> str:
    """
    Accepts a Drive file id OR a share URL; returns the file id.
    Example URL: https://drive.google.com/file/d/<FILE_ID>/view?usp=...
    """
    if not url_or_id:
        return ""
    if "/" not in url_or_id and len(url_or_id) > 20:
        return url_or_id  # already looks like an id
    m = re.search(r"/d/([A-Za-z0-9_-]{20,})", url_or_id)
    return m.group(1) if m else url_or_id

@st.cache_data(ttl=3600, show_spinner=False)
def download_template_pdf_from_drive() -> bytes:
    """
    Download the canonical, non-editable ICT Equipment Form template from Drive.
    Configure the id under:
      st.secrets["drive"]["template_file_id"]  (preferred)  OR
      st.secrets["drive"]["template_file_url"] (share link)
    Make sure the Service Account has at least 'reader' access to that file.
    """
    file_id = st.secrets.get("drive", {}).get("template_file_id", "")
    if not file_id:
        url = st.secrets.get("drive", {}).get("template_file_url", "")
        file_id = _extract_drive_file_id(url)
    if not file_id:
        # As a convenience, support env var too
        file_id = _extract_drive_file_id(os.environ.get("ICT_TEMPLATE_FILE_ID", ""))

    if not file_id:
        st.error("Template form file id/url is not configured. Please set drive.template_file_id in secrets.")
        return b""

    drive_cli = _get_drive()
    try:
        req = drive_cli.files().get_media(fileId=file_id, supportsAllDrives=True)
        fh = io.BytesIO()
        downloader = googleapiclient.http.MediaIoBaseDownload(fh, req)
        done = False
        while not done:
            status, done = downloader.next_chunk()
        fh.seek(0)
        data = fh.read()
        if _is_pdf_bytes(data):
            return data
        st.error("Downloaded template is not a valid PDF.")
        return b""
    except Exception as e:
        st.error(f"Failed to download template form from Drive: {e}")
        return b""

# Helper to build enforced file names like: HO-JED-REG-<SERIAL>-0008-YYYYMMDD.pdf
def make_form_filename(action: str, serial: str, counter: int = 1) -> str:
    prefix = st.secrets.get("branding", {}).get("site_prefix", "HO-JED")
    today = datetime.now().strftime("%Y%m%d")
    return f"{prefix}-{action}-{serial}-{counter:04d}-{today}.pdf"

# =============================================================================
# SHEETS HELPERS
# =============================================================================

from gspread_dataframe import set_with_dataframe

def canon_inventory_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize inventory dataframe headers (Current user, Previous User, etc.)."""
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
    """Reorder/extend columns in dataframe to match schema."""
    for c in desired:
        if c not in df.columns:
            df[c] = ""
    tail = [c for c in df.columns if c not in desired]
    return df[desired + tail]

def get_or_create_ws(title, rows=500, cols=80):
    """Get a worksheet by title, create it if not found."""
    sh = get_sh()
    try:
        return sh.worksheet(title)
    except gspread.exceptions.WorksheetNotFound:
        return sh.add_worksheet(title=title, rows=rows, cols=cols)

def get_employee_ws():
    """Return the correct 'mainlists' worksheet, resolving duplicates."""
    sh = get_sh()
    wanted = EMPLOYEE_WS.strip().lower()
    matches = [ws for ws in sh.worksheets() if ws.title.strip().lower() == wanted]

    if not matches:
        raise RuntimeError(f"Worksheet '{EMPLOYEE_WS}' not found. Please create/rename it in the spreadsheet.")

    if len(matches) > 1:
        for ws in matches:
            try:
                if len(ws.get_all_values()) > 1:
                    return ws
            except Exception:
                pass
        st.warning(f"Multiple worksheets named '{EMPLOYEE_WS}' found; using the first (all appear empty).")
    return matches[0]

@st.cache_data(ttl=120, show_spinner=False)
def _read_worksheet_cached(ws_title: str) -> pd.DataFrame:
    """Read worksheet with schema enforcement."""
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
        if ws_title == INVENTORY_WS:   return pd.DataFrame(columns=INVENTORY_COLS)
        if ws_title == TRANSFERLOG_WS: return pd.DataFrame(columns=LOG_COLS)
        if ws_title == EMPLOYEE_WS:    return pd.DataFrame(columns=EMPLOYEE_CANON_COLS)
        if ws_title == PENDING_DEVICE_WS: return pd.DataFrame(columns=PENDING_DEVICE_COLS)
        if ws_title == PENDING_TRANSFER_WS: return pd.DataFrame(columns=PENDING_TRANSFER_COLS)
        return pd.DataFrame()

def write_worksheet(ws_title, df):
    """Clear and write a dataframe into worksheet with schema enforcement."""
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

def append_to_worksheet(ws_title, new_data: pd.DataFrame):
    """Append rows to worksheet (merge old + new)."""
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
# PDF HELPERS (template download, filename policy, serial extraction)
# =============================================================================

def generate_ict_form(device_row: dict) -> bytes:
    """
    Return the canonical ICT Equipment Form PDF (immutable).
    We DO NOT pre-fill or modify the template to keep it uneditable as requested.
    """
    data = download_template_pdf_from_drive()
    if not data:
        st.error("ICT template form could not be downloaded. Check drive.template_file_id in secrets.")
    return data

def extract_serials_from_pdf(file) -> list[str]:
    """
    Extract possible Serial Numbers from a signed ICT form PDF.
    - Tries both text layer and AcroForm fields.
    - Normalizes to uppercase alphanumeric (keeps dashes).
    NOTE: Requires PyPDF2. Add `PyPDF2` to your requirements.
    """
    try:
        # Import inside function to allow app to boot even if PyPDF2 not yet installed.
        from PyPDF2 import PdfReader
    except Exception:
        st.error("PyPDF2 is required for serial detection. Please add `PyPDF2` to your requirements.")
        return []

    serials: list[str] = []
    try:
        # PdfReader can take a file-like or bytes. If Streamlit UploadedFile, pass directly.
        reader = PdfReader(file)

        # 1) Try form fields first (if any)
        try:
            fields = reader.get_fields() or {}
            for k, v in fields.items():
                val = ""
                if isinstance(v, dict):
                    val = v.get("/V", "") or v.get("V", "")
                elif hasattr(v, "get"):
                    val = v.get("/V", "")
                text_val = str(val or "").strip()
                if text_val:
                    # Try to detect serial-like strings from fields too
                    m = re.findall(r"[A-Za-z0-9][A-Za-z0-9\-]{3,}", text_val)
                    serials.extend(m)
        except Exception:
            pass

        # 2) Extract page text
        text = ""
        for page in reader.pages:
            try:
                text += page.extract_text() or ""
            except Exception:
                continue

        # Heuristics: lines with Serial No / Serial Number / SN:
        patterns = [
            r"(?:Serial\s*No\.?|Serial\s*Number|Serial|S\/N|SN)\s*[:#\-]?\s*([A-Za-z0-9][A-Za-z0-9\-]{3,})",
            r"\b([A-Z0-9][A-Z0-9\-]{6,})\b",  # broad fallback for long alphanumerics (typical serials)
        ]

        for pat in patterns:
            for s in re.findall(pat, text, flags=re.IGNORECASE):
                serials.append(s)

        # Normalize and dedupe
        cleaned = []
        seen = set()
        for s in serials:
            s = s.strip().upper()
            # Keep dashes, strip other non A-Z/0-9/-
            s = re.sub(r"[^A-Z0-9\-]", "", s)
            if not s:
                continue
            if s not in seen:
                seen.add(s)
                cleaned.append(s)
        return cleaned

    except Exception as e:
        st.error(f"Could not read PDF for serial detection: {e}")
        return []

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
        if st.session_state.get("role") == "Admin":
            st.dataframe(df, use_container_width=True)
        else:
            st.dataframe(df, use_container_width=True, hide_index=True)


def register_device_tab():
    st.subheader("📝 Register New Device")

    # Inline helper to live-offer the ICT template download once serial is typed
    def render_template_download_area(current_serial: str):
        s_norm_live = normalize_serial(current_serial)
        with st.expander("📄 Download ICT Equipment Form (template)", expanded=False):
            if s_norm_live:
                tpl_bytes = generate_ict_form({})
                fname = make_form_filename("REG", s_norm_live, counter=1)
                st.download_button(
                    "Download ICT Equipment Form",
                    tpl_bytes,
                    file_name=fname,
                    mime="application/pdf",
                    key=f"dl_tpl_{s_norm_live}",
                )
                st.caption("Download, print/sign, then upload the **signed** form below.")
            else:
                st.info("Enter a Serial Number above to enable the template download with the correct filename.")

    with st.form("register_device", clear_on_submit=True):
        r1c1, r1c2, r1c3 = st.columns(3)
        with r1c1:
            serial = st.text_input("Serial Number *")
        with r1c2:
            st.caption("Owner will be assigned only during **TRANSFER**, not on registration.")
            assigned_to = UNASSIGNED_LABEL
        with r1c3:
            device = st.text_input("Device Type *")

        # Offer template download inline (based on current serial)
        render_template_download_area(serial)

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

        st.markdown("**Signed ICT Equipment Form (PDF) — required**")
        pdf_file = st.file_uploader("Upload the signed ICT Equipment Form", type=["pdf"], key="reg_pdf")

        submitted = st.form_submit_button("Submit for Approval", type="primary")

    # Optional live preview (user upload)
    if ss.get("reg_pdf"):
        ss.reg_pdf_ref = ss.reg_pdf
    if ss.reg_pdf_ref:
        st.caption("Preview: Signed ICT Form")
        try:
            pdf_viewer(input=ss.reg_pdf_ref.getvalue(), width=700, key="viewer_reg")
        except Exception:
            pass

    if submitted:
        # Validate required fields
        if not serial.strip() or not device.strip():
            st.error("Serial Number and Device Type are required.")
            return
        s_norm = normalize_serial(serial)
        if not s_norm:
            st.error("Serial Number cannot be blank after normalization.")
            return

        # Inventory duplicate & near-duplicate checks
        inv = read_worksheet(INVENTORY_WS)
        if not inv.empty:
            inv["__snorm"] = inv["Serial Number"].astype(str).map(normalize_serial)
            if s_norm in set(inv["__snorm"]):
                existing = inv[inv["__snorm"] == s_norm].iloc[0]
                st.error(
                    f"Duplicate serial. Already exists as '{existing['Serial Number']}' "
                    f"({existing.get('Device Type','')} {existing.get('Brand','')}/{existing.get('Model','')})."
                )
                return
            near_mask = inv["__snorm"].apply(lambda x: levenshtein(s_norm, x, max_dist=1) <= 1)
            near = inv[near_mask]
            if not near.empty:
                similar_list = near["Serial Number"].astype(str).unique().tolist()
                st.warning("Near-duplicate serials: " + ", ".join(similar_list))

        # Require signed PDF for ALL roles for registration
        if pdf_file is None:
            st.error("Signed ICT Equipment Form (PDF) is required.")
            return
        if not _is_pdf_bytes(pdf_file.getvalue()):
            st.error("The uploaded file is not a valid PDF.")
            return

        now_str = datetime.now().strftime(DATE_FMT)
        actor   = st.session_state.get("username", "")

        # Construct device row (owner remains Unassigned)
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
            "Current user": assigned_to.strip(),  # Unassigned (Stock)
            "Previous User": "",
            "TO": "",  # not used in registration
            "Department": dept.strip(),
            "Email Address": email.strip(),
            "Contact Number": contact.strip(),
            "Location": location.strip(),
            "Office": office.strip(),
            "Notes": notes.strip(),
            "Date issued": now_str,
            "Registered by": actor,
        }

        # Upload signed PDF to Drive
        link, fid = upload_pdf_and_link(pdf_file, prefix=f"device_{s_norm}")
        if not fid:
            return

        pending = {
            **row,
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

    with st.form("transfer_device", clear_on_submit=True):
        st.caption("Upload the **signed ICT Equipment Form**; the system will detect the Serial Number automatically.")
        pdf_file = st.file_uploader("Signed ICT Form (PDF)", type=["pdf"], key="transfer_pdf")

        # Preview the uploaded PDF
        if pdf_file is not None:
            try:
                pdf_viewer(input=pdf_file.getvalue(), width=700, key="viewer_trans_upload")
            except Exception:
                pass

        chosen_serial = None
        if pdf_file is not None:
            try:
                # Use a fresh BytesIO so the UploadedFile can be re-used for Drive upload
                serials = extract_serials_from_pdf(io.BytesIO(pdf_file.getvalue()))
            except Exception as e:
                serials = []
                st.error(f"Error reading PDF: {e}")
            if serials:
                chosen_serial = serials[0]
                st.success(f"Detected Serial Number: **{chosen_serial}**")
            else:
                st.error("No Serial Number detected in the uploaded form.")

        existing_users = sorted([u for u in inventory_df["Current user"].dropna().astype(str).tolist() if u.strip()])
        new_owner_choice = st.selectbox("New Owner", ["— Select —"] + existing_users + ["Type a new name…"])
        if new_owner_choice == "Type a new name…":
            new_owner = st.text_input("Enter new owner name")
        else:
            new_owner = new_owner_choice if new_owner_choice != "— Select —" else ""

        do_transfer = st.form_submit_button("Submit Transfer for Approval", type="primary",
                                            disabled=not (pdf_file and chosen_serial and new_owner.strip()))

    if do_transfer:
        if not pdf_file:
            st.error("Signed ICT Equipment Form (PDF) is required.")
            return
        if not chosen_serial:
            st.error("A valid Serial Number could not be detected in the PDF.")
            return
        if not new_owner.strip():
            st.error("Please select or enter the new owner.")
            return

        # Validate serial exists
        match = inventory_df[inventory_df["Serial Number"].astype(str) == chosen_serial]
        if match.empty:
            st.error("Serial number not found in Inventory.")
            return

        idx = match.index[0]
        prev_user = str(inventory_df.loc[idx, "Current user"] or "")
        now_str   = datetime.now().strftime(DATE_FMT)
        actor     = st.session_state.get("username", "")

        # Upload signed PDF to Drive
        link, fid = upload_pdf_and_link(pdf_file, prefix=f"transfer_{normalize_serial(chosen_serial)}")
        if not fid:
            return

        # Always go through approvals for transfers (for both Staff & Admin)
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


def employee_register_tab():
    st.subheader("🧑‍💼 Register New Employee (mainlists)")
    emp_df = read_worksheet(EMPLOYEE_WS)

    try:
        ids = pd.to_numeric(emp_df["Employee ID"], errors="coerce").dropna().astype(int)
        next_id_suggestion = str(ids.max() + 1) if len(ids) else str(len(emp_df) + 1)
    except Exception:
        next_id_suggestion = str(len(emp_df) + 1)

    dept_existing = unique_nonempty(emp_df, "Department")
    pos_existing  = unique_nonempty(emp_df, "Position")
    proj_existing = unique_nonempty(emp_df, "Project")
    loc_existing  = unique_nonempty(emp_df, "Location (KSA)")

    ksa_cities = ["Riyadh","Jeddah","Dammam","Khobar","Dhahran","Jubail","Mecca","Medina","Abha","Tabuk","Hail","Buraidah"]

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
            position = select_with_other("Position", ["Engineer","Technician","Manager","Coordinator"], pos_existing)
        with r3c2:
            department = select_with_other("Department", ["IT","HR","Finance","Operations","Procurement"], dept_existing)
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


def approvals_tab():
    st.subheader("✅ Approvals (Admin)")
    if st.session_state.get("role") != "Admin":
        st.info("Only Admins can view approvals.")
        return

    pending_dev = read_worksheet(PENDING_DEVICE_WS)
    pending_tr  = read_worksheet(PENDING_TRANSFER_WS)

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
                    # Inline PDF preview
                    pdf_bytes = _fetch_public_pdf_bytes(row.get("Approval File ID",""), row.get("Approval PDF",""))
                    if pdf_bytes:
                        st.caption("Approval PDF Preview")
                        try:
                            pdf_viewer(input=pdf_bytes, width=700, key=f"viewer_dev_{i}")
                        except Exception:
                            pass
                    elif row.get("Approval PDF"):
                        st.markdown(f"[Open Approval PDF]({row['Approval PDF']})")
                with c2:
                    pdf_ok = bool(row.get("Approval File ID")) and bool(row.get("Approval PDF"))
                    if not pdf_ok:
                        st.error("⚠️ No signed ICT Equipment Form attached. Cannot approve.")
                    reviewed = True
                    if REQUIRE_REVIEW_CHECK:
                        reviewed = st.checkbox("I reviewed the attached PDF", key=f"review_dev_{i}")
                    a_col, r_col = st.columns(2)
                    if a_col.button("Approve", key=f"approve_dev_{i}", disabled=not (reviewed and pdf_ok)):
                        _approve_device_row(row)
                    if r_col.button("Reject", key=f"reject_dev_{i}"):
                        _reject_row(PENDING_DEVICE_WS, i, row)

    st.markdown("---")
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
                    pdf_bytes = _fetch_public_pdf_bytes(row.get("Approval File ID",""), row.get("Approval PDF",""))
                    if pdf_bytes:
                        st.caption("Approval PDF Preview")
                        try:
                            pdf_viewer(input=pdf_bytes, width=700, key=f"viewer_tr_{i}")
                        except Exception:
                            pass
                    elif row.get("Approval PDF"):
                        st.markdown(f"[Open Approval PDF]({row['Approval PDF']})")
                with c2:
                    pdf_ok = bool(row.get("Approval File ID")) and bool(row.get("Approval PDF"))
                    if not pdf_ok:
                        st.error("⚠️ No signed ICT Equipment Form attached. Cannot approve.")
                    reviewed = True
                    if REQUIRE_REVIEW_CHECK:
                        reviewed = st.checkbox("I reviewed the attached PDF", key=f"review_tr_{i}")
                    a_col, r_col = st.columns(2)
                    if a_col.button("Approve", key=f"approve_tr_{i}", disabled=not (reviewed and pdf_ok)):
                        _approve_transfer_row(row)
                    if r_col.button("Reject", key=f"reject_tr_{i}"):
                        _reject_row(PENDING_TRANSFER_WS, i, row)


# =============================================================================
# APPROVAL ACTIONS
# =============================================================================

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
            "- Put your Service Account JSON under `st.secrets['gcp_service_account']` or env `GOOGLE_SERVICE_ACCOUNT_JSON`.\n"
            "- Ensure it includes **private_key** and **client_email**.\n"
            "- Share the Google Sheet URL in `st.secrets['sheets']['url']` with the service account email (Editor).\n"
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

# try restore session from cookie
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
