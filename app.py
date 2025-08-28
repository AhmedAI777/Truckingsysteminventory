# app.py — Tracking Inventory Management System (Option B: My Drive via OAuth token)
# - Google Sheets via Service Account (SA)
# - Google Drive uploads: try SA → on 403 storageQuotaExceeded, fall back to OAuth **token from secrets**
# - Streamlit Cloud safe (no interactive browser). Admin must review PDF inline before Approve.
#
# Requirements:
#   pip install streamlit gspread gspread-dataframe extra-streamlit-components pandas \
#               google-auth google-api-python-client streamlit-pdf-viewer requests

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
    "Approval Status","Approval PDF",approvals,
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
            f"""<div style=\"display:flex; align-items:center; justify-content:flex-end; gap:1rem;\">\n                   <div>\n                     <div style=\"font-weight:600;\">Welcome, {username or '—'}</div>\n                     <div>Role: <b>{role or '—'}</b></div>\n                   </div>\n                 </div>""",
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
# GOOGLE SHEETS & DRIVE (Service Account + OAuth token fallback)
# =============================================================================
SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive",
]
OAUTH_SCOPES = ["https://www.googleapis.com/auth/drive.file"]  # user upload to My Drive

# Option B flag: allow OAuth fallback, but ONLY via token in secrets (no browser in cloud)
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
    """Get user OAuth creds STRICTLY from secrets.token_json in cloud.
    If token_json is missing and LOCAL_OAUTH=1, allow interactive local auth.
    Otherwise stop with a helpful error (prevents 'no runnable browser').
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
            creds.refresh(Request())
        return creds

    # No token_json present
    if os.environ.get("LOCAL_OAUTH", "0") == "1":
        # Local-only flow
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
        pass


def _is_pdf_bytes(data: bytes) -> bool:
    return isinstance(data, (bytes, bytearray)) and data[:4] == b"%PDF"


def upload_pdf_and_link(uploaded_file, *, prefix: str) -> tuple[str, str]:
    """Upload PDF to Drive. Try SA first; on 403 storage quota, fall back to OAuth user (My Drive)."""
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


def _fetch_public_pdf_bytes(file_id: str, link: str) -> bytes:
    """Fetch bytes for PDF preview (works when file is public)."""
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

import io
from pdfrw import PdfReader, PdfWriter, PageMerge
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from datetime import datetime

def generate_prefilled_pdf(device_data: dict, user_data: dict, output_filename: str) -> bytes:
    buffer = io.BytesIO()
    can = canvas.Canvas(buffer, pagesize=A4)
    
    can.drawString(70, 790, f"Name: {user_data.get('Name', '')}")
    can.drawString(70, 770, f"Mobile Number: {user_data.get('Mobile Number', '')}")
    can.drawString(70, 750, f"Email Address: {user_data.get('Email', '')}")
    can.drawString(70, 730, f"Department: {user_data.get('Department', '')}")
    can.drawString(70, 710, f"Date: {datetime.today().strftime('%Y-%m-%d')}")
    can.drawString(70, 690, f"Location: {user_data.get('Location (KSA)', '')}")

    y = 650
    for idx, dev in enumerate(device_data, 1):
        can.drawString(70, y, f"Device {idx}: {dev['Device Type']} - {dev['Brand']} {dev['Model']} - SN: {dev['Serial Number']}")
        y -= 20

    can.save()
    buffer.seek(0)
    
    overlay_pdf = PdfReader(fdata=buffer.read())
    base_pdf = PdfReader("Register and Transfer Device.pdf")
    
    for page_num, page in enumerate(base_pdf.pages):
        overlay_page = overlay_pdf.pages[0] if overlay_pdf.pages else None
        if overlay_page:
            merger = PageMerge(page)
            merger.add(overlay_page).render()

    output = io.BytesIO()
    PdfWriter(output, trailer=base_pdf).write()
    return output.getvalue()

def get_device_from_inventory(serial, inventory_df):
    serial = serial.strip().upper()
    match = inventory_df[inventory_df["Serial Number"].str.upper() == serial]
    if not match.empty:
        return match.iloc[0].to_dict()
    return None

def get_user_info(name, mainlist_df):
    match = mainlist_df[mainlist_df["Name"].str.strip().str.lower() == name.strip().lower()]
    if not match.empty:
        return match.iloc[0].to_dict()
    return None


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
    st.subheader("📝 Register New Device (Autofill + Download)")

    emp_df = read_worksheet(EMPLOYEE_WS)
    inv_df = read_worksheet(INVENTORY_WS)

    emp_names = sorted(emp_df["Name"].dropna().unique().tolist())
    serial_numbers = sorted(inv_df["Serial Number"].dropna().unique().tolist())

    selected_serial = st.selectbox("Select Serial Number", ["— Select —"] + serial_numbers)
    selected_user = st.selectbox("Assign to Employee", ["— Select —"] + emp_names)

    device_data = get_device_from_inventory(selected_serial, inv_df) if selected_serial != "— Select —" else {}
    user_data = get_user_info(selected_user, emp_df) if selected_user != "— Select —" else {}

    with st.form("register_device_form"):
        col1, col2, col3 = st.columns(3)
        with col1:
            serial = st.text_input("Serial Number", value=selected_serial or "")
        with col2:
            assigned_to = st.text_input("Assigned to", value=user_data.get("Name", ""))
        with col3:
            device_type = st.text_input("Device Type", value=device_data.get("Device Type", ""))

        col4, col5, col6 = st.columns(3)
        with col4:
            brand = st.text_input("Brand", value=device_data.get("Brand", ""))
        with col5:
            model = st.text_input("Model", value=device_data.get("Model", ""))
        with col6:
            cpu = st.text_input("CPU", value=device_data.get("CPU", ""))

        col7, col8, col9 = st.columns(3)
        with col7:
            mem = st.text_input("Memory", value=device_data.get("Memory", ""))
        with col8:
            hdd1 = st.text_input("Hard Drive 1", value=device_data.get("Hard Drive 1", ""))
        with col9:
            hdd2 = st.text_input("Hard Drive 2", value=device_data.get("Hard Drive 2", ""))

        col10, col11, col12 = st.columns(3)
        with col10:
            gpu = st.text_input("GPU", value=device_data.get("GPU", ""))
        with col11:
            screen = st.text_input("Screen Size", value=device_data.get("Screen Size", ""))
        with col12:
            email = st.text_input("Email Address", value=user_data.get("Email", ""))

        col13, col14, col15 = st.columns(3)
        with col13:
            contact = st.text_input("Contact Number", value=user_data.get("Mobile Number", ""))
        with col14:
            dept = st.text_input("Department", value=user_data.get("Department", ""))
        with col15:
            location = st.text_input("Location", value=user_data.get("Location (KSA)", ""))

        office = st.text_input("Office")
        notes = st.text_area("Notes", height=60)

        # PDF upload field (signed scanned file)
        pdf_file = st.file_uploader("Upload Scanned Signed Approval PDF", type=["pdf"], key="upload_signed_pdf")

        submitted = st.form_submit_button("Submit Device", type="primary")

    # 🔽 Download Prefilled PDF before uploading
    if selected_serial != "— Select —" and selected_user != "— Select —":
        today = datetime.today().strftime("%Y%m%d")
        seq = "0008"  # Can be made auto-increment later
        filename = f"HO-JED-REG-{selected_serial}-{seq}-{today}.pdf"

        if device_data and user_data:
            pdf_bytes = generate_prefilled_pdf([device_data], user_data, filename)
            st.download_button(
                label=f"⬇️ Download Prefilled PDF: {filename}",
                data=pdf_bytes,
                file_name=filename,
                mime="application/pdf"
            )

    if submitted:
        if not serial.strip() or not device_type.strip():
            st.error("Serial Number and Device Type are required.")
            return

        now_str = datetime.now().strftime(DATE_FMT)
        actor = st.session_state.get("username", "")
        is_admin = st.session_state.get("role") == "Admin"

        row = {
            "Serial Number": serial,
            "Device Type": device_type,
            "Brand": brand,
            "Model": model,
            "CPU": cpu,
            "Hard Drive 1": hdd1,
            "Hard Drive 2": hdd2,
            "Memory": mem,
            "GPU": gpu,
            "Screen Size": screen,
            "Current user": assigned_to,
            "Previous User": "",
            "TO": assigned_to,
            "Department": dept,
            "Email Address": email,
            "Contact Number": contact,
            "Location": location,
            "Office": office,
            "Notes": notes,
            "Date issued": now_str,
            "Registered by": actor,
        }

        if is_admin:
            append_to_worksheet(INVENTORY_WS, pd.DataFrame([row]))
            st.success("✅ Device registered and added to Inventory.")
        else:
            if not pdf_file:
                st.error("Staff must upload a signed PDF for approval.")
                return

            link, fid = upload_pdf_and_link(pdf_file, prefix=f"device_{normalize_serial(serial)}")
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
            st.success("🕒 Submitted for admin approval.")


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

    # Optional live preview
    if ss.get("transfer_pdf"):
        ss.transfer_pdf_ref = ss.transfer_pdf
    if ss.transfer_pdf_ref:
        st.caption("Preview: Approval PDF")
        try:
            pdf_viewer(input=ss.transfer_pdf_ref.getvalue(), width=700, key="viewer_trans")
        except Exception:
            pass

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
                approvals: fid,
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
    st.subheader("✅ Approvals (Admin Only)")
    pending_df = read_worksheet(PENDING_DEVICE_WS)
    if pending_df.empty:
        st.info("No pending approvals.")
        return

    for i, row in pending_df.iterrows():
        with st.expander(f"Serial: {row['Serial Number']}  User: {row['Current user']}"):
            st.json(row.to_dict(), expanded=False)
            if row.get("Approval PDF"):
                st.markdown(f"[📎 View Uploaded Signed PDF]({row['Approval PDF']})")

            decision = st.radio(
                f"Decision for {row['Serial Number']}:",
                ["Approve", "Reject", "Skip"],
                key=f"decision_{i}",
                horizontal=True
            )

            if decision == "Approve":
                #  Upload signed PDF to your Drive folder
                file_id = row.get("Approval File ID")
                if file_id:
                    serial = normalize_serial(row["Serial Number"])
                    user = row["Current user"].replace(" ", "_")
                    filename = f"signed_{serial}_{user}.pdf"
                    new_link, _ = move_file_in_drive(
                        file_id,
                        target_folder_id="YOUR_DRIVE_FOLDER_ID",  # Replace this
                        new_name=filename
                    )
                    row["Final PDF"] = new_link
                    st.info(f"📁 Signed PDF stored in Drive: {new_link}")

                #  Add to inventory
                append_to_worksheet(INVENTORY_WS, pd.DataFrame([row]))
                st.success("✅ Approved and added to inventory.")

                #  Remove from pending
                pending_df.drop(index=i, inplace=True)
                write_worksheet(PENDING_DEVICE_WS, pending_df)
                st.rerun()

            elif decision == "Reject":
                pending_df.drop(index=i, inplace=True)
                write_worksheet(PENDING_DEVICE_WS, pending_df)
                st.warning("❌ Request rejected and removed.")
                st.rerun()

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
            "🧑‍💼 Employee Register",      # tabs[0]
            "📇 View Employees",          # tabs[1]
            "📝 Register Device",         # tabs[2]
            "📄 Generate Prefilled PDF",  # tabs[3]
            "📋 View Inventory",          # tabs[4]
            "🔁 Transfer Device",         # tabs[5]
            "📜 Transfer Log",            # tabs[6]
            "✅ Approvals",               # tabs[7]
            "⬇️ Export",                  # tabs[8]
        ])
        with tabs[0]: employee_register_tab()
        with tabs[1]: employees_view_tab()
        with tabs[2]: register_device_tab()
        with tabs[3]: prefill_pdf_tab()
        with tabs[4]: inventory_tab()
        with tabs[5]: transfer_tab()
        with tabs[6]: history_tab()
        with tabs[7]: approvals_tab()
        with tabs[8]: export_tab()

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
