# Requirements (add to requirements.txt):
# streamlit gspread gspread-dataframe extra-streamlit-components pandas google-auth google-api-python-client

import os
import re
import glob
import io
import base64
import json
import hmac
import hashlib
import time
from datetime import datetime, timedelta

import streamlit as st
import pandas as pd
import gspread
from google.oauth2.service_account import Credentials
from gspread_dataframe import set_with_dataframe
import extra_streamlit_components as stx

# Drive API (optional but recommended for PDF storage)
try:
    from googleapiclient.discovery import build
    from googleapiclient.http import MediaIoBaseUpload
    HAS_DRIVE = True
except Exception:
    HAS_DRIVE = False

# =============================================================================
# CONFIG
# =============================================================================
APP_TITLE = "Tracking Inventory Management System"
SUBTITLE = "Advanced Construction"
DATE_FMT = "%Y-%m-%d %H:%M:%S"

# Cookie/session config
SESSION_TTL_DAYS = 30
SESSION_TTL_SECONDS = SESSION_TTL_DAYS * 24 * 60 * 60
COOKIE_NAME = "ac_auth"
COOKIE_PATH = "/"
COOKIE_SECURE = False
COOKIE_SAMESITE = "Lax"

# Default to your sheet URL; can be overridden in secrets
SHEET_URL_DEFAULT = "https://docs.google.com/spreadsheets/d/1SHp6gOW4ltsyOT41rwo85e_LELrHkwSwKN33K6XNHFI/edit"

# Worksheet titles (created if missing)
INVENTORY_WS     = "truckinventory"
TRANSFERLOG_WS   = "transfer_log"
EMPLOYEE_WS      = "mainlists"
PENDING_WS       = "pending_devices"   # staff submissions awaiting admin approval

# Debug toggle (set `[debug].show = true` in secrets to reveal diagnostics)
DEBUG_SHOW = bool(st.secrets.get("debug", {}).get("show", False))

# Inventory columns (uses "Current user"; synonym mapping covers 'USER')
INVENTORY_COLS = [
    "Serial Number","Device Type","Brand","Model","CPU",
    "Hard Drive 1","Hard Drive 2","Memory","GPU","Screen Size",
    "Current user","Previous User","TO",
    "Department","Email Address","Contact Number","Location","Office",
    "Notes","Date issued","Registered by"
]

# Transfer log columns (include Form URL)
LOG_COLS = [
    "Device Type","Serial Number","From owner","To owner",
    "Date issued","Registered by","Form URL"
]

# Employees sheet columns (no Email/APLUS)
EMPLOYEE_CANON_COLS = [
    "Employee ID","New Signature","Name","Address",
    "Active","Position","Department","Location (KSA)",
    "Project","Microsoft Teams","Mobile Number"
]

# Pending devices columns (same as inventory + audit/status)
PENDING_COLS = INVENTORY_COLS + [
    "Submitted by","Submitted at","Status","Approver","Approved at","Decision Note"
]

# -----------------------------------------------------------------------------
# Header normalization
# -----------------------------------------------------------------------------
# Map (normalized header) -> canonical name or None to DROP
HEADER_SYNONYMS = {
    # Drop legacy/undesired headers
    "newemployee": None,
    "newemployeer": None,
    "email": None,
    "emailaddress": None,
    "aplus": None,

    # Normalize variants
    "employeeid": "Employee ID",
    "newsignature": "New Signature",
    "locationksa": "Location (KSA)",
    "microsoftteams": "Microsoft Teams",
    "microsoftteam": "Microsoft Teams",
    "mobile": "Mobile Number",
    "mobilenumber": "Mobile Number",
}

# Map old inventory headers -> canonical
INVENTORY_HEADER_SYNONYMS = {
    "user": "Current user",
    "currentuser": "Current user",
    "previoususer": "Previous User",
    "to": "TO",
    "department1": None,  # drop
}

st.set_page_config(page_title=APP_TITLE, layout="wide")
COOKIE_MGR = stx.CookieManager(key="ac_cookie_mgr")

# =============================================================================
# HELPERS
# =============================================================================

def _norm_header(h: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (h or "").strip().lower())

def _norm_ws_title(t: str) -> str:
    return re.sub(r"\s+", "", (t or "").strip().lower())

def normalize_serial(s: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", (s or "").strip().upper())

_ws = re.compile(r"\s+")

def norm_name(x: str) -> str:
    return _ws.sub(" ", (x or "").strip().lower())


def type_or_select(label: str, options: list[str], key: str, help: str | None = None) -> str:
    _DEF_SELECT = "— Select —"
    _TYPE_NEW = "Type a new value…"
    opts = sorted({o.strip() for o in options if isinstance(o, str) and o.strip()})
    choice = st.selectbox(label, [_DEF_SELECT] + opts + [_TYPE_NEW], key=key, help=help)
    if choice == _TYPE_NEW:
        return st.text_input(f"Enter {label}", key=f"{key}_free")
    return "" if choice == _DEF_SELECT else choice

# =============================================================================
# AUTH (SESSION COOKIE)
# =============================================================================

def _cookie_key() -> str:
    return st.secrets.get("auth", {}).get("cookie_key", "PLEASE_SET_auth.cookie_key_IN_SECRETS")


def _sign(raw: bytes) -> str:
    return hmac.new(_cookie_key().encode(), raw, hashlib.sha256).hexdigest()


def _issue_session_cookie(username: str, role: str):
    iat = int(time.time())
    exp = iat + (SESSION_TTL_SECONDS if SESSION_TTL_SECONDS > 0 else 0)
    payload = {"u": username, "r": role, "iat": iat, "exp": exp, "v": 1}
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    token = base64.urlsafe_b64encode(raw).decode() + "." + _sign(raw)
    if SESSION_TTL_SECONDS > 0:
        COOKIE_MGR.set(COOKIE_NAME, token, max_age=SESSION_TTL_SECONDS, path=COOKIE_PATH, secure=COOKIE_SECURE, same_site=COOKIE_SAMESITE)
    else:
        COOKIE_MGR.set(COOKIE_NAME, token, path=COOKIE_PATH, secure=COOKIE_SECURE, same_site=COOKIE_SAMESITE)


def _read_cookie():
    token = COOKIE_MGR.get(COOKIE_NAME)
    if not token:
        return None
    try:
        data_b64, sig = token.split(".", 1)
        raw = base64.urlsafe_b64decode(data_b64.encode())
        if not hmac.compare_digest(sig, _sign(raw)):
            COOKIE_MGR.delete(COOKIE_NAME, path=COOKIE_PATH)
            return None
        payload = json.loads(raw.decode())
        if int(payload.get("exp", 0)) and int(time.time()) > int(payload.get("exp", 0)):
            COOKIE_MGR.delete(COOKIE_NAME, path=COOKIE_PATH)
            return None
        return payload
    except Exception:
        COOKIE_MGR.delete(COOKIE_NAME, path=COOKIE_PATH)
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
        COOKIE_MGR.delete(COOKIE_NAME, path=COOKIE_PATH)
        COOKIE_MGR.set(COOKIE_NAME, "", expires_at=datetime.utcnow() - timedelta(days=1), path=COOKIE_PATH)
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
# STYLE (Custom Font Loader)
# =============================================================================

def _inject_font_css(font_path: str, family: str = "ACBrandFont"):
    if not os.path.exists(font_path):
        return
    ext = os.path.splitext(font_path)[1].lower()
    mime = "font/ttf" if ext == ".ttf" else "font/otf"
    fmt = "truetype" if ext == ".ttf" else "opentype"
    with open(font_path, "rb") as f:
        b64 = base64.b64encode(f.read()).decode("utf-8")
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
          h1,h2,h3,h4,h5,h6, .stTabs [role="tab"] {{ font-family: '{family}', sans-serif !important; }}
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
        "company_font.ttf","company_font.otf","ACBrandFont.ttf","ACBrandFont.otf",
        "FounderGroteskCondensed-Regular.otf","Cairo-Regular.ttf",
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
        if st.session_state.get("authenticated") and st.button("Logout", key="logout_btn"):
            do_logout()

    st.markdown("<hr style='margin-top:0.8rem;'>", unsafe_allow_html=True)


def hide_table_toolbar_for_non_admin():
    if st.session_state.get("role") != "Admin":
        st.markdown(
            """
            <style>
              div[data-testid=\"stDataFrame\"] div[data-testid=\"stElementToolbar\"] { display:none !important; }
              div[data-testid=\"stDataEditor\"]  div[data-testid=\"stElementToolbar\"] { display:none !important; }
              div[data-testid=\"stElementToolbar\"] { display:none !important; }
            </style>
            """,
            unsafe_allow_html=True,
        )

# =============================================================================
# GOOGLE SHEETS — CLIENT / UTILITIES
# =============================================================================
SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive",
]

@st.cache_resource(show_spinner=False)
def _get_gc():
    creds = Credentials.from_service_account_info(st.secrets["gcp_service_account"], scopes=SCOPES)
    return gspread.authorize(creds)


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


def get_or_create_ws(title, rows=500, cols=80):
    sh = get_sh()
    # try exact and loose match first to avoid silently creating duplicates
    t_norm = _norm_ws_title(title)
    for ws in sh.worksheets():
        if _norm_ws_title(ws.title) == t_norm:
            return ws
    try:
        return sh.worksheet(title)
    except gspread.exceptions.WorksheetNotFound:
        return sh.add_worksheet(title=title, rows=rows, cols=cols)


def get_employee_ws() -> gspread.Worksheet:
    """Return the employees worksheet using robust matching, preferring existing tabs.
    Avoids creating a new empty sheet when a near-identical one exists."""
    sh = get_sh()
    preferred = [EMPLOYEE_WS, "Mainlists", "Main Lists", "Employees", "Employee List", "Employees (mainlists)"]
    titles = [ws.title for ws in sh.worksheets()]
    # exact/normalized lookup
    target_norm = _norm_ws_title(EMPLOYEE_WS)
    for ws in sh.worksheets():
        if _norm_ws_title(ws.title) == target_norm:
            return ws
    for name in preferred:
        for ws in sh.worksheets():
            if _norm_ws_title(ws.title) == _norm_ws_title(name):
                return ws
    # fallback create
    return sh.add_worksheet(title=EMPLOYEE_WS, rows=500, cols=50)

# ---------- EMPLOYEE DF CLEANING ----------

def _coalesce_duplicate_columns(df: pd.DataFrame) -> pd.DataFrame:
    from collections import Counter
    counts = Counter(df.columns)
    for name, n in list(counts.items()):
        if n > 1:
            cols = [c for c in df.columns if c == name]
            combined = df[cols].replace(["", None], pd.NA).bfill(axis=1).iloc[:, 0].fillna("").astype(str)
            df = df.drop(columns=cols).assign(**{name: combined})
    return df


def _clean_employee_df(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame(columns=EMPLOYEE_CANON_COLS)
    drops = [c for c in df.columns if _norm_header(c) in {k for k, v in HEADER_SYNONYMS.items() if v is None}]
    if drops:
        df = df.drop(columns=drops)
    df = _coalesce_duplicate_columns(df)
    for c in EMPLOYEE_CANON_COLS:
        if c not in df.columns:
            df[c] = ""
    return df[EMPLOYEE_CANON_COLS]


def _guess_employee_header_row(values: list[list[str]]) -> int:
    max_scan = min(len(values), 25)
    acceptable = set(EMPLOYEE_CANON_COLS)
    for k, v in HEADER_SYNONYMS.items():
        if v and v in acceptable:
            acceptable.add(v)
    best_i, best_score = 0, -1
    for i in range(max_scan):
        row = values[i]
        mapped = []
        for h in row:
            key = _norm_header(h)
            mapped_h = HEADER_SYNONYMS.get(key, h.strip())
            if mapped_h is None:
                continue
            mapped.append(mapped_h)
        score = len(set(mapped) & set(EMPLOYEE_CANON_COLS))
        if score > best_score:
            best_i, best_score = i, score
    # if no overlap at all but the first row is non-empty, still use first row as header
    if best_score <= 0:
        for i in range(max_scan):
            if any(x.strip() for x in values[i]):
                return i
    return best_i


def _read_employee_df(ws: gspread.Worksheet) -> pd.DataFrame:
    values = ws.get_all_values() or []
    if not values:
        return pd.DataFrame(columns=EMPLOYEE_CANON_COLS)
    hdr_idx = _guess_employee_header_row(values)
    headers_raw = values[hdr_idx]
    mapped_headers = []
    for h in headers_raw:
        key = _norm_header(h)
        mapped = HEADER_SYNONYMS.get(key, h.strip())
        if mapped is None:
            mapped_headers.append(f"DROP__{h}")
        else:
            mapped_headers.append(mapped)
    data_rows = values[hdr_idx + 1 :]
    if not data_rows:
        return pd.DataFrame(columns=EMPLOYEE_CANON_COLS)
    df = pd.DataFrame(data_rows, columns=mapped_headers)
    df = df.dropna(how="all").replace({None: ""})
    df = _clean_employee_df(df)
    return df

# ---------- INVENTORY HEADER NORMALIZATION ----------

def canon_inventory_columns(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return reorder_columns(df, INVENTORY_COLS)
    ren, drops = {}, []
    for c in list(df.columns):
        new = INVENTORY_HEADER_SYNONYMS.get(_norm_header(c))
        if new is None:
            drops.append(c)
        elif new:
            ren[c] = new
    if ren:
        df = df.rename(columns=ren)
    if drops:
        df = df.drop(columns=drops)
    return df


def reorder_columns(df: pd.DataFrame, desired: list[str]) -> pd.DataFrame:
    for c in desired:
        if c not in df.columns:
            df[c] = ""
    tail = [c for c in df.columns if c not in desired]
    return df[desired + tail]

# ---------- READ/CACHE LAYERS ----------

@st.cache_data(ttl=30, show_spinner=False)
def _read_worksheet_cached(ws_title: str) -> pd.DataFrame:
    if ws_title == EMPLOYEE_WS:
        ws = get_employee_ws()
        return _read_employee_df(ws)

    ws = get_or_create_ws(ws_title)
    data = ws.get_all_records()
    df = pd.DataFrame(data)
    if ws_title == INVENTORY_WS:
        df = canon_inventory_columns(df)
        return reorder_columns(df, INVENTORY_COLS)
    if ws_title == TRANSFERLOG_WS:
        return reorder_columns(df, LOG_COLS)
    if ws_title == PENDING_WS:
        return reorder_columns(df, PENDING_COLS)
    return df


def read_worksheet(ws_title: str) -> pd.DataFrame:
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
        if ws_title == PENDING_WS:
            return pd.DataFrame(columns=PENDING_COLS)
        return pd.DataFrame()

# ---------- WRITE HELPERS ----------

def write_worksheet(ws_title: str, df: pd.DataFrame):
    if ws_title == EMPLOYEE_WS:
        df = _clean_employee_df(df)
        ws = get_employee_ws()
    else:
        if ws_title == INVENTORY_WS:
            df = canon_inventory_columns(df)
            df = reorder_columns(df, INVENTORY_COLS)
        if ws_title == TRANSFERLOG_WS:
            df = reorder_columns(df, LOG_COLS)
        if ws_title == PENDING_WS:
            df = reorder_columns(df, PENDING_COLS)
        ws = get_or_create_ws(ws_title)
    ws.clear()
    set_with_dataframe(ws, df)
    st.cache_data.clear()


def append_to_worksheet(ws_title: str, new_data: pd.DataFrame):
    ws = get_or_create_ws(ws_title)
    df_existing = pd.DataFrame(ws.get_all_records())
    df_combined = pd.concat([df_existing, new_data], ignore_index=True)
    if ws_title == INVENTORY_WS:
        df_combined = canon_inventory_columns(df_combined)
        df_combined = reorder_columns(df_combined, INVENTORY_COLS)
    if ws_title == TRANSFERLOG_WS:
        df_combined = reorder_columns(df_combined, LOG_COLS)
    if ws_title == PENDING_WS:
        df_combined = reorder_columns(df_combined, PENDING_COLS)
    set_with_dataframe(ws, df_combined)
    st.cache_data.clear()

# =============================================================================
# DRIVE UPLOADS (PDF forms)
# =============================================================================

def _get_drive_service():
    if not HAS_DRIVE:
        raise RuntimeError("google-api-python-client not installed")
    creds = Credentials.from_service_account_info(st.secrets["gcp_service_account"], scopes=[
        "https://www.googleapis.com/auth/drive",
        "https://www.googleapis.com/auth/drive.file",
    ])
    return build('drive','v3', credentials=creds, cache_discovery=False)


def upload_pdf_to_drive(filename: str, content: bytes) -> str:
    folder_id = st.secrets.get("drive", {}).get("folder_id")
    if not folder_id:
        raise RuntimeError("Missing [drive].folder_id in secrets")
    service = _get_drive_service()
    file_metadata = {"name": filename, "parents": [folder_id]}
    media = MediaIoBaseUpload(io.BytesIO(content), mimetype="application/pdf", resumable=False)
    created = service.files().create(body=file_metadata, media_body=media, fields="id, webViewLink").execute()
    file_id = created["id"]
    service.permissions().create(fileId=file_id, body={"role":"reader","type":"anyone"}).execute()
    info = service.files().get(fileId=file_id, fields="webViewLink").execute()
    return info.get("webViewLink")

# =============================================================================
# AUTH (users) + LOGIN FORM
# =============================================================================

def load_users():
    admins = st.secrets.get("auth", {}).get("admins", {})
    staff  = st.secrets.get("auth", {}).get("staff", {})
    users = {}
    for user, pw in admins.items():
        if user != "type":
            users[user] = {"password": pw, "role": "Admin", "name": user}
    for user, pw in staff.items():
        users[user] = {"password": pw, "role": "Staff", "name": user}
    return users


USERS = load_users()


def show_login():
    st.subheader("🔐 Sign In")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login", type="primary", key="login_btn"):
        user = USERS.get(username)
        if user and user["password"] == password:
            do_login(username, user["role"])  # sets cookie + rerun
        else:
            st.error("❌ Invalid username or password.")

# =============================================================================
# ADMIN OVERRIDE (PIN)
# =============================================================================

def admin_confirm_widget(key_prefix: str, title: str = "Admin confirmation") -> bool:
    st.info(title)
    admins = [u for u in st.secrets.get("auth", {}).get("admins", {}).keys() if u != "type"]
    with st.form(f"admin_confirm_{key_prefix}", clear_on_submit=False):
        admin_user = st.selectbox("Admin username", ["— Select —"] + admins, key=f"admin_user_{key_prefix}")
        pin        = st.text_input("Admin PIN", type="password", key=f"admin_pin_{key_prefix}")
        ok = st.form_submit_button("Confirm", type="primary")
    if ok:
        if admin_user == "— Select —":
            st.error("Select an admin username.")
            st.stop()
        pins = st.secrets.get("auth", {}).get("override_pins", {})
        valid = str(pins.get(admin_user, "")) == str(pin).strip()
        if not valid:
            st.error("Invalid admin override.")
            st.stop()
        st.session_state[f"admin_ok_{key_prefix}"] = True
        st.session_state[f"admin_user_{key_prefix}"] = admin_user
    return st.session_state.get(f"admin_ok_{key_prefix}", False)

# =============================================================================
# TABS
# =============================================================================

def _refresh_button(key: str):
    col1, col2 = st.columns([1,8])
    with col1:
        if st.button("🔄 Refresh data", key=f"refresh_btn_{key}"):
            st.cache_data.clear()
            st.rerun()

# ---------- Employees ----------

def employees_view_tab():
    st.subheader("📇 Main Employees (mainlists)")
    _refresh_button("employees")
    if DEBUG_SHOW:
        with st.expander("🔍 Debug (worksheets)"):
            try:
                sh = get_sh()
                st.write([ws.title for ws in sh.worksheets()])
                ws_emp = get_employee_ws()
                st.write("Employees worksheet read:", ws_emp.title)
                st.write("Employee rows (raw):", len(ws_emp.get_all_values()))
            except Exception as e:
                st.error(str(e))
    df = read_worksheet(EMPLOYEE_WS)
    if df.empty:
        st.info("No employees found in 'mainlists'.")
    else:
        st.dataframe(df[EMPLOYEE_CANON_COLS], use_container_width=True, hide_index=True)


def employee_register_tab():
    st.subheader("🧑‍💼 Register New Employee (mainlists)")
    emp_df = read_worksheet(EMPLOYEE_WS)

    def _opts(col):
        return sorted({str(x).strip() for x in emp_df.get(col, pd.Series(dtype=str)).dropna().astype(str) if str(x).strip()})

    dept_opts = _opts("Department")
    pos_opts  = _opts("Position")
    loc_opts  = _opts("Location (KSA)")
    proj_opts = _opts("Project")
    teams_opts= _opts("Microsoft Teams")

    try:
        ids = pd.to_numeric(emp_df.get("Employee ID", pd.Series(dtype=str)), errors="coerce").dropna().astype(int)
        next_id_suggestion = str(ids.max() + 1) if len(ids) else str(len(emp_df) + 1)
    except Exception:
        next_id_suggestion = str(len(emp_df) + 1)

    with st.form("register_employee", clear_on_submit=True):
        r1c1, r1c2, r1c3 = st.columns(3)
        with r1c1:
            emp_id = st.text_input("Employee ID", help=f"Suggested next ID: {next_id_suggestion}")
        with r1c2:
            new_sig = st.text_input("New Signature")
        with r1c3:
            name = st.text_input("Name *")

        r2c1, r2c2, r2c3 = st.columns(3)
        with r2c1:
            address = st.text_input("Address")
        with r2c2:
            active  = st.text_input("Active")
        with r2c3:
            position = type_or_select("Position", pos_opts, key="pos")

        r3c1, r3c2, r3c3 = st.columns(3)
        with r3c1:
            department = type_or_select("Department", dept_opts, key="dept")
        with r3c2:
            location_ksa = type_or_select("Location (KSA)", loc_opts, key="loc")
        with r3c3:
            project = type_or_select("Project", proj_opts, key="proj")

        r4c1, r4c2 = st.columns(2)
        with r4c1:
            teams = type_or_select("Microsoft Teams", teams_opts, key="teams")
        with r4c2:
            mobile = st.text_input("Mobile Number")

        submitted = st.form_submit_button("Save Employee", type="primary")

    if submitted:
        if not (name or "").strip():
            st.error("Name is required.")
            return

        id_set    = set(emp_df.get("Employee ID", pd.Series(dtype=str)).astype(str).str.strip().str.lower())
        name_set  = set(emp_df.get("Name", pd.Series(dtype=str)).astype(str).str.lower().str.replace(r"\s+", " ", regex=True))
        phone_set = set(emp_df.get("Mobile Number", pd.Series(dtype=str)).astype(str).str.replace(r"\D+", "", regex=True))

        id_norm    = (emp_id or "").strip().lower()
        name_norm  = re.sub(r"\s+", " ", (name or "").strip().lower())
        phone_norm = re.sub(r"\D+", "", mobile or "")

        if id_norm and id_norm in id_set:
            st.error(f"Employee ID '{emp_id}' already exists.")
            return
        if name_norm and name_norm in name_set:
            st.error("An employee with the same name already exists.")
            return
        if phone_norm and phone_norm in phone_set:
            st.error("Mobile Number is already used by another employee.")
            return

        row = {
            "Employee ID": emp_id.strip() if emp_id.strip() else next_id_suggestion,
            "New Signature": new_sig.strip(),
            "Name": name.strip(),
            "Address": address.strip(),
            "Active": active.strip(),
            "Position": position.strip(),
            "Department": department.strip(),
            "Location (KSA)": location_ksa.strip(),
            "Project": project.strip(),
            "Microsoft Teams": teams.strip(),
            "Mobile Number": mobile.strip(),
        }
        new_df = pd.concat([emp_df, pd.DataFrame([row])], ignore_index=True) if not emp_df.empty else pd.DataFrame([row])
        new_df = _clean_employee_df(new_df)
        write_worksheet(EMPLOYEE_WS, new_df)
        st.success("✅ Employee saved to 'mainlists'.")

# ---------- Inventory + Pending approvals ----------

def register_device_tab():
    st.subheader("📝 Register New Device")
    with st.form("register_device", clear_on_submit=True):
        r1c1, r1c2, r1c3 = st.columns(3)
        with r1c1:
            serial = st.text_input("Serial Number *")
        with r1c2:
            current_user = st.text_input("Current user")
        with r1c3:
            device = st.text_input("Device Type *")

        r2c1, r2c2, r2c3 = st.columns(3)
        with r2c1:
            brand = st.text_input("Brand")
        with r2c2:
            model = st.text_input("Model")
        with r2c3:
            cpu = st.text_input("CPU")

        r3c1, r3c2, r3c3 = st.columns(3)
        with r3c1:
            mem = st.text_input("Memory")
        with r3c2:
            hdd1 = st.text_input("Hard Drive 1")
        with r3c3:
            hdd2 = st.text_input("Hard Drive 2")

        r4c1, r4c2, r4c3 = st.columns(3)
        with r4c1:
            gpu = st.text_input("GPU")
        with r4c2:
            screen = st.text_input("Screen Size")
        with r4c3:
            email = st.text_input("Email Address")

        r5c1, r5c2, r5c3 = st.columns(3)
        with r5c1:
            contact = st.text_input("Contact Number")
        with r5c2:
            dept = st.text_input("Department")
        with r5c3:
            location = st.text_input("Location")

        r6c1, r6c2 = st.columns([1, 2])
        with r6c1:
            office = st.text_input("Office")
        with r6c2:
            notes = st.text_area("Notes", height=60)

        need_inline_admin = st.session_state.get("role") == "Staff"
        if need_inline_admin:
            st.caption("If an admin is next to you, they can confirm now to add directly; otherwise it goes to Pending for approval.")
            inline_confirm = st.checkbox("Admin will confirm now", key="inline_admin_confirm")
        else:
            inline_confirm = False

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
                    f"Duplicate serial. Already exists as '{existing['Serial Number']}' "
                    f"({existing.get('Device Type','')} {existing.get('Brand','')}/{existing.get('Model','')})."
                )
                return

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
            "Current user": current_user.strip(),
            "Previous User": "",
            "TO": current_user.strip(),
            "Department": dept.strip(),
            "Email Address": email.strip(),
            "Contact Number": contact.strip(),
            "Location": location.strip(),
            "Office": office.strip(),
            "Notes": notes.strip(),
            "Date issued": datetime.now().strftime(DATE_FMT),
            "Registered by": st.session_state.get("username", ""),
        }

        if st.session_state.get("role") == "Admin":
            inv_fresh = read_worksheet(INVENTORY_WS)
            inv_out = pd.concat([inv_fresh, pd.DataFrame([row])], ignore_index=True) if not inv_fresh.empty else pd.DataFrame([row])
            inv_out = reorder_columns(inv_out, INVENTORY_COLS)
            write_worksheet(INVENTORY_WS, inv_out)
            st.success("✅ Device added to Inventory.")
        else:
            approver_now = False
            if inline_confirm:
                approver_now = admin_confirm_widget(key_prefix=f"add_{s_norm}", title="Admin confirmation to add device now")
            if approver_now:
                admin_user = st.session_state.get(f"admin_user_add_{s_norm}", "")
                row_direct = dict(row)
                row_direct["Registered by"] = f"{st.session_state.get('username','')} (via {admin_user})"
                inv_fresh = read_worksheet(INVENTORY_WS)
                inv_out = pd.concat([inv_fresh, pd.DataFrame([row_direct])], ignore_index=True) if not inv_fresh.empty else pd.DataFrame([row_direct])
                inv_out = reorder_columns(inv_out, INVENTORY_COLS)
                write_worksheet(INVENTORY_WS, inv_out)
                st.success("✅ Device added to Inventory (admin confirmed).")
            else:
                pend = read_worksheet(PENDING_WS)
                payload = dict(row)
                payload.update({
                    "Submitted by": st.session_state.get("username",""),
                    "Submitted at": datetime.now().strftime(DATE_FMT),
                    "Status": "Pending",
                    "Approver": "",
                    "Approved at": "",
                    "Decision Note": "",
                })
                pend_out = pd.concat([pend, pd.DataFrame([payload])], ignore_index=True) if not pend.empty else pd.DataFrame([payload])
                pend_out = reorder_columns(pend_out, PENDING_COLS)
                write_worksheet(PENDING_WS, pend_out)
                st.success("🕒 Submitted for admin approval. You'll be able to transfer after it's approved.")

# ---------- Inventory view ----------

def inventory_tab():
    st.subheader("📋 Main Inventory")
    _refresh_button("inventory")
    df = read_worksheet(INVENTORY_WS)
    if df.empty:
        st.warning("Inventory is empty.")
    else:
        st.dataframe(df, use_container_width=True)

# ---------- Transfer with PDF required + Approvals (moved here) ----------

def transfer_tab():
    st.subheader("🔁 Transfer Device (PDF form required)")

    # Blank template download
    template_paths = ["assets/transfer_form_template.pdf", "transfer_form_template.pdf"]
    found_template = next((p for p in template_paths if os.path.exists(p)), None)
    col_dl, _ = st.columns([1,4])
    with col_dl:
        if found_template:
            with open(found_template, "rb") as f:
                st.download_button(
                    "⬇️ Download transfer form (PDF)",
                    f.read(),
                    file_name="transfer_form_template.pdf",
                    mime="application/pdf",
                    key="dl_template_transfer"
                )
        else:
            st.info("Place a template at assets/transfer_form_template.pdf to enable download.")

    # Transfer form
    inventory_df = read_worksheet(INVENTORY_WS)
    if inventory_df.empty:
        st.warning("Inventory is empty.")
        return

    serial_list = sorted(inventory_df["Serial Number"].dropna().astype(str).unique().tolist())
    serial = st.selectbox("Serial Number", ["— Select —"] + serial_list, key="transfer_sn")
    chosen_serial = None if serial == "— Select —" else serial

    existing_users = sorted([u for u in inventory_df["Current user"].dropna().astype(str).tolist() if u.strip()])
    new_owner_choice = st.selectbox("New Owner", ["— Select —"] + existing_users + ["Type a new name…"], key="transfer_new_owner_choice")
    if new_owner_choice == "Type a new name…":
        new_owner = st.text_input("Enter new owner name", key="transfer_new_owner_custom")
    else:
        new_owner = new_owner_choice if new_owner_choice != "— Select —" else ""

    uploaded_pdf = st.file_uploader(
        "Upload signed transfer form (PDF, ≤ 100 KB) *",
        type=["pdf"],
        accept_multiple_files=False,
        key="transfer_pdf"
    )

    def _pdf_ok() -> tuple[bool, str]:
        if not uploaded_pdf:
            return False, "Please upload the signed transfer form (PDF)."
        if getattr(uploaded_pdf, "type", "") != "application/pdf":
            return False, "Only PDF files are allowed."
        size = getattr(uploaded_pdf, "size", None)
        if size is None:
            uploaded_pdf.seek(0, os.SEEK_END); size = uploaded_pdf.tell(); uploaded_pdf.seek(0)
        if size <= 0 or size > 100 * 1024:
            return False, "PDF must be between 1 byte and 100 KB."
        return True, ""

    ok_file, err_msg = _pdf_ok()
    if not ok_file and uploaded_pdf is not None:
        st.error(err_msg)

    do_transfer = st.button(
        "Transfer Now",
        type="primary",
        disabled=not (chosen_serial and new_owner.strip() and ok_file),
        key="transfer_now"
    )

    if do_transfer:
        match = inventory_df[inventory_df["Serial Number"].astype(str) == chosen_serial]
        if match.empty:
            st.warning("Serial number not found.")
            return

        pdf_bytes = uploaded_pdf.getvalue()
        pdf_filename = f"transfer_{chosen_serial}_{int(time.time())}.pdf"
        try:
            form_url = upload_pdf_to_drive(pdf_filename, pdf_bytes)
        except Exception as e:
            st.error(f"Could not store PDF form. Admin: set [drive].folder_id in secrets and deploy. Detail: {e}")
            return

        idx = match.index[0]
        prev_user = str(inventory_df.loc[idx, "Current user"] or "")
        now_str   = datetime.now().strftime(DATE_FMT)
        actor     = st.session_state.get("username", "")

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
            "Form URL": form_url,
        }
        append_to_worksheet(TRANSFERLOG_WS, pd.DataFrame([log_row]))

        st.success(f"✅ Transfer saved: {prev_user or '(blank)'} → {new_owner.strip()} (form stored)")

    # -------------------- Admin-only: Pending Device Approvals (moved here) --------------------
    if st.session_state.get("role") == "Admin":
        st.divider()
        st.markdown("### 🔏 Pending Device Approvals")
        _refresh_button("approvals_in_transfer")
        pend = read_worksheet(PENDING_WS)
        if pend.empty or not (pend["Status"] == "Pending").any():
            st.info("No pending devices.")
        else:
            for ridx, row in pend[pend["Status"] == "Pending"].reset_index().iterrows():
                label = f"{row['Device Type']} — {row['Brand']} {row['Model']} — SN: {row['Serial Number']}"
                with st.expander(label):
                    st.write({k: row[k] for k in ["Submitted by","Submitted at","Department","Current user","Location","Notes"]})
                    c1, c2, c3 = st.columns([1,1,3])
                    with c3:
                        note = st.text_input("Decision note", key=f"apx_note_{row['Serial Number']}_{ridx}")
                    row_index = row['index']
                    with c1:
                        if st.button("✅ Approve", key=f"apx_approve_{row['Serial Number']}_{ridx}"):
                            inv = read_worksheet(INVENTORY_WS)
                            inv_out = pd.concat([inv, pd.DataFrame([row[INVENTORY_COLS].to_dict()])], ignore_index=True) if not inv.empty else pd.DataFrame([row[INVENTORY_COLS].to_dict()])
                            inv_out = reorder_columns(inv_out, INVENTORY_COLS)
                            write_worksheet(INVENTORY_WS, inv_out)
                            pend.at[row_index, "Status"] = "Approved"
                            pend.at[row_index, "Approver"] = st.session_state.get("username", "")
                            pend.at[row_index, "Approved at"] = datetime.now().strftime(DATE_FMT)
                            pend.at[row_index, "Decision Note"] = note
                            write_worksheet(PENDING_WS, pend)
                            st.success("Approved and added to Inventory.")
                            st.rerun()
                    with c2:
                        if st.button("❌ Reject", key=f"apx_reject_{row['Serial Number']}_{ridx}"):
                            pend.at[row_index, "Status"] = "Rejected"
                            pend.at[row_index, "Approver"] = st.session_state.get("username", "")
                            pend.at[row_index, "Approved at"] = datetime.now().strftime(DATE_FMT)
                            pend.at[row_index, "Decision Note"] = note
                            write_worksheet(PENDING_WS, pend)
                            st.warning("Rejected.")
                            st.rerun()

# ---------- History ----------

def history_tab():
    st.subheader("📜 History Transfer")
    _refresh_button("history")
    df = read_worksheet(TRANSFERLOG_WS)
    if df.empty:
        st.info("No transfer history found.")
    else:
        st.dataframe(df, use_container_width=True, hide_index=True)

# ---------- Export (CSV + template + open PDF forms) ----------

def export_tab():
    st.subheader("⬇️ Export (always fresh)")
    _refresh_button("export")
    inv = read_worksheet(INVENTORY_WS)
    log = read_worksheet(TRANSFERLOG_WS)
    emp = read_worksheet(EMPLOYEE_WS)
    pend = read_worksheet(PENDING_WS)
    st.caption(f"Last fetched: {datetime.now().strftime(DATE_FMT)}")

    # CSV buttons (+ template PDF)
    template_paths = ["assets/transfer_form_template.pdf", "transfer_form_template.pdf"]
    found_template = next((p for p in template_paths if os.path.exists(p)), None)

    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        st.download_button("Inventory CSV", inv.to_csv(index=False).encode("utf-8"), "inventory.csv", "text/csv", key="dl_inv")
    with c2:
        st.download_button("Transfer Log CSV", log.to_csv(index=False).encode("utf-8"), "transfer_log.csv", "text/csv", key="dl_log")
    with c3:
        st.download_button("Employees CSV", emp.to_csv(index=False).encode("utf-8"), "employees.csv", "text/csv", key="dl_emp")
    with c4:
        st.download_button("Pending Devices CSV", pend.to_csv(index=False).encode("utf-8"), "pending_devices.csv", "text/csv", key="dl_pend")
    with c5:
        if found_template:
            with open(found_template, "rb") as f:
                st.download_button(
                    "Blank Transfer Form (PDF)",
                    f.read(),
                    file_name="transfer_form_template.pdf",
                    mime="application/pdf",
                    key="dl_template_export"
                )
        else:
            st.info("Add assets/transfer_form_template.pdf to enable template download.")

    # Signed form open buttons
    st.markdown("### 📄 Signed Transfer Forms")
    if log.empty or not log.get("Form URL").dropna().any():
        st.info("No signed forms uploaded yet.")
        return

    df_forms = log.dropna(subset=["Form URL"]).copy()
    df_forms["__ts"] = pd.to_datetime(df_forms["Date issued"], errors="coerce")
    df_forms = df_forms.sort_values("__ts", ascending=False)

    sn_options = ["All"] + sorted(df_forms["Serial Number"].astype(str).unique().tolist())
    choice_sn = st.selectbox("Filter by Serial Number", sn_options, key="export_forms_sn")
    top_n = st.number_input("Show most recent N", min_value=1, max_value=1000, value=50, step=1, key="export_forms_n")

    if choice_sn != "All":
        df_forms = df_forms[df_forms["Serial Number"].astype(str) == choice_sn]

    df_forms = df_forms.head(int(top_n))

    for i, r in df_forms.iterrows():
        label = f"{r['Serial Number']} – {r.get('From owner','')} → {r.get('To owner','')} ({r.get('Date issued','')})"
        st.link_button(f"Open PDF: {label}", r["Form URL"], key=f"open_form_{i}")

# =============================================================================
# MAIN
# =============================================================================

def run_app():
    render_header()
    hide_table_toolbar_for_non_admin()

    if st.session_state.role == "Admin":
        tabs = st.tabs([
            "🧑‍💼 Employee Register",
            "🧾 Main Employees",
            "📝 Register Device",
            "📋 Main Inventory",
            "🔁 Transfer Device",
            "📜 History Transfer",
            "⬇️ Export",
        ])
        with tabs[0]: employee_register_tab()
        with tabs[1]: employees_view_tab()
        with tabs[2]: register_device_tab()
        # Approvals tab removed; moved into Transfer
        with tabs[3]: inventory_tab()
        with tabs[4]: transfer_tab()
        with tabs[5]: history_tab()
        with tabs[6]: export_tab()
    else:
        tabs = st.tabs(["📋 Main Inventory", "📝 Register Device", "🔁 Transfer Device", "📜 History Transfer"])
        with tabs[0]: inventory_tab()
        with tabs[1]: register_device_tab()
        with tabs[2]: transfer_tab()
        with tabs[3]: history_tab()

# =============================================================================
# ENTRY
# =============================================================================
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

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
    # Quick onboarding note if creds/secrets missing
    if DEBUG_SHOW:
        with st.expander("🔧 Debug – secrets checks"):
            st.write("Sheet URL:", _get_sheet_url())
            try:
                st.write("Service account:", st.secrets["gcp_service_account"].get("client_email"))
            except Exception as e:
                st.error("Missing gcp_service_account in secrets")
    show_login()
