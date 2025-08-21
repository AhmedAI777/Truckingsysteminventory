# path: app/streamlit_app_inventory.py
# NOTE: This version removes the standalone "Name" field in the Employee form,
# relabels "New Employeer" as the required name field, and writes both
# "New Employeer" and "Name" columns with the same value for compatibility.
# It also adds helpful dropdowns (with "Other…" fallbacks) for common fields.

# pip install streamlit gspread gspread-dataframe extra-streamlit-components pandas google-auth
import os
import re
import glob
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

# =============================================================================
# CONFIG
# =============================================================================
APP_TITLE = "Tracking Inventory Management System"
SUBTITLE  = "Advanced Construction"
DATE_FMT  = "%Y-%m-%d %H:%M:%S"

# Cookie/session config (persist login across refresh; set SESSION_TTL_DAYS=0 for session-only)
SESSION_TTL_DAYS = 30
SESSION_TTL_SECONDS = SESSION_TTL_DAYS * 24 * 60 * 60
COOKIE_NAME = "ac_auth"
COOKIE_PATH = "/"
COOKIE_SECURE = False   # set True if app is served over HTTPS
COOKIE_SAMESITE = "Lax" # or "Strict" / "None" (with SECURE=True)

# Default to your sheet URL; can be overridden in secrets
SHEET_URL_DEFAULT = "https://docs.google.com/spreadsheets/d/1SHp6gOW4ltsyOT41rwo85e_LELrHkwSwKN33K6XNHFI/edit"

# Worksheet titles (created if missing)
INVENTORY_WS    = "truckinventory"
TRANSFERLOG_WS  = "transfer_log"
EMPLOYEE_WS     = "mainlists"

# Canonical inventory columns (UPDATED: uses "Current user"; removed Department.1)
INVENTORY_COLS = [
    "Serial Number","Device Type","Brand","Model","CPU",
    "Hard Drive 1","Hard Drive 2","Memory","GPU","Screen Size",
    "Current user","Previous User","TO",
    "Department","Email Address","Contact Number","Location","Office",
    "Notes","Date issued","Registered by"
]
LOG_COLS = ["Device Type","Serial Number","From owner","To owner","Date issued","Registered by"]

# Employees sheet columns (canonical names)
# Keeping both columns in the sheet for compatibility. The form only asks once
# and the same value is written to both columns.
EMPLOYEE_CANON_COLS = [
    "New Employeer","Employee ID","New Signature","Name","Address",
    "Active","Position","Department","Location (KSA)",
    "Project","Microsoft Teams","Mobile Number"
]

# Accept common synonym/typo headers and normalize to canon (employees)
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

# Map old inventory headers → new canonical names
INVENTORY_HEADER_SYNONYMS = {
    "user": "Current user",
    "currentuser": "Current user",
    "previoususer": "Previous User",
    "to": "TO",
    "department1": None,  # drop this header entirely if present
}

st.set_page_config(page_title=APP_TITLE, layout="wide")

# Mount CookieManager once
COOKIE_MGR = stx.CookieManager(key="ac_cookie_mgr")

# =============================================================================
# HELPERS (serial normalization + near-duplicate)
# =============================================================================

def normalize_serial(s: str) -> str:
    """Uppercase and strip all non-alphanumerics for stable serial comparison."""
    return re.sub(r"[^A-Z0-9]", "", (s or "").strip().upper())


def levenshtein(a: str, b: str, max_dist: int = 1) -> int:
    """Compute Levenshtein distance with early-exit when distance > max_dist."""
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if abs(la - lb) > max_dist:
        return max_dist + 1
    # ensure a is shorter
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

# =============================================================================
# AUTH (SESSION COOKIE)
# =============================================================================

def _cookie_key() -> str:
    # Put a strong random in secrets:
    # [auth]
    # cookie_key = "your-very-long-random-secret"
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
        COOKIE_MGR.set(
            COOKIE_NAME,
            token,
            max_age=SESSION_TTL_SECONDS,
            path=COOKIE_PATH,
            secure=COOKIE_SECURE,
            same_site=COOKIE_SAMESITE,
        )
    else:
        COOKIE_MGR.set(
            COOKIE_NAME,
            token,
            path=COOKIE_PATH,
            secure=COOKIE_SECURE,
            same_site=COOKIE_SAMESITE,
        )


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
        exp = int(payload.get("exp", 0))
        now = int(time.time())
        if exp and now > exp:
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

# Ensure CookieManager is mounted before first read
if "cookie_bootstrapped" not in st.session_state:
    st.session_state.cookie_bootstrapped = True
    _ = COOKIE_MGR.get_all()
    st.rerun()

# =============================================================================
# STYLE (Custom Font Loader)
# =============================================================================

def _inject_font_css(font_path: str, family: str = "ACBrandFont"):
    """Embed a local TTF/OTF and apply as the default UI font."""
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
          section.main > div {{ padding-top: 0.6rem; }}
        </style>
        """,
        unsafe_allow_html=True,
    )


def _font_candidates():
    """Return likely font file paths in priority order."""
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
              div[data-testid=\"stDataFrame\"] div[data-testid=\"stElementToolbar\"] { display:none !important; }
              div[data-testid=\"stDataEditor\"]  div[data-testid=\"stElementToolbar\"] { display:none !important; }
              div[data-testid=\"stElementToolbar\"] { display:none !important; }
            </style>
            """,
            unsafe_allow_html=True
        )

# =============================================================================
# GOOGLE SHEETS — LAZY + RETRY + CACHED READS
# =============================================================================
SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive",
]


@st.cache_resource(show_spinner=False)
def _get_gc():
    creds = Credentials.from_service_account_info(
        st.secrets["gcp_service_account"], scopes=SCOPES
    )
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
    st.error("Google Sheets API error while opening the spreadsheet. "
             "Please confirm the service account has access and try again.")
    raise last_exc


def _norm_title(t: str) -> str:
    return (t or "").strip().lower()


def _norm_header(h: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (h or "").strip().lower())


def _canon_header(h: str) -> str:
    key = _norm_header(h)
    return HEADER_SYNONYMS.get(key, h.strip())


def canon_inventory_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize inventory headers (e.g., USER → Current user) and drop deprecated ones."""
    rename = {}
    drop_cols = []
    for c in df.columns:
        key = _norm_header(c)
        if key in INVENTORY_HEADER_SYNONYMS:
            new = INVENTORY_HEADER_SYNONYMS[key]
            if new:
                rename[c] = new
            else:
                drop_cols.append(c)  # Department.1 → drop
    if rename:
        df = df.rename(columns=rename)
    if drop_cols:
        df = df.drop(columns=drop_cols)
    return df


def reorder_columns(df: pd.DataFrame, desired: list[str]) -> pd.DataFrame:
    for c in desired:
        if c not in df.columns:
            df[c] = ""
    tail = [c for c in df.columns if c not in desired]
    return df[desired + tail]


def reorder_columns_strict(df: pd.DataFrame, desired: list[str]) -> pd.DataFrame:
    """Return only desired columns (create missing), drop all extras. Why: keep employees schema clean."""
    for c in desired:
        if c not in df.columns:
            df[c] = ""
    return df[desired]


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
    df = reorder_columns_strict(df, expected_cols)
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
        return pd.DataFrame()


def write_worksheet(ws_title, df):
    if ws_title == INVENTORY_WS:
        df = canon_inventory_columns(df)
        df = reorder_columns(df, INVENTORY_COLS)
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
    df_combined = pd.concat([df_existing, new_data], ignore_index=True)
    set_with_dataframe(ws, df_combined)
    st.cache_data.clear()

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
    if st.button("Login", type="primary"):
        user = USERS.get(username)
        if user and user["password"] == password:
            do_login(username, user["role"])  # sets cookie + rerun
        else:
            st.error("❌ Invalid username or password.")

# =============================================================================
# ADMIN OVERRIDE (for near-duplicate serials)
# =============================================================================

def admin_override_widget(s_norm: str, similar_serials: list[str]) -> bool:
    """Inline admin confirmation gate. Returns True if a valid admin override PIN was provided.
    Configure pins in secrets:

    [auth]
    # admins = { alice = "...", bob = "..." }
    [auth.override_pins]
    alice = "123456"
    bob   = "654321"
    """
    st.warning(
        "Near-duplicate serial detected: " + ", ".join(similar_serials) +
        ". Admin confirmation required to proceed."
    )
    admins = [u for u in st.secrets.get("auth", {}).get("admins", {}).keys() if u != "type"]
    with st.form(f"override_form_{s_norm}", clear_on_submit=False):
        admin_user = st.selectbox("Admin username", ["— Select —"] + admins, index=0)
        pin = st.text_input("Admin override PIN", type="password")
        ok = st.form_submit_button("Confirm admin override", type="primary")
    if ok:
        if admin_user == "— Select —":
            st.error("Select an admin username.")
            st.stop()
        pins = st.secrets.get("auth", {}).get("override_pins", {})
        valid = str(pins.get(admin_user, "")) == str(pin).strip()
        if not valid:
            st.error("Invalid admin override.")
            st.stop()
        st.session_state[f"override_ok_{s_norm}"] = True
        st.session_state[f"override_admin_{s_norm}"] = admin_user
    return st.session_state.get(f"override_ok_{s_norm}", False)

# =============================================================================
# TABS
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
    with st.form("register_device", clear_on_submit=True):
        r1c1, r1c2, r1c3 = st.columns(3)
        with r1c1:
            serial = st.text_input("Serial Number *")
        with r1c2:
            current_user = st.text_input("Current user")
        with r1c3:
            device = st.text_input("Device Type *")

        r2c1, r2c2 = st.columns(2)
        with r2c1:
            address = st.text_input("Address")
        with r2c2:
            active = st.selectbox("Active", ["Active", "Inactive", "Onboarding", "Resigned"])  # why: status consistency

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
            teams = st.selectbox("Microsoft Teams", ["— Select —", "Yes", "No", "Requested"])  # why: standardize
        with r4c3:
            mobile = st.text_input("Mobile Number")

        submitted = st.form_submit_button("Save Employee", type="primary")

    if submitted:
        if not emp_name.strip():
            st.error("Name is required.")
            return
        if emp_id.strip() and not emp_df.empty and emp_id.strip() in emp_df["Employee ID"].astype(str).values:
            st.error(f"Employee ID '{emp_id}' already exists.")
            return

        row = {
            # Store name under both columns for compatibility with downstream views/reports
            "New Employeer": emp_name.strip(),
            "Name": emp_name.strip(),
            "Employee ID": emp_id.strip() if emp_id.strip() else next_id_suggestion,
            "New Signature": new_sig if new_sig != "— Select —" else "",
            "Address": address.strip(),
