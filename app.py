# Requirements (requirements.txt)
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

# Google Drive API for PDF storage (optional but recommended)
try:
    from googleapiclient.discovery import build
    from googleapiclient.http import MediaIoBaseUpload
    HAS_DRIVE = True
except Exception:
    HAS_DRIVE = False

# =============================================================================
# CONFIG / CONSTANTS
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

# Your spreadsheet URL (can be overridden in secrets)
SHEET_URL_DEFAULT = "https://docs.google.com/spreadsheets/d/1SHp6gOW4ltsyOT41rwo85e_LELrHkwSwKN33K6XNHFI/edit"

# Worksheet titles
INVENTORY_WS           = "truckinventory"
TRANSFERLOG_WS         = "transfer_log"
EMPLOYEE_WS            = "mainlists"
PENDING_DEVICES_WS     = "pending_devices"   # device registrations awaiting admin approval (kept)
PENDING_TRANSFERS_WS   = "pending_transfers" # NEW: staff-submitted transfers awaiting admin approval

# Debug flag (optional): set [debug].show = true in secrets to expose diagnostics
DEBUG_SHOW = bool(st.secrets.get("debug", {}).get("show", False))

# Inventory columns (map legacy 'USER' to 'Current user')
INVENTORY_COLS = [
    "Serial Number","Device Type","Brand","Model","CPU",
    "Hard Drive 1","Hard Drive 2","Memory","GPU","Screen Size",
    "Current user","Previous User","TO",
    "Department","Email Address","Contact Number","Location","Office",
    "Notes","Date issued","Registered by"
]

# Transfer log columns (with form URL)
LOG_COLS = [
    "Device Type","Serial Number","From owner","To owner",
    "Date issued","Registered by","Form URL"
]

# Employees columns
EMPLOYEE_CANON_COLS = [
    "Employee ID","New Signature","Name","Address",
    "Active","Position","Department","Location (KSA)",
    "Project","Microsoft Teams","Mobile Number"
]

# Pending device registration columns
PENDING_DEVICE_COLS = INVENTORY_COLS + [
    "Submitted by","Submitted at","Status","Approver","Approved at","Decision Note"
]

# Pending transfer columns (NEW)
PENDING_TRANSFER_COLS = [
    "Serial Number","Device Type","From owner","To owner",
    "Submitted by","Submitted at","PDF URL",
    "Status","Approver","Approved at","Decision Note"
]

# Header normalization maps
HEADER_SYNONYMS = {
    # drop
    "newemployee": None,
    "newemployeer": None,
    "email": None,
    "emailaddress": None,
    "aplus": None,
    # normalize
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
# HELPERS
# =============================================================================

def _norm_header(h: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (h or "").strip().lower())

def _norm_ws_title(t: str) -> str:
    return re.sub(r"\s+", "", (t or "").strip().lower())

def normalize_serial(s: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", (s or "").strip().upper())

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
# BRANDING CSS (optional)
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
# GOOGLE SHEETS CLIENT
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
    return gc.open_by_url(url)


def _find_or_add_ws(sh, title, rows=500, cols=80):
    t_norm = _norm_ws_title(title)
    for ws in sh.worksheets():
        if _norm_ws_title(ws.title) == t_norm:
            return ws
    try:
        return sh.worksheet(title)
    except gspread.exceptions.WorksheetNotFound:
        return sh.add_worksheet(title=title, rows=rows, cols=cols)


def get_or_create_ws(title, rows=500, cols=80):
    return _find_or_add_ws(get_sh(), title, rows, cols)


def get_employee_ws() -> gspread.Worksheet:
    sh = get_sh()
    preferred = [EMPLOYEE_WS, "Employees", "Employee List", "Main Lists", "Mainlists"]
    for cand in preferred:
        t_norm = _norm_ws_title(cand)
        for ws in sh.worksheets():
            if _norm_ws_title(ws.title) == t_norm:
                return ws
    return sh.add_worksheet(title=EMPLOYEE_WS, rows=500, cols=50)

# =============================================================================
# DATAFRAME CLEANING & IO
# =============================================================================

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

@st.cache_data(ttl=30, show_spinner=False)
def _read_worksheet_cached(ws_title: str) -> pd.DataFrame:
    if ws_title == EMPLOYEE_WS:
        return _read_employee_df(get_employee_ws())

    ws = get_or_create_ws(ws_title)
    data = ws.get_all_records()
    df = pd.DataFrame(data)
    if ws_title == INVENTORY_WS:
        df = canon_inventory_columns(df)
        return reorder_columns(df, INVENTORY_COLS)
    if ws_title == TRANSFERLOG_WS:
        return reorder_columns(df, LOG_COLS)
    if ws_title == PENDING_DEVICES_WS:
        return reorder_columns(df, PENDING_DEVICE_COLS)
    if ws_title == PENDING_TRANSFERS_WS:
        return reorder_columns(df, PENDING_TRANSFER_COLS)
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
        if ws_title == PENDING_DEVICES_WS:
            return pd.DataFrame(columns=PENDING_DEVICE_COLS)
        if ws_title == PENDING_TRANSFERS_WS:
            return pd.DataFrame(columns=PENDING_TRANSFER_COLS)
        return pd.DataFrame()


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
        if ws_title == PENDING_DEVICES_WS:
            df = reorder_columns(df, PENDING_DEVICE_COLS)
        if ws_title == PENDING_TRANSFERS_WS:
            df = reorder_columns(df, PENDING_TRANSFER_COLS)
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
    if ws_title == PENDING_DEVICES_WS:
        df_combined = reorder_columns(df_combined, PENDING_DEVICE_COLS)
    if ws_title == PENDING_TRANSFERS_WS:
        df_combined = reorder_columns(df_combined, PENDING_TRANSFER_COLS)
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
# UI UTIL
# =============================================================================

def _refresh_button(key: str):
    col1, col2 = st.columns([1,8])
    with col1:
        if st.button("🔄 Refresh data", key=f"refresh_btn_{key}"):
            st.cache_data.clear()
            st.rerun()

# =============================================================================
# TABS – EMPLOYEES
# =============================================================================

def employees_view_tab():
    st.subheader("📇 Main Employees (mainlists)")
    _refresh_button("employees")
    if DEBUG_SHOW:
        with st.expander("🔍 Debug: worksheet list"):
            try:
                sh = get_sh()
                st.write([ws.title for ws in sh.worksheets()])
                st.write("Sheet URL:", _get_sheet_url())
            except Exception as e:
                st.error(str(e))
    df = read_worksheet(EMPLOYEE_WS)
    if df.empty:
        st.info("No employees found in 'mainlists'.")
    else:
        st.dataframe(df[EMPLOYEE_CANON_COLS], use_container_width=True, hide_index=True)

# (keep your employee_register_tab from previous version if needed)

# =============================================================================
# TABS – INVENTORY
# =============================================================================

def inventory_tab():
    st.subheader("📋 Main Inventory")
    _refresh_button("inventory")
    df = read_worksheet(INVENTORY_WS)
    if df.empty:
        st.warning("Inventory is empty.")
    else:
        st.dataframe(df, use_container_width=True)

# =============================================================================
# TABS – TRANSFERS (NEW WORKFLOW)
# =============================================================================

def transfer_tab():
    """Staff can submit a transfer with a signed PDF; Admins approve and apply it."""
    st.subheader("🔁 Transfer Device (Admin approval with PDF)")

    inv_df = read_worksheet(INVENTORY_WS)
    if inv_df.empty:
        st.warning("Inventory is empty.")
        return

    # STAFF SUBMISSION UI ------------------------------------------------------
    if st.session_state.get("role") == "Staff":
        st.markdown("#### Submit Transfer for Approval")
        _refresh_button("transfer_staff")

        serials = sorted(inv_df["Serial Number"].dropna().astype(str).unique().tolist())
        serial = st.selectbox("Serial Number", ["— Select —"] + serials, key="t_sn")
        if serial != "— Select —":
            row = inv_df[inv_df["Serial Number"].astype(str) == serial].iloc[0]
            current_owner = str(row.get("Current user", ""))
            st.info(f"Current owner: **{current_owner or '(blank)'}**")
        else:
            current_owner = ""

        candidate_users = sorted([u for u in inv_df["Current user"].astype(str).tolist() if u.strip()])
        to_owner_choice = st.selectbox("New Owner", ["— Select —"] + candidate_users + ["Type a new name…"], key="t_to_owner_choice")
        if to_owner_choice == "Type a new name…":
            to_owner = st.text_input("Enter new owner name", key="t_to_owner_custom")
        else:
            to_owner = "" if to_owner_choice == "— Select —" else to_owner_choice

        uploaded_pdf = st.file_uploader(
            "Upload signed approval form (PDF, ≤ 2 MB) *",
            type=["pdf"], accept_multiple_files=False, key="t_pdf_staff"
        )

        def _pdf_ok(f):
            if not f:
                return False, "Please upload the signed approval form (PDF)."
            if getattr(f, "type", "") != "application/pdf":
                return False, "Only PDF files are allowed."
            size = getattr(f, "size", None)
            if size is None:
                f.seek(0, os.SEEK_END); size = f.tell(); f.seek(0)
            if size <= 0 or size > 2 * 1024 * 1024:
                return False, "PDF must be between 1 byte and 2 MB."
            return True, ""

        ok_file, err = _pdf_ok(uploaded_pdf)
        if not ok_file and uploaded_pdf is not None:
            st.error(err)

        submit_btn = st.button(
            "📨 Submit for Admin Approval",
            type="primary",
            disabled=not (serial != "— Select —" and to_owner.strip() and ok_file),
            key="t_submit"
        )

        if submit_btn:
            try:
                pdf_bytes = uploaded_pdf.getvalue()
                pdf_url = upload_pdf_to_drive(
                    f"transfer_{serial}_{int(time.time())}.pdf", pdf_bytes
                )
            except Exception as e:
                st.error(f"Could not store PDF form. Ask admin to set [drive].folder_id in secrets. Detail: {e}")
                return

            payload = {
                "Serial Number": serial,
                "Device Type": str(row.get("Device Type", "")) if serial != "— Select —" else "",
                "From owner": current_owner,
                "To owner": to_owner.strip(),
                "Submitted by": st.session_state.get("username", ""),
                "Submitted at": datetime.now().strftime(DATE_FMT),
                "PDF URL": pdf_url,
                "Status": "Pending",
                "Approver": "",
                "Approved at": "",
                "Decision Note": "",
            }
            append_to_worksheet(PENDING_TRANSFERS_WS, pd.DataFrame([payload]))
            st.success("✅ Transfer submitted. Admin will review and approve.")

    # ADMIN REVIEW & DIRECT TRANSFER ------------------------------------------
    else:
        st.markdown("#### Admin – Pending Transfer Approvals")
        _refresh_button("transfer_admin")
        pend = read_worksheet(PENDING_TRANSFERS_WS)
        if pend.empty or not (pend["Status"] == "Pending").any():
            st.info("No pending transfers.")
        else:
            for ridx, row in pend[pend["Status"] == "Pending"].reset_index().iterrows():
                label = f"SN {row['Serial Number']} – {row['From owner']} → {row['To owner']}"
                with st.expander(label):
                    st.write({
                        "Serial Number": row["Serial Number"],
                        "From": row["From owner"],
                        "To": row["To owner"],
                        "Submitted by": row["Submitted by"],
                        "Submitted at": row["Submitted at"],
                    })
                    if row.get("PDF URL"):
                        st.link_button("Open PDF form", row["PDF URL"], key=f"open_pdf_{row['Serial Number']}_{ridx}")
                    c1, c2, c3 = st.columns([1,1,3])
                    with c3:
                        note = st.text_input("Decision note", key=f"tr_note_{row['Serial Number']}_{ridx}")
                    real_idx = row["index"]

                    def _apply_transfer(inv_df_local: pd.DataFrame, serial: str, to_owner: str):
                        match = inv_df_local[inv_df_local["Serial Number"].astype(str) == str(serial)]
                        if match.empty:
                            st.error("Serial not found in inventory.")
                            return False
                        idx = match.index[0]
                        prev_user = str(inv_df_local.loc[idx, "Current user"] or "")
                        now_str   = datetime.now().strftime(DATE_FMT)
                        actor     = st.session_state.get("username", "")
                        inv_df_local.loc[idx, "Previous User"] = prev_user
                        inv_df_local.loc[idx, "Current user"]  = to_owner
                        inv_df_local.loc[idx, "TO"]            = to_owner
                        inv_df_local.loc[idx, "Date issued"]   = now_str
                        inv_df_local.loc[idx, "Registered by"] = actor
                        write_worksheet(INVENTORY_WS, reorder_columns(inv_df_local, INVENTORY_COLS))
                        log_row = {
                            "Device Type": inv_df_local.loc[idx, "Device Type"],
                            "Serial Number": serial,
                            "From owner": prev_user,
                            "To owner": to_owner,
                            "Date issued": now_str,
                            "Registered by": actor,
                            "Form URL": row.get("PDF URL", ""),
                        }
                        append_to_worksheet(TRANSFERLOG_WS, pd.DataFrame([log_row]))
                        return True

                    with c1:
                        if st.button("✅ Approve", key=f"tr_approve_{row['Serial Number']}_{ridx}"):
                            inv_fresh = read_worksheet(INVENTORY_WS)
                            ok = _apply_transfer(inv_fresh, row["Serial Number"], row["To owner"])
                            if ok:
                                pend.at[real_idx, "Status"] = "Approved"
                                pend.at[real_idx, "Approver"] = st.session_state.get("username", "")
                                pend.at[real_idx, "Approved at"] = datetime.now().strftime(DATE_FMT)
                                pend.at[real_idx, "Decision Note"] = note
                                write_worksheet(PENDING_TRANSFERS_WS, pend)
                                st.success("Transfer approved and applied to inventory.")
                                st.rerun()
                    with c2:
                        if st.button("❌ Reject", key=f"tr_reject_{row['Serial Number']}_{ridx}"):
                            pend.at[real_idx, "Status"] = "Rejected"
                            pend.at[real_idx, "Approver"] = st.session_state.get("username", "")
                            pend.at[real_idx, "Approved at"] = datetime.now().strftime(DATE_FMT)
                            pend.at[real_idx, "Decision Note"] = note
                            write_worksheet(PENDING_TRANSFERS_WS, pend)
                            st.warning("Transfer rejected.")
                            st.rerun()

        st.divider()
        st.markdown("#### Admin – Direct Transfer (with PDF)")
        serials = sorted(inv_df["Serial Number"].dropna().astype(str).unique().tolist())
        serial = st.selectbox("Serial Number", ["— Select —"] + serials, key="t_sn_admin")
        if serial != "— Select —":
            match = inv_df[inv_df["Serial Number"].astype(str) == serial]
            if not match.empty:
                st.caption(f"Current owner: {match.iloc[0]['Current user']}")
        candidate_users = sorted([u for u in inv_df["Current user"].astype(str).tolist() if u.strip()])
        to_owner_choice = st.selectbox("New Owner", ["— Select —"] + candidate_users + ["Type a new name…"], key="t_to_owner_choice_admin")
        if to_owner_choice == "Type a new name…":
            to_owner = st.text_input("Enter new owner name", key="t_to_owner_custom_admin")
        else:
            to_owner = "" if to_owner_choice == "— Select —" else to_owner_choice

        pdf_admin = st.file_uploader(
            "Upload signed approval form (PDF, ≤ 2 MB) *",
            type=["pdf"], accept_multiple_files=False, key="t_pdf_admin"
        )
        ok_file = pdf_admin is not None
        if ok_file and getattr(pdf_admin, "type", "") != "application/pdf":
            st.error("Only PDF files are allowed.")
            ok_file = False

        btn_apply = st.button(
            "⚡ Apply Transfer Now (Admin)",
            type="primary",
            disabled=not (serial != "— Select —" and to_owner.strip() and ok_file),
            key="t_apply_admin"
        )
        if btn_apply:
            try:
                pdf_bytes = pdf_admin.getvalue()
                pdf_url = upload_pdf_to_drive(f"transfer_{serial}_{int(time.time())}.pdf", pdf_bytes)
            except Exception as e:
                st.error(f"Could not store PDF form. Set [drive].folder_id in secrets. Detail: {e}")
                return
            # apply immediately
            match = inv_df[inv_df["Serial Number"].astype(str) == serial]
            if match.empty:
                st.error("Serial not found.")
                return
            idx = match.index[0]
            prev_user = str(inv_df.loc[idx, "Current user"] or "")
            now_str   = datetime.now().strftime(DATE_FMT)
            actor     = st.session_state.get("username", "")
            inv_df.loc[idx, "Previous User"] = prev_user
            inv_df.loc[idx, "Current user"]  = to_owner
            inv_df.loc[idx, "TO"]            = to_owner
            inv_df.loc[idx, "Date issued"]   = now_str
            inv_df.loc[idx, "Registered by"] = actor
            write_worksheet(INVENTORY_WS, reorder_columns(inv_df, INVENTORY_COLS))
            log_row = {
                "Device Type": inv_df.loc[idx, "Device Type"],
                "Serial Number": serial,
                "From owner": prev_user,
                "To owner": to_owner,
                "Date issued": now_str,
                "Registered by": actor,
                "Form URL": pdf_url,
            }
            append_to_worksheet(TRANSFERLOG_WS, pd.DataFrame([log_row]))
            st.success("✅ Transfer applied.")

# =============================================================================
# TABS – HISTORY & EXPORT
# =============================================================================

def history_tab():
    st.subheader("📜 History Transfer")
    _refresh_button("history")
    df = read_worksheet(TRANSFERLOG_WS)
    if df.empty:
        st.info("No transfer history found.")
    else:
        st.dataframe(df, use_container_width=True, hide_index=True)


def export_tab():
    st.subheader("⬇️ Export")
    _refresh_button("export")
    inv  = read_worksheet(INVENTORY_WS)
    log  = read_worksheet(TRANSFERLOG_WS)
    emp  = read_worksheet(EMPLOYEE_WS)
    pend_dev = read_worksheet(PENDING_DEVICES_WS)
    pend_tr  = read_worksheet(PENDING_TRANSFERS_WS)

    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        st.download_button("Inventory CSV", inv.to_csv(index=False).encode("utf-8"), "inventory.csv", "text/csv")
    with c2:
        st.download_button("Transfer Log CSV", log.to_csv(index=False).encode("utf-8"), "transfer_log.csv", "text/csv")
    with c3:
        st.download_button("Employees CSV", emp.to_csv(index=False).encode("utf-8"), "employees.csv", "text/csv")
    with c4:
        st.download_button("Pending Devices CSV", pend_dev.to_csv(index=False).encode("utf-8"), "pending_devices.csv", "text/csv")
    with c5:
        st.download_button("Pending Transfers CSV", pend_tr.to_csv(index=False).encode("utf-8"), "pending_transfers.csv", "text/csv")

# =============================================================================
# MAIN
# =============================================================================

def run_app():
    render_header()
    hide_table_toolbar_for_non_admin()

    if st.session_state.role == "Admin":
        tabs = st.tabs([
            "🧾 Main Employees",
            "📋 Main Inventory",
            "🔁 Transfers",
            "📜 History Transfer",
            "⬇️ Export",
        ])
        with tabs[0]: employees_view_tab()
        with tabs[1]: inventory_tab()
        with tabs[2]: transfer_tab()
        with tabs[3]: history_tab()
        with tabs[4]: export_tab()
    else:
        tabs = st.tabs(["📋 Main Inventory", "🔁 Transfer (Request)", "📜 History Transfer"])
        with tabs[0]: inventory_tab()
        with tabs[1]: transfer_tab()
        with tabs[2]: history_tab()

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
    if DEBUG_SHOW:
        with st.expander("🔧 Debug – secrets checks"):
            st.write("Sheet URL:", _get_sheet_url())
            try:
                st.write("Service account:", st.secrets["gcp_service_account"].get("client_email"))
            except Exception:
                st.error("Missing gcp_service_account in secrets")
    st.subheader("Welcome")
    st.caption("Please log in to continue.")
    show_login()
