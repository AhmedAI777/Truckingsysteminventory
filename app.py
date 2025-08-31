# app.py — Tracking Inventory Management System
# Requirements:
#   pip install streamlit gspread gspread-dataframe extra-streamlit-components pandas \
#               google-auth google-api-python-client streamlit-pdf-viewer requests PyPDF2

import os, re, io, json, hmac, time, base64, hashlib
from datetime import datetime, timedelta
from typing import Tuple

import pandas as pd
import requests
import streamlit as st

st.set_page_config(page_title="Tracking Inventory Management System", layout="wide")

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
from googleapiclient.http import MediaIoBaseUpload, MediaIoBaseDownload
from googleapiclient.errors import HttpError

# PDF helpers
from PyPDF2 import PdfReader, PdfWriter
from PyPDF2.generic import NameObject, DictionaryObject, BooleanObject, ArrayObject

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
DEVICE_CATALOG_WS    = st.secrets.get("sheets", {}).get("catalog_ws", "truckingsysteminventory")

# Standard device columns
INVENTORY_COLS = [
    "Serial Number","Device Type","Brand","Model","CPU",
    "Hard Drive 1","Hard Drive 2","Memory","GPU","Screen Size",
    "Current user","Previous User","TO",
    "Department","Email Address","Contact Number","Location","Office",
    "Notes","Date issued","Registered by"
]
CATALOG_COLS = [
    "Serial Number","Device Type","Brand","Model","CPU",
    "Hard Drive 1","Hard Drive 2","Memory","GPU","Screen Size",
]
LOG_COLS = ["Device Type","Serial Number","From owner","To owner","Date issued","Registered by"]
EMPLOYEE_CANON_COLS = [
    "New Employeer","Employee ID","New Signature","Name","Address",
    "Active","Position","Department","Location (KSA)",
    "Project","Microsoft Teams","Mobile Number","Email"
]
APPROVAL_META_COLS = [
    "Approval Status","Approval PDF","Approval File ID",
    "Submitted by","Submitted at","Approver","Decision at"
]
PENDING_DEVICE_COLS   = INVENTORY_COLS + APPROVAL_META_COLS
PENDING_TRANSFER_COLS = LOG_COLS + APPROVAL_META_COLS

UNASSIGNED_LABEL = "Unassigned (Stock)"

ICT_TEMPLATE_FILE_ID = st.secrets.get("drive", {}).get("template_file_id", "")
TRANSFER_TEMPLATE_FILE_ID = st.secrets.get("drive", {}).get("transfer_template_file_id", ICT_TEMPLATE_FILE_ID)

def _ict_filename(serial: str) -> str:
    seq = _next_sequence("REG")
    return f"HO-JED-REG-{re.sub(r'[^A-Z0-9]', '', serial.upper())}-{seq}-{datetime.now().strftime('%Y%m%d')}.pdf"

def _transfer_filename(serial: str) -> str:
    seq = _next_sequence("TRF")
    return f"HO-JED-TRF-{re.sub(r'[^A-Z0-9]', '', serial.upper())}-{seq}-{datetime.now().strftime('%Y%m%d')}.pdf"

COOKIE_MGR = stx.CookieManager(key="ac_cookie_mgr")
for k in ("reg_pdf_ref", "transfer_pdf_ref"): ss.setdefault(k, None)

# =============================================================================
# AUTH
# =============================================================================
def _load_users_from_secrets():
    users_cfg = st.secrets.get("auth", {}).get("users", [])
    return {u["username"]: {"password": u.get("password", ""), "role": u.get("role", "Staff")} for u in users_cfg}
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
    iat = int(time.time()); exp = iat + SESSION_TTL_SECONDS
    payload = {"u": username, "r": role, "iat": iat, "exp": exp, "v": 1}
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    token = base64.urlsafe_b64encode(raw).decode() + "." + _sign(raw)
    COOKIE_MGR.set(COOKIE_NAME, token, expires_at=datetime.utcnow() + timedelta(seconds=SESSION_TTL_SECONDS))

def _read_cookie():
    token = COOKIE_MGR.get(COOKIE_NAME)
    if not token: return None
    try:
        data_b64, sig = token.split(".", 1)
        raw = base64.urlsafe_b64decode(data_b64.encode())
        if not _verify_sig(sig, raw):
            COOKIE_MGR.delete(COOKIE_NAME); return None
        payload = json.loads(raw.decode())
        if int(payload.get("exp", 0)) < time.time():
            COOKIE_MGR.delete(COOKIE_NAME); return None
        return payload
    except Exception:
        COOKIE_MGR.delete(COOKIE_NAME); return None

def do_login(username: str, role: str):
    st.session_state.authenticated = True
    st.session_state.username = username
    st.session_state.role = role
    st.session_state.just_logged_out = False
    _issue_session_cookie(username, role)
    st.rerun()

def do_logout():
    try: COOKIE_MGR.delete(COOKIE_NAME)
    except: pass
    for k in ["authenticated", "role", "username"]: st.session_state.pop(k, None)
    st.session_state.just_logged_out = True
    st.rerun()

if "cookie_bootstrapped" not in st.session_state:
    st.session_state.cookie_bootstrapped = True
    _ = COOKIE_MGR.get_all()
    st.rerun()

# =============================================================================
# GOOGLE SHEETS & DRIVE
# =============================================================================
SCOPES = ["https://www.googleapis.com/auth/spreadsheets","https://www.googleapis.com/auth/drive"]
OAUTH_SCOPES = ["https://www.googleapis.com/auth/drive.file"]
ALLOW_OAUTH_FALLBACK = st.secrets.get("drive", {}).get("allow_oauth_fallback", True)

def _load_sa_info() -> dict:
    raw = st.secrets.get("gcp_service_account", {})
    sa: dict = dict(raw) if isinstance(raw, dict) else json.loads(raw or "{}")
    pk = sa.get("private_key", "")
    if isinstance(pk, str) and "\\n" in pk: sa["private_key"] = pk.replace("\\n", "\n")
    return sa

@st.cache_resource
def _get_creds(): return Credentials.from_service_account_info(_load_sa_info(), scopes=SCOPES)
@st.cache_resource
def _get_gc(): return gspread.authorize(_get_creds())
@st.cache_resource
def _get_drive(): return build("drive", "v3", credentials=_get_creds())

def get_sh():
    gc = _get_gc(); url = st.secrets.get("sheets", {}).get("url", SHEET_URL_DEFAULT)
    return gc.open_by_url(url)

def _drive_make_public(file_id: str, drive_client=None):
    try:
        cli = drive_client or _get_drive()
        cli.permissions().create(fileId=file_id, body={"role": "reader", "type": "anyone"}, fields="id").execute()
    except: pass

def _drive_download_bytes(file_id: str) -> bytes:
    buf = io.BytesIO(); req = _get_drive().files().get_media(fileId=file_id); MediaIoBaseDownload(buf, req).next_chunk()
    buf.seek(0); return buf.read()

# =============================================================================
# SHEETS HELPERS
# =============================================================================
def reorder_columns(df: pd.DataFrame, desired: list[str]) -> pd.DataFrame:
    for c in desired:
        if c not in df.columns: df[c] = ""
    return df[desired + [c for c in df.columns if c not in desired]]

def get_or_create_ws(title, rows=500, cols=80):
    sh = get_sh()
    try: return sh.worksheet(title)
    except gspread.exceptions.WorksheetNotFound: return sh.add_worksheet(title=title, rows=rows, cols=cols)

def read_worksheet(ws_title):
    ws = get_or_create_ws(ws_title)
    df = pd.DataFrame(ws.get_all_records())
    if ws_title == INVENTORY_WS: return reorder_columns(df, INVENTORY_COLS)
    if ws_title == TRANSFERLOG_WS: return reorder_columns(df, LOG_COLS)
    if ws_title == EMPLOYEE_WS: return reorder_columns(df, EMPLOYEE_CANON_COLS)
    if ws_title == PENDING_DEVICE_WS: return reorder_columns(df, PENDING_DEVICE_COLS)
    if ws_title == PENDING_TRANSFER_WS: return reorder_columns(df, PENDING_TRANSFER_COLS)
    return df

def write_worksheet(ws_title, df):
    ws = get_or_create_ws(ws_title)
    ws.clear(); set_with_dataframe(ws, df)

def append_to_worksheet(ws_title, new_data):
    ws = get_or_create_ws(ws_title)
    df_existing = pd.DataFrame(ws.get_all_records())
    df_combined = pd.concat([df_existing, new_data], ignore_index=True)
    set_with_dataframe(ws, df_combined)

# =============================================================================
# COUNTERS
# =============================================================================
COUNTERS_WS = "counters"
def _get_counter_ws():
    sh = get_sh()
    try: return sh.worksheet(COUNTERS_WS)
    except gspread.exceptions.WorksheetNotFound:
        ws = sh.add_worksheet(title=COUNTERS_WS, rows=10, cols=3)
        ws.update([["Type", "LastUsed"], ["REG", 0], ["TRF", 0]])
        return ws

def _next_sequence(seq_type: str) -> str:
    ws = _get_counter_ws(); df = pd.DataFrame(ws.get_all_records())
    if df.empty: df = pd.DataFrame([{"Type": "REG", "LastUsed": 0}, {"Type": "TRF", "LastUsed": 0}])
    if seq_type not in df["Type"].values: df = pd.concat([df, pd.DataFrame([{"Type": seq_type, "LastUsed": 0}])])
    idx = df.index[df["Type"] == seq_type][0]
    df.at[idx, "LastUsed"] = int(df.at[idx, "LastUsed"]) + 1
    set_with_dataframe(ws, df)
    return f"{int(df.at[idx,'LastUsed']):04d}"

# =============================================================================
# SMALL HELPERS
# =============================================================================
def normalize_serial(sn: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", str(sn).upper().strip()) if sn else ""

def unique_nonempty(df: pd.DataFrame, col: str) -> list[str]:
    if df is None or df.empty or col not in df.columns: return []
    vals = [str(x).strip() for x in df[col].dropna().astype(str).tolist()]
    return sorted({v for v in vals if v})

# =============================================================================
# PDF FILLING + EMPLOYEE HELPERS + BUILD VALUES
# =============================================================================
# (Insert all functions from Chunk 2 here: _registration_field_map, fill_pdf_form,
#  _find_emp_row_by_name, _get_emp_value, _owner_changed, build_registration_values,
#  build_transfer_values — unchanged from earlier.)

# =============================================================================
# UPLOAD TO GOOGLE DRIVE
# =============================================================================
def upload_pdf_and_link(uploaded_file, *, prefix: str) -> Tuple[str, str]:
    """Upload a signed PDF to Drive and return (link, file_id)."""
    if uploaded_file is None:
        st.error("No file selected.")
        return "", ""
    mime = getattr(uploaded_file, "type", "") or ""
    name = getattr(uploaded_file, "name", "file.pdf")
    try: data = uploaded_file.getvalue()
    except Exception as e: st.error(f"Failed reading file: {e}"); return "", ""
    if not data: st.error("Uploaded file is empty."); return "", ""
    if data[:4] != b"%PDF": st.warning("File may not be a valid PDF.")
    fname = f"{prefix}_{int(time.time())}.pdf"
    folder_id = st.secrets.get("drive", {}).get("approvals", "")
    metadata = {"name": fname}
    if folder_id: metadata["parents"] = [folder_id]
    media = MediaIoBaseUpload(io.BytesIO(data), mimetype="application/pdf", resumable=False)
    drive_cli = _get_drive()
    try:
        file = drive_cli.files().create(body=metadata, media_body=media,
                                        fields="id, webViewLink", supportsAllDrives=True).execute()
    except HttpError as e:
        st.error(f"Drive upload failed: {e}"); return "", ""
    try: _drive_make_public(file["id"], drive_cli)
    except: pass
    return file.get("webViewLink", ""), file.get("id", "")

# =============================================================================
# TAB FUNCTIONS (Employee, Inventory, Register, Transfer, Approvals, Export)
# =============================================================================
# (Insert all functions from Chunk 3 here: render_header, employee_register_tab,
#  employees_view_tab, inventory_tab, history_tab, register_device_tab,
#  transfer_tab, approvals_tab, export_tab, run_app, etc.)

# =============================================================================
# TAB FUNCTIONS
# =============================================================================
def render_header():
    c_title, c_user = st.columns([7, 3])
    with c_title:
        st.markdown(f"### {APP_TITLE}")
        st.caption(SUBTITLE)
    with c_user:
        username = st.session_state.get("username", "—")
        role = st.session_state.get("role", "—")
        st.markdown(f"**User:** {username} &nbsp;&nbsp;&nbsp; **Role:** {role}")
        if st.session_state.get("authenticated") and st.button("Logout"):
            do_logout()
    st.markdown("---")

def employee_register_tab():
    st.subheader("🧑‍💼 Register New Employee (mainlists)")
    emp_df = read_worksheet(EMPLOYEE_WS)
    next_id = str(len(emp_df) + 1) if not emp_df.empty else "1"
    with st.form("register_employee", clear_on_submit=True):
        emp_name = st.text_input("New Employeer *")
        emp_id   = st.text_input("Employee ID", help=f"Suggested: {next_id}")
        submitted = st.form_submit_button("Save Employee", type="primary")
    if submitted and emp_name.strip():
        row = {"New Employeer": emp_name.strip(), "Name": emp_name.strip(), "Employee ID": emp_id or next_id}
        new_df = pd.concat([emp_df, pd.DataFrame([row])], ignore_index=True)
        new_df = reorder_columns(new_df, EMPLOYEE_CANON_COLS)
        write_worksheet(EMPLOYEE_WS, new_df)
        st.success("✅ Employee saved.")

def employees_view_tab():
    st.subheader("📇 Employees")
    df = read_worksheet(EMPLOYEE_WS)
    st.dataframe(df, use_container_width=True, hide_index=True)

def inventory_tab():
    st.subheader("📋 Inventory")
    df = read_worksheet(INVENTORY_WS)
    st.dataframe(df, use_container_width=True, hide_index=True)

def history_tab():
    st.subheader("📜 Transfer Log")
    df = read_worksheet(TRANSFERLOG_WS)
    st.dataframe(df, use_container_width=True, hide_index=True)

# register_device_tab()  ← already defined above
# transfer_tab()         ← already defined above

def approvals_tab():
    st.subheader("✅ Approvals (Admin)")
    if st.session_state.get("role") != "Admin":
        st.info("Only Admins can view approvals.")
        return
    pending_dev = read_worksheet(PENDING_DEVICE_WS)
    st.write(pending_dev)

def export_tab():
    st.subheader("⬇️ Export")
    inv = read_worksheet(INVENTORY_WS)
    log = read_worksheet(TRANSFERLOG_WS)
    emp = read_worksheet(EMPLOYEE_WS)
    st.download_button("Inventory CSV", inv.to_csv(index=False).encode(), "inventory.csv")
    st.download_button("Transfer Log CSV", log.to_csv(index=False).encode(), "transfer_log.csv")
    st.download_button("Employees CSV", emp.to_csv(index=False).encode(), "employees.csv")

# =============================================================================
# RUN APP
# =============================================================================
def run_app():
    render_header()
    if st.session_state.role == "Admin":
        tabs = st.tabs([
            "🧑‍💼 Employee Register","📇 View Employees","📝 Register Device",
            "📋 View Inventory","🔁 Transfer Device","📜 Transfer Log","✅ Approvals","⬇️ Export"
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
        tabs = st.tabs(["📝 Register Device","🔁 Transfer Device","📋 View Inventory","📜 Transfer Log"])
        with tabs[0]: register_device_tab()
        with tabs[1]: transfer_tab()
        with tabs[2]: inventory_tab()
        with tabs[3]: history_tab()


# =============================================================================
# ENTRYPOINT
# =============================================================================
if "authenticated" not in st.session_state: st.session_state.authenticated = False
if "just_logged_out" not in st.session_state: st.session_state.just_logged_out = False
if not st.session_state.authenticated and not st.session_state.get("just_logged_out"):
    payload = _read_cookie()
    if payload:
        st.session_state.authenticated = True
        st.session_state.username = payload["u"]
        st.session_state.role = payload.get("r", "")

if st.session_state.authenticated:
    run_app()
else:
    st.subheader("🔐 Sign In")
    username = st.text_input("Username"); password = st.text_input("Password", type="password")
    if st.button("Login", type="primary"):
        user = USERS.get(username)
        if user and _verify_password(password, user["password"]):
            do_login(username, user.get("role", "Staff"))
        else:
            st.error("❌ Invalid username or password.")
