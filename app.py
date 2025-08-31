# app.py — Tracking Inventory Management System (Merged Version)
# Features:
# - Google Sheets via Service Account
# - Google Drive structured uploads (Head Office folder + subfolders)
# - Serial auto-generation for registrations (HO-JED-REG-…)
# - Counter system (REG, TRF)
# - Admin approval with inline PDF review

import os, re, io, json, hmac, time, base64, hashlib, glob
from datetime import datetime, timedelta

import pandas as pd
import requests
import streamlit as st
from streamlit import session_state as ss
import extra_streamlit_components as stx
from streamlit_pdf_viewer import pdf_viewer

import gspread
from gspread_dataframe import set_with_dataframe
from google.oauth2.service_account import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload
from googleapiclient.errors import HttpError
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials as UserCredentials

# =============================================================================
# CONFIG
# =============================================================================
APP_TITLE = "Tracking Inventory Management System"
SUBTITLE  = "Advanced Construction"
DATE_FMT  = "%Y-%m-%d %H:%M:%S"

SHEET_URL_DEFAULT = "https://docs.google.com/spreadsheets/d/.../edit"
ROOT_FOLDER_ID = st.secrets.get("drive", {}).get("root_folder_id", "1ZbvAklbOIAZp62EvmqQLZHWu6du8TjCd")

INVENTORY_WS       = "truckinventory"
TRANSFERLOG_WS     = "transfer_log"
EMPLOYEE_WS        = "mainlists"
PENDING_DEVICE_WS  = "pending_device_reg"
PENDING_TRANSFER_WS= "pending_transfers"
COUNTERS_WS        = "counters"

# Auth cookie/session
SESSION_TTL_DAYS = 30
SESSION_TTL_SECONDS = SESSION_TTL_DAYS * 24 * 60 * 60
COOKIE_NAME = "ac_auth_v2"
COOKIE_MGR = stx.CookieManager(key="ac_cookie_mgr")

# Pre-init PDF refs
for k in ("reg_pdf_ref", "transfer_pdf_ref"):
    if k not in ss: ss[k] = None

# =============================================================================
# GOOGLE API
# =============================================================================
SCOPES = ["https://www.googleapis.com/auth/spreadsheets", "https://www.googleapis.com/auth/drive"]

def _load_sa_info():
    raw = st.secrets.get("gcp_service_account", {})
    sa = dict(raw) if isinstance(raw, dict) else {}
    pk = sa.get("private_key", "")
    if "\\n" in str(pk): sa["private_key"] = pk.replace("\\n", "\n")
    return sa

@st.cache_resource
def _get_creds(): return Credentials.from_service_account_info(_load_sa_info(), scopes=SCOPES)
@st.cache_resource
def _get_gc(): return gspread.authorize(_get_creds())
@st.cache_resource
def _get_drive(): return build("drive", "v3", credentials=_get_creds())

def get_sh():
    gc = _get_gc()
    url = st.secrets.get("sheets", {}).get("url", SHEET_URL_DEFAULT)
    return gc.open_by_url(url)

# =============================================================================
# COUNTER SYSTEM
# =============================================================================
def get_next_counter(counter_type: str) -> int:
    ws = get_or_create_ws(COUNTERS_WS)
    df = pd.DataFrame(ws.get_all_records())
    if df.empty or counter_type not in df["Type"].values:
        df = pd.concat([df, pd.DataFrame([{"Type": counter_type, "LastUsed": 0}])], ignore_index=True)
    idx = df.index[df["Type"] == counter_type][0]
    last_used = int(df.loc[idx, "LastUsed"])
    next_val = last_used + 1
    df.loc[idx, "LastUsed"] = next_val
    ws.clear()
    set_with_dataframe(ws, df)
    return next_val

# =============================================================================
# DRIVE HELPERS
# =============================================================================
def ensure_drive_folder(parent_id: str, name: str, drive_cli=None) -> str:
    cli = drive_cli or _get_drive()
    q = f"'{parent_id}' in parents and mimeType='application/vnd.google-apps.folder' and name='{name}' and trashed=false"
    results = cli.files().list(q=q, fields="files(id)").execute()
    if results.get("files"):
        return results["files"][0]["id"]
    meta = {"name": name, "mimeType": "application/vnd.google-apps.folder", "parents": [parent_id]}
    folder = cli.files().create(body=meta, fields="id").execute()
    return folder["id"]

def upload_pdf_to_folder(data: bytes, filename: str, folder_id: str, drive_cli=None):
    cli = drive_cli or _get_drive()
    media = MediaIoBaseUpload(io.BytesIO(data), mimetype="application/pdf", resumable=False)
    meta = {"name": filename, "parents": [folder_id]}
    file = cli.files().create(body=meta, media_body=media, fields="id, webViewLink").execute()
    return file.get("webViewLink"), file.get("id")

# =============================================================================
# SERIAL GENERATION
# =============================================================================
def build_folder_name(office: str, location: str, action: str, serial: str, counter: int, date: datetime) -> str:
    office_code = office[:2].upper()
    loc_code = location[:3].upper()
    action_code = "REG" if action == "register" else "TRF"
    counter_str = str(counter).zfill(4)
    date_str = date.strftime("%Y%m%d")
    return f"{office_code}-{loc_code}-{action_code}-{serial}-{counter_str}-{date_str}"

# =============================================================================
# SHEETS HELPERS
# =============================================================================
def get_or_create_ws(title, rows=500, cols=80):
    sh = get_sh()
    try:
        return sh.worksheet(title)
    except gspread.exceptions.WorksheetNotFound:
        return sh.add_worksheet(title=title, rows=rows, cols=cols)

@st.cache_data(ttl=120)
def read_worksheet(ws_title: str) -> pd.DataFrame:
    ws = get_or_create_ws(ws_title)
    df = pd.DataFrame(ws.get_all_records())
    return df

def write_worksheet(ws_title: str, df: pd.DataFrame):
    ws = get_or_create_ws(ws_title)
    ws.clear()
    set_with_dataframe(ws, df)
    st.cache_data.clear()

def append_to_worksheet(ws_title: str, new_data: pd.DataFrame):
    ws = get_or_create_ws(ws_title)
    df_existing = pd.DataFrame(ws.get_all_records())
    df_combined = pd.concat([df_existing, new_data], ignore_index=True)
    set_with_dataframe(ws, df_combined)
    st.cache_data.clear()

# =============================================================================
# AUTH
# =============================================================================
def _load_users_from_secrets():
    users_cfg = st.secrets.get("auth", {}).get("users", [])
    users = {}
    for u in users_cfg:
        users[u["username"]] = {
            "password": u.get("password", ""), "role": u.get("role", "Staff")
        }
    return users

USERS = _load_users_from_secrets()

def _verify_password(raw: str, stored: str) -> bool:
    return hmac.compare_digest(str(stored), str(raw))

def _sign(raw: bytes, *, key: str | None = None) -> str:
    use = key or st.secrets.get("auth", {}).get("cookie_key", "")
    return hmac.new(use.encode(), raw, hashlib.sha256).hexdigest()

def _issue_session_cookie(username: str, role: str):
    iat = int(time.time())
    exp = iat + SESSION_TTL_SECONDS
    payload = {"u": username, "r": role, "iat": iat, "exp": exp, "v": 1}
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    token = base64.urlsafe_b64encode(raw).decode() + "." + _sign(raw)
    COOKIE_MGR.set(
        COOKIE_NAME, token,
        expires_at=(datetime.utcnow() + timedelta(seconds=SESSION_TTL_SECONDS)),
        secure=True,
    )

def _read_cookie():
    token = COOKIE_MGR.get(COOKIE_NAME)
    if not token: return None
    try:
        data_b64, sig = token.split(".", 1)
        raw = base64.urlsafe_b64decode(data_b64.encode())
        payload = json.loads(raw.decode())
        return payload if int(payload.get("exp", 0)) > int(time.time()) else None
    except Exception: return None

def do_login(username: str, role: str):
    st.session_state.authenticated = True
    st.session_state.username = username
    st.session_state.role = role
    _issue_session_cookie(username, role)
    st.rerun()

def do_logout():
    COOKIE_MGR.delete(COOKIE_NAME)
    for k in ["authenticated", "role", "username"]:
        st.session_state.pop(k, None)
    st.session_state.just_logged_out = True
    st.rerun()

# Try restore session from cookie
if "authenticated" not in st.session_state: st.session_state.authenticated = False
if "just_logged_out" not in st.session_state: st.session_state.just_logged_out = False
if not st.session_state.authenticated and not st.session_state.just_logged_out:
    payload = _read_cookie()
    if payload:
        st.session_state.authenticated = True
        st.session_state.username = payload["u"]
        st.session_state.role = payload.get("r", "")

# =============================================================================
# EMPLOYEE + INVENTORY HELPERS
# =============================================================================
def unique_nonempty(df: pd.DataFrame, col: str) -> list[str]:
    if df.empty or col not in df.columns: return []
    vals = [str(x).strip() for x in df[col].dropna().astype(str).tolist()]
    return sorted({v for v in vals if v})

def normalize_serial(s: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", (s or "").strip().upper())


# =============================================================================
# FILENAME + FOLDER HELPERS
# =============================================================================
SEQ_WS = "sequence_counters"   # sheet to store running counters

def _get_or_init_seq(seq_type: str) -> int:
    """Get current counter from sheet; create if missing."""
    df = read_worksheet(SEQ_WS)
    if df.empty or "type" not in df.columns or "counter" not in df.columns:
        df = pd.DataFrame(columns=["type", "counter"])
    if seq_type not in df["type"].values:
        new = pd.DataFrame([{"type": seq_type, "counter": 1}])
        df = pd.concat([df, new], ignore_index=True)
        write_worksheet(SEQ_WS, df)
        return 1
    cur = int(df.loc[df["type"] == seq_type, "counter"].iloc[0])
    return cur

def _bump_seq(seq_type: str) -> int:
    df = read_worksheet(SEQ_WS)
    if df.empty or "type" not in df.columns or "counter" not in df.columns:
        df = pd.DataFrame(columns=["type", "counter"])
    if seq_type not in df["type"].values:
        new = pd.DataFrame([{"type": seq_type, "counter": 2}])
        df = pd.concat([df, new], ignore_index=True)
    else:
        idx = df[df["type"] == seq_type].index[0]
        df.at[idx, "counter"] = int(df.at[idx, "counter"]) + 1
    write_worksheet(SEQ_WS, df)
    return int(df.loc[df["type"] == seq_type, "counter"].iloc[0])

def _ict_filename(serial: str, seq: str) -> str:
    return f"HO-JED-REG-{normalize_serial(serial)}-{seq}-{datetime.now().strftime('%Y%m%d')}.pdf"

def _transfer_filename(serial: str, seq: str) -> str:
    return f"HO-JED-TRF-{normalize_serial(serial)}-{seq}-{datetime.now().strftime('%Y%m%d')}.pdf"

def _get_ho_folder_id() -> str:
    return st.secrets.get("drive", {}).get("head_office_folder", "")

# =============================================================================
# REGISTER DEVICE
# =============================================================================
def register_device_tab():
    st.subheader("📝 Register New Device")
    emp_df = read_worksheet(EMPLOYEE_WS)
    emp_names = sorted({*unique_nonempty(emp_df, "New Employeer"), *unique_nonempty(emp_df, "Name")})

    with st.form("register_device", clear_on_submit=True):
        r1c1, r1c2, r1c3 = st.columns(3)
        with r1c1: serial = st.text_input("Serial Number *")
        with r1c2: device = st.text_input("Device Type *")
        with r1c3: owner  = st.selectbox("Assigned to", [UNASSIGNED_LABEL] + emp_names)

        brand = st.text_input("Brand")
        model = st.text_input("Model")
        cpu   = st.text_input("CPU")
        mem   = st.text_input("Memory")
        hdd1  = st.text_input("Hard Drive 1")
        hdd2  = st.text_input("Hard Drive 2")
        gpu   = st.text_input("GPU")
        screen= st.text_input("Screen Size")
        dept  = st.text_input("Department")
        email = st.text_input("Email Address")
        contact = st.text_input("Contact Number")
        location= st.text_input("Location")
        office = st.text_input("Office")
        notes  = st.text_area("Notes", height=60)

        pdf_file = st.file_uploader("Signed Registration PDF", type=["pdf"], key="reg_pdf")
        submitted = st.form_submit_button("Save Device", type="primary")

    if submitted:
        if not serial.strip() or not device.strip():
            st.error("Serial Number and Device Type are required.")
            return

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
            "Current user": owner.strip(),
            "Previous User": "",
            "TO": owner.strip() if owner.strip() != UNASSIGNED_LABEL else "",
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
        seq_val  = _get_or_init_seq("REG")

        if is_admin:
            inv = read_worksheet(INVENTORY_WS)
            inv_out = pd.concat([inv, pd.DataFrame([row])], ignore_index=True)
            write_worksheet(INVENTORY_WS, inv_out)
            _bump_seq("REG")
            st.success("✅ Device registered directly into Inventory.")
        else:
            if pdf_file is None:
                st.error("Signed PDF is required for staff submission.")
                return
            fname = _ict_filename(serial, f"{seq_val:04d}")
            folder_id = _get_ho_folder_id()
            link, fid = upload_pdf_and_link(pdf_file, prefix=fname)
            if not fid: return
            pending = {**row,
                "Approval Status": "Pending",
                "Approval PDF": link,
                "Approval File ID": fid,
                "Submitted by": actor,
                "Submitted at": now_str,
                "Approver": "", "Decision at": "",
            }
            append_to_worksheet(PENDING_DEVICE_WS, pd.DataFrame([pending]))
            st.success("🕒 Submitted for admin approval.")

# =============================================================================
# TRANSFER DEVICE
# =============================================================================
def transfer_tab():
    st.subheader("🔁 Transfer Device")
    inv = read_worksheet(INVENTORY_WS)
    if inv.empty:
        st.info("No devices to transfer.")
        return

    serials = sorted(inv["Serial Number"].dropna().astype(str).unique().tolist())
    serial  = st.selectbox("Select Serial", ["— Select —"] + serials)
    if serial == "— Select —": return

    emp_df = read_worksheet(EMPLOYEE_WS)
    emp_names = sorted({*unique_nonempty(emp_df,"New Employeer"), *unique_nonempty(emp_df,"Name")})
    new_owner = st.selectbox("Transfer To", ["— Select —"] + emp_names)
    if new_owner == "— Select —": return

    pdf_file = st.file_uploader("Signed Transfer PDF", type=["pdf"], key="transfer_pdf")
    if st.button("Submit Transfer", type="primary"):
        now_str = datetime.now().strftime(DATE_FMT)
        actor   = st.session_state.get("username", "")
        match   = inv[inv["Serial Number"].astype(str) == serial]
        if match.empty: return
        prev_user = str(match.iloc[0]["Current user"])

        is_admin = st.session_state.get("role") == "Admin"
        seq_val  = _get_or_init_seq("TRF")

        if is_admin:
            idx = match.index[0]
            inv.loc[idx,"Previous User"] = prev_user
            inv.loc[idx,"Current user"]  = new_owner
            inv.loc[idx,"TO"]            = new_owner
            inv.loc[idx,"Date issued"]   = now_str
            inv.loc[idx,"Registered by"] = actor
            write_worksheet(INVENTORY_WS, inv)

            log = {
                "Device Type": match.iloc[0]["Device Type"],
                "Serial Number": serial,
                "From owner": prev_user, "To owner": new_owner,
                "Date issued": now_str, "Registered by": actor,
            }
            append_to_worksheet(TRANSFERLOG_WS, pd.DataFrame([log]))
            _bump_seq("TRF")
            st.success("✅ Transfer applied immediately.")
        else:
            if pdf_file is None:
                st.error("Signed Transfer PDF required.")
                return
            fname = _transfer_filename(serial, f"{seq_val:04d}")
            link, fid = upload_pdf_and_link(pdf_file, prefix=fname)
            if not fid: return
            pend = {
                "Device Type": match.iloc[0]["Device Type"],
                "Serial Number": serial,
                "From owner": prev_user, "To owner": new_owner,
                "Date issued": now_str, "Registered by": actor,
                "Approval Status": "Pending",
                "Approval PDF": link, "Approval File ID": fid,
                "Submitted by": actor, "Submitted at": now_str,
                "Approver": "", "Decision at": "",
            }
            append_to_worksheet(PENDING_TRANSFER_WS, pd.DataFrame([pend]))
            st.success("🕒 Transfer submitted for approval.")

# =============================================================================
# APPROVALS (ADMIN)
# =============================================================================
def _mark_decision(ws_title: str, row: pd.Series, status: str):
    df = read_worksheet(ws_title)
    mask = (df["Serial Number"].astype(str) == str(row["Serial Number"])) & \
           (df["Submitted at"].astype(str) == str(row["Submitted at"]))
    if not mask.any(): return
    idx = df[mask].index[0]
    df.loc[idx, "Approval Status"] = status
    df.loc[idx, "Approver"] = st.session_state.get("username","")
    df.loc[idx, "Decision at"] = datetime.now().strftime(DATE_FMT)
    write_worksheet(ws_title, df)

def _approve_device_row(row: pd.Series):
    inv = read_worksheet(INVENTORY_WS)
    new_row = {k: row.get(k,"") for k in inv.columns}
    inv_out = pd.concat([inv, pd.DataFrame([new_row])], ignore_index=True)
    write_worksheet(INVENTORY_WS, inv_out)
    _mark_decision(PENDING_DEVICE_WS, row, "Approved")
    _bump_seq("REG")
    st.success("✅ Device approved & added to Inventory.")

def _approve_transfer_row(row: pd.Series):
    inv = read_worksheet(INVENTORY_WS)
    sn  = str(row["Serial Number"])
    match = inv[inv["Serial Number"].astype(str)==sn]
    if match.empty:
        st.error("Serial not found in Inventory.")
        return
    idx = match.index[0]
    inv.loc[idx,"Previous User"] = str(row["From owner"])
    inv.loc[idx,"Current user"]  = str(row["To owner"])
    inv.loc[idx,"TO"]            = str(row["To owner"])
    inv.loc[idx,"Date issued"]   = datetime.now().strftime(DATE_FMT)
    inv.loc[idx,"Registered by"] = st.session_state.get("username","")
    write_worksheet(INVENTORY_WS, inv)

    log = {k: row.get(k,"") for k in ["Device Type","Serial Number","From owner","To owner"]}
    log["Date issued"] = datetime.now().strftime(DATE_FMT)
    log["Registered by"]=st.session_state.get("username","")
    append_to_worksheet(TRANSFERLOG_WS, pd.DataFrame([log]))
    _mark_decision(PENDING_TRANSFER_WS, row, "Approved")
    _bump_seq("TRF")
    st.success("✅ Transfer approved & applied.")

def approvals_tab():
    st.subheader("✅ Approvals (Admin)")
    if st.session_state.get("role")!="Admin":
        st.info("Only Admins can view this tab.")
        return

    pending_dev = read_worksheet(PENDING_DEVICE_WS)
    for i,row in pending_dev[pending_dev["Approval Status"]=="Pending"].iterrows():
        with st.expander(f"Device {row['Serial Number']} (by {row['Submitted by']})", expanded=False):
            st.json({k: row.get(k,"") for k in ["Device Type","Serial Number","Current user","Department"]})
            pdf_link=row.get("Approval PDF","")
            if pdf_link: st.markdown(f"[View PDF]({pdf_link})")
            if st.button("Approve", key=f"approve_dev_{i}"): _approve_device_row(row)
            if st.button("Reject", key=f"reject_dev_{i}"): _mark_decision(PENDING_DEVICE_WS,row,"Rejected")

    st.markdown("---")
    pending_tr = read_worksheet(PENDING_TRANSFER_WS)
    for i,row in pending_tr[pending_tr["Approval Status"]=="Pending"].iterrows():
        with st.expander(f"Transfer {row['Serial Number']} (by {row['Submitted by']})", expanded=False):
            st.json({k: row.get(k,"") for k in ["Device Type","Serial Number","From owner","To owner"]})
            pdf_link=row.get("Approval PDF","")
            if pdf_link: st.markdown(f"[View PDF]({pdf_link})")
            if st.button("Approve", key=f"approve_tr_{i}"): _approve_transfer_row(row)
            if st.button("Reject", key=f"reject_tr_{i}"): _mark_decision(PENDING_TRANSFER_WS,row,"Rejected")

# =============================================================================
# EXPORT
# =============================================================================
def export_tab():
    st.subheader("⬇️ Export")
    inv = read_worksheet(INVENTORY_WS)
    log = read_worksheet(TRANSFERLOG_WS)
    emp = read_worksheet(EMPLOYEE_WS)
    st.download_button("Inventory CSV", inv.to_csv(index=False).encode("utf-8"), "inventory.csv")
    st.download_button("Transfer Log CSV", log.to_csv(index=False).encode("utf-8"), "transfer_log.csv")
    st.download_button("Employees CSV", emp.to_csv(index=False).encode("utf-8"), "employees.csv")

# =============================================================================
# MAIN APP
# =============================================================================
def run_app():
    st.title(APP_TITLE)
    st.caption(SUBTITLE)

    if st.session_state.role=="Admin":
        tabs=st.tabs(["📝 Register Device","🔁 Transfer","✅ Approvals","⬇️ Export"])
        with tabs[0]: register_device_tab()
        with tabs[1]: transfer_tab()
        with tabs[2]: approvals_tab()
        with tabs[3]: export_tab()
    else:
        tabs=st.tabs(["📝 Register Device","🔁 Transfer"])
        with tabs[0]: register_device_tab()
        with tabs[1]: transfer_tab()

# =============================================================================
# ENTRY POINT
# =============================================================================
if st.session_state.authenticated:
    run_app()
else:
    st.subheader("🔐 Sign In")
    username=st.text_input("Username")
    password=st.text_input("Password", type="password")
    if st.button("Login", type="primary"):
        user=USERS.get(username)
        if user and _verify_password(password,user["password"]):
            do_login(username,user.get("role","Staff"))
        else:
            st.error("❌ Invalid username or password.")
