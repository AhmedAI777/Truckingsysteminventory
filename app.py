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

from PyPDF2 import PdfReader, PdfWriter
from PyPDF2.generic import NameObject, DictionaryObject, BooleanObject, ArrayObject

# =============================================================================
# CONFIG
# =============================================================================
APP_TITLE = "Tracking Inventory Management System"
SUBTITLE  = "Advanced Construction"
DATE_FMT  = "%Y-%m-%d %H:%M:%S"

SESSION_TTL_SECONDS = 30 * 24 * 60 * 60
COOKIE_NAME = "ac_auth_v2"

SHEET_URL_DEFAULT = "https://docs.google.com/spreadsheets/d/1SHp6gOW4ltsyOT41rwo85e_LELrHkwSwKN33K6XNHFI/edit"

INVENTORY_WS = "truckinventory"
TRANSFERLOG_WS = "transfer_log"
EMPLOYEE_WS = "mainlists"
PENDING_DEVICE_WS = "pending_device_reg"
PENDING_TRANSFER_WS = "pending_transfers"
DEVICE_CATALOG_WS = st.secrets.get("sheets", {}).get("catalog_ws", "truckingsysteminventory")

INVENTORY_COLS = [
    "Serial Number","Device Type","Brand","Model","CPU",
    "Hard Drive 1","Hard Drive 2","Memory","GPU","Screen Size",
    "Current user","Previous User","TO","Department","Email Address","Contact Number",
    "Location","Office","Notes","Date issued","Registered by"
]
LOG_COLS = ["Device Type","Serial Number","From owner","To owner","Date issued","Registered by"]
EMPLOYEE_CANON_COLS = ["New Employeer","Employee ID","New Signature","Name","Address",
    "Active","Position","Department","Location (KSA)","Project","Microsoft Teams","Mobile Number","Email"]
APPROVAL_META_COLS = ["Approval Status","Approval PDF","Approval File ID","Submitted by","Submitted at","Approver","Decision at"]
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

def _verify_password(raw, stored): return hmac.compare_digest(str(stored), str(raw))

def _sign(raw: bytes) -> str:
    key = st.secrets.get("auth", {}).get("cookie_key", "")
    return hmac.new(key.encode(), raw, hashlib.sha256).hexdigest()

def _issue_session_cookie(username: str, role: str):
    iat = int(time.time()); exp = iat + SESSION_TTL_SECONDS
    payload = {"u": username, "r": role, "iat": iat, "exp": exp}
    raw = json.dumps(payload).encode()
    token = base64.urlsafe_b64encode(raw).decode() + "." + _sign(raw)
    COOKIE_MGR.set(COOKIE_NAME, token, expires_at=datetime.utcnow() + timedelta(seconds=SESSION_TTL_SECONDS))

def _read_cookie():
    token = COOKIE_MGR.get(COOKIE_NAME)
    if not token: return None
    try:
        data_b64, sig = token.split(".", 1)
        raw = base64.urlsafe_b64decode(data_b64.encode())
        if _sign(raw) != sig: return None
        payload = json.loads(raw.decode())
        if payload["exp"] < time.time(): return None
        return payload
    except: return None

def do_login(username: str, role: str):
    st.session_state.authenticated = True
    st.session_state.username = username
    st.session_state.role = role
    _issue_session_cookie(username, role)
    st.rerun()

def do_logout():
    COOKIE_MGR.delete(COOKIE_NAME)
    for k in ["authenticated","username","role"]: st.session_state.pop(k, None)
    st.session_state.just_logged_out = True
    st.rerun()

if "cookie_bootstrapped" not in st.session_state:
    st.session_state.cookie_bootstrapped = True
    _ = COOKIE_MGR.get_all()
    st.rerun()

# =============================================================================
# GOOGLE SHEETS & DRIVE
# =============================================================================
def _load_sa_info() -> dict:
    raw = st.secrets.get("gcp_service_account", {})
    return dict(raw) if isinstance(raw, dict) else json.loads(raw or "{}")

@st.cache_resource
def _get_creds(): return Credentials.from_service_account_info(_load_sa_info(), scopes=["https://www.googleapis.com/auth/spreadsheets","https://www.googleapis.com/auth/drive"])
@st.cache_resource
def _get_gc(): return gspread.authorize(_get_creds())
@st.cache_resource
def _get_drive(): return build("drive", "v3", credentials=_get_creds())

def get_sh(): return _get_gc().open_by_url(st.secrets.get("sheets", {}).get("url", SHEET_URL_DEFAULT))

def _drive_make_public(file_id: str, drive_client=None):
    try: (drive_client or _get_drive()).permissions().create(fileId=file_id, body={"role":"reader","type":"anyone"}).execute()
    except: pass

def _drive_download_bytes(file_id: str) -> bytes:
    buf = io.BytesIO(); req = _get_drive().files().get_media(fileId=file_id); MediaIoBaseDownload(buf, req).next_chunk()
    buf.seek(0); return buf.read()

# =============================================================================
# SHEETS HELPERS
# =============================================================================
def reorder_columns(df, cols): 
    for c in cols:
        if c not in df.columns: df[c] = ""
    return df[cols+[c for c in df.columns if c not in cols]]

def get_or_create_ws(title): 
    sh = get_sh()
    try: return sh.worksheet(title)
    except gspread.exceptions.WorksheetNotFound: return sh.add_worksheet(title, rows=500, cols=80)

def read_worksheet(ws_title): return reorder_columns(pd.DataFrame(get_or_create_ws(ws_title).get_all_records()), 
    INVENTORY_COLS if ws_title==INVENTORY_WS else LOG_COLS if ws_title==TRANSFERLOG_WS else EMPLOYEE_CANON_COLS if ws_title==EMPLOYEE_WS else PENDING_DEVICE_COLS if ws_title==PENDING_DEVICE_WS else PENDING_TRANSFER_COLS if ws_title==PENDING_TRANSFER_WS else [])

def write_worksheet(ws_title, df): ws=get_or_create_ws(ws_title); ws.clear(); set_with_dataframe(ws, df)
def append_to_worksheet(ws_title, new_data): set_with_dataframe(get_or_create_ws(ws_title), pd.concat([pd.DataFrame(get_or_create_ws(ws_title).get_all_records()), new_data], ignore_index=True))

# =============================================================================
# COUNTERS + HELPERS
# =============================================================================
def _get_counter_ws():
    sh=get_sh()
    try: return sh.worksheet("counters")
    except gspread.exceptions.WorksheetNotFound:
        ws=sh.add_worksheet(title="counters", rows=10, cols=3)
        ws.update([["Type","LastUsed"],["REG",0],["TRF",0]])
        return ws

def _next_sequence(t): ws=_get_counter_ws(); df=pd.DataFrame(ws.get_all_records()); 
df_empty = df.empty
    if df.empty: df=pd.DataFrame([{"Type":"REG","LastUsed":0},{"Type":"TRF","LastUsed":0}])
    if t not in df["Type"].values: df=pd.concat([df,pd.DataFrame([{"Type":t,"LastUsed":0}])])
    idx=df.index[df["Type"]==t][0]; df.at[idx,"LastUsed"]=int(df.at[idx,"LastUsed"])+1; set_with_dataframe(ws,df)
    return f"{int(df.at[idx,'LastUsed']):04d}"

def normalize_serial(sn): return re.sub(r"[^A-Z0-9]","",str(sn).upper().strip()) if sn else ""
def unique_nonempty(df,col): return sorted({str(x).strip() for x in df[col].dropna()}) if df is not None and not df.empty and col in df.columns else []

# =============================================================================
# PDF HELPERS
# =============================================================================
def _registration_field_map(): return {"from_name":"Text Field0","to_name":"Text Field6","eq_type":"Text Field12","eq_serial":"Text Field16"} # simplified

def fill_pdf_form(template_bytes, values, flatten=True):
    reader=PdfReader(io.BytesIO(template_bytes)); writer=PdfWriter(); [writer.add_page(p) for p in reader.pages]
    writer.update_page_form_field_values(writer.pages[0], values)
    out=io.BytesIO(); writer.write(out); out.seek(0); return out.read()

def build_registration_values(row, *, actor_name, emp_df=None): return {"Text Field0":row.get("Current user",""),"Text Field12":row.get("Device Type",""),"Text Field16":row.get("Serial Number","")}
def build_transfer_values(row, new_owner, *, emp_df): return {"Text Field0":row.get("Current user",""),"Text Field6":new_owner,"Text Field12":row.get("Device Type",""),"Text Field16":row.get("Serial Number","")}

# =============================================================================
# UPLOAD TO DRIVE
# =============================================================================
def upload_pdf_and_link(uploaded_file, *, prefix: str) -> Tuple[str,str]:
    if not uploaded_file: return "",""
    data=uploaded_file.getvalue()
    if not data: return "",""
    fname=f"{prefix}_{int(time.time())}.pdf"; folder_id=st.secrets.get("drive",{}).get("approvals",""); metadata={"name":fname}
    if folder_id: metadata["parents"]=[folder_id]
    media=MediaIoBaseUpload(io.BytesIO(data), mimetype="application/pdf", resumable=False)
    file=_get_drive().files().create(body=metadata, media_body=media, fields="id, webViewLink").execute()
    _drive_make_public(file["id"]); return file.get("webViewLink",""),file.get("id","")

# =============================================================================
# TAB FUNCTIONS
# =============================================================================
def render_header():
    st.markdown(f"### {APP_TITLE}"); st.caption(SUBTITLE)
    if st.session_state.get("authenticated") and st.button("Logout"): do_logout()
    st.markdown("---")

def employee_register_tab():
    st.subheader("🧑‍💼 Employee Register")
    emp_df=read_worksheet(EMPLOYEE_WS); emp_name=st.text_input("New Employeer"); emp_id=st.text_input("Employee ID")
    if st.button("Save Employee") and emp_name: append_to_worksheet(EMPLOYEE_WS,pd.DataFrame([{"New Employeer":emp_name,"Employee ID":emp_id}])); st.success("Saved")

def employees_view_tab(): st.subheader("📇 Employees"); st.dataframe(read_worksheet(EMPLOYEE_WS), use_container_width=True)
def inventory_tab(): st.subheader("📋 Inventory"); st.dataframe(read_worksheet(INVENTORY_WS), use_container_width=True)
def history_tab(): st.subheader("📜 Transfer Log"); st.dataframe(read_worksheet(TRANSFERLOG_WS), use_container_width=True)

def register_device_tab():
    st.subheader("📝 Register Device")
    serial=st.text_input("Serial Number *"); device=st.text_input("Device Type *")
    if st.button("Generate PDF") and serial and device: 
        tpl=_drive_download_bytes(ICT_TEMPLATE_FILE_ID); vals=build_registration_values({"Serial Number":serial,"Device Type":device,"Current user":UNASSIGNED_LABEL},actor_name=st.session_state.get("username",""))
        st.download_button("📥 Download Form", data=fill_pdf_form(tpl,vals), file_name=_ict_filename(serial))
    pdf=st.file_uploader("Signed PDF",type="pdf"); 
    if st.button("Save Device") and pdf: link,fid=upload_pdf_and_link(pdf,prefix=f"device_{normalize_serial(serial)}"); st.success(f"Saved with link {link}")

def transfer_tab():
    st.subheader("🔁 Transfer Device")
    df=read_worksheet(INVENTORY_WS); sn=st.selectbox("Serial",[UNASSIGNED_LABEL]+df["Serial Number"].astype(str).tolist())
    emp_df=read_worksheet(EMPLOYEE_WS); new_owner=st.selectbox("New Owner",unique_nonempty(emp_df,"New Employeer"))
    if st.button("Generate Transfer PDF") and sn and new_owner:
        tpl=_drive_download_bytes(TRANSFER_TEMPLATE_FILE_ID); vals=build_transfer_values(df[df["Serial Number"]==sn].iloc[0],new_owner,emp_df=emp_df)
        st.download_button("📥 Download Transfer", data=fill_pdf_form(tpl,vals), file_name=_transfer_filename(sn))
    pdf=st.file_uploader("Signed Transfer PDF",type="pdf"); 
    if st.button("Submit Transfer") and pdf: link,fid=upload_pdf_and_link(pdf,prefix=f"transfer_{normalize_serial(sn)}"); st.success(f"Submitted {sn} → {new_owner}")

def approvals_tab(): st.subheader("✅ Approvals"); st.write(read_worksheet(PENDING_DEVICE_WS)); st.write(read_worksheet(PENDING_TRANSFER_WS))
def export_tab(): st.subheader("⬇️ Export"); st.download_button("Inventory CSV", read_worksheet(INVENTORY_WS).to_csv(index=False).encode(),"inv.csv")

def run_app():
    render_header()
    if st.session_state.role=="Admin":
        tabs=st.tabs(["🧑‍💼 Employee Register","📇 View Employees","📝 Register Device","📋 View Inventory","🔁 Transfer Device","📜 Transfer Log","✅ Approvals","⬇️ Export"])
        with tabs[0]: employee_register_tab(); with tabs[1]: employees_view_tab(); with tabs[2]: register_device_tab(); with tabs[3]: inventory_tab(); with tabs[4]: transfer_tab(); with tabs[5]: history_tab(); with tabs[6]: approvals_tab(); with tabs[7]: export_tab()
    else:
        tabs=st.tabs(["📝 Register Device","🔁 Transfer Device","📋 View Inventory","📜 Transfer Log"])
        with tabs[0]: register_device_tab(); with tabs[1]: transfer_tab(); with tabs[2]: inventory_tab(); with tabs[3]: history_tab()

# =============================================================================
# ENTRYPOINT
# =============================================================================
if "authenticated" not in st.session_state: st.session_state.authenticated=False
if "just_logged_out" not in st.session_state: st.session_state.just_logged_out=False
if not st.session_state.authenticated and not st.session_state.just_logged_out:
    payload=_read_cookie()
    if payload: st.session_state.authenticated=True; st.session_state.username=payload["u"]; st.session_state.role=payload.get("r","")
if st.session_state.authenticated: run_app()
else:
    st.subheader("🔐 Sign In"); u=st.text_input("Username"); p=st.text_input("Password",type="password")
    if st.button("Login"): user=USERS.get(u); 
        if user and _verify_password(p,user["password"]): do_login(u,user.get("role","Staff"))
        else: st.error("❌ Invalid username or password.")
