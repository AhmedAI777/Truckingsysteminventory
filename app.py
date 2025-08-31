# app.py — Tracking Inventory Management System (with pre-filled, non-editable PDFs)
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

# Standard device columns (used across inventory + catalog)
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
REQUIRE_REVIEW_CHECK = True  # gate Approve behind a review checkbox

ICT_TEMPLATE_FILE_ID = st.secrets.get("drive", {}).get(
    "template_file_id",
    "1BdbeVEpDuS_hpQgxNLGij5sl01azT_zG"  # replace with your file's id
)
TRANSFER_TEMPLATE_FILE_ID = st.secrets.get("drive", {}).get(
    "transfer_template_file_id",
    ICT_TEMPLATE_FILE_ID
)

def _ict_filename(serial: str, seq: str = "0008") -> str:
    return f"HO-JED-REG-{re.sub(r'[^A-Z0-9]','',serial.upper())}-{seq}-{datetime.now().strftime('%Y%m%d')}.pdf"

def _transfer_filename(serial: str, seq: str = "0009") -> str:
    return f"HO-JED-TRN-{re.sub(r'[^A-Z0-9]','',serial.upper())}-{seq}-{datetime.now().strftime('%Y%m%d')}.pdf"

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
    "email": "Email Address",  # allow 'Email' header to map to 'Email Address'
    "department1": None,
}

COOKIE_MGR = stx.CookieManager(key="ac_cookie_mgr")
for k in ("reg_pdf_ref", "transfer_pdf_ref"): ss.setdefault(k, None)

# =============================================================================
# AUTH
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
    if not token: return None
    try:
        data_b64, sig = token.split(".", 1)
        raw = base64.urlsafe_b64decode(data_b64.encode())
        if not _verify_sig(sig, raw):
            COOKIE_MGR.delete(COOKIE_NAME); return None
        payload = json.loads(raw.decode())
        exp = int(payload.get("exp", 0)); now = int(time.time())
        if exp and now > exp:
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
    try:
        COOKIE_MGR.delete(COOKIE_NAME)
        COOKIE_MGR.set(COOKIE_NAME, "", expires_at=datetime.utcnow() - timedelta(days=1))
    except Exception:
        pass
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
SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive",
]
OAUTH_SCOPES = ["https://www.googleapis.com/auth/drive.file"]
ALLOW_OAUTH_FALLBACK = st.secrets.get("drive", {}).get("allow_oauth_fallback", True)

def _load_sa_info() -> dict:
    raw = st.secrets.get("gcp_service_account", {})
    sa: dict = {}
    if isinstance(raw, dict): sa = dict(raw)
    elif isinstance(raw, str) and raw.strip():
        try: sa = json.loads(raw)
        except Exception: sa = {}
    if not sa:
        env_json = os.environ.get("GOOGLE_SERVICE_ACCOUNT_JSON", "")
        if env_json:
            try: sa = json.loads(env_json)
            except Exception: sa = {}
    pk = sa.get("private_key", "")
    if isinstance(pk, str) and "\\n" in pk: sa["private_key"] = pk.replace("\\n", "\n")
    if "private_key" not in sa:
        raise RuntimeError("Service account JSON not found or missing 'private_key'.")
    return sa

@st.cache_resource(show_spinner=False)
def _get_creds():
    return Credentials.from_service_account_info(_load_sa_info(), scopes=SCOPES)

@st.cache_resource(show_spinner=False)
def _get_gc(): return gspread.authorize(_get_creds())

@st.cache_resource(show_spinner=False)
def _get_drive(): return build("drive", "v3", credentials=_get_creds())

@st.cache_resource(show_spinner=False)
def _get_user_creds():
    cfg = st.secrets.get("google_oauth", {})
    token_json = cfg.get("token_json")
    if token_json:
        try: info = json.loads(token_json)
        except Exception: info = None
        if not info: st.error("google_oauth.token_json is not valid JSON."); st.stop()
        creds = UserCredentials.from_authorized_user_info(info, OAUTH_SCOPES)
        if not creds.valid and creds.refresh_token: creds.refresh(Request())
        return creds
    if os.environ.get("LOCAL_OAUTH", "0") == "1":
        client_id = cfg.get("client_id"); client_secret = cfg.get("client_secret")
        if not client_id or not client_secret:
            st.error("[google_oauth] client_id/client_secret required for local OAuth."); st.stop()
        flow = InstalledAppFlow.from_client_config(
            {"installed": {"client_id": client_id,"client_secret": client_secret,
                           "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                           "token_uri": "https://oauth2.googleapis.com/token",
                           "redirect_uris": ["http://localhost"]}},
            scopes=OAUTH_SCOPES,
        )
        return flow.run_local_server(port=0)
    st.error("OAuth token not configured. Add [google_oauth].token_json to secrets, "
             "or move uploads to a Shared drive and disable OAuth fallback.")
    st.stop()

@st.cache_resource(show_spinner=False)
def _get_user_drive(): return build("drive", "v3", credentials=_get_user_creds())

@st.cache_resource(show_spinner=False)
def _get_sheet_url(): return st.secrets.get("sheets", {}).get("url", SHEET_URL_DEFAULT)

def get_sh():
    gc = _get_gc(); url = _get_sheet_url()
    last_exc = None
    for attempt in range(3):
        try: return gc.open_by_url(url)
        except gspread.exceptions.APIError as e:
            last_exc = e; time.sleep(0.6 * (attempt + 1))
    st.error("Google Sheets API error while opening the spreadsheet."); raise last_exc

def _drive_make_public(file_id: str, drive_client=None):
    try:
        cli = drive_client or _get_drive()
        cli.permissions().create(
            fileId=file_id, body={"role": "reader", "type": "anyone"},
            fields="id", supportsAllDrives=True,
        ).execute()
    except Exception:
        pass

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

def _drive_download_bytes(file_id: str) -> bytes:
    buf = io.BytesIO()
    request = _get_drive().files().get_media(fileId=file_id, supportsAllDrives=True)
    downloader = MediaIoBaseDownload(buf, request)
    done = False
    while not done:
        _, done = downloader.next_chunk()
    buf.seek(0)
    return buf.read()

# =============================================================================
# DRIVE FOLDER HELPERS
# =============================================================================

CITY_MAP = {
    "JED": "Jeddah (JED)",
    "RUH": "Riyadh (RUH)",
    "TIF": "TAIF (TIF)",
    "MED": "Medina (MED)",
    # Add more mappings if needed
}

def city_folder_name(code: str) -> str:
    """Return the correct Drive folder name for a city code (fallback = CODE (CODE))."""
    if not code:
        return "Unknown"
    return CITY_MAP.get(code.upper(), f"{code.upper()} ({code.upper()})")

def ensure_drive_subfolder(root_id: str, path_parts: list[str], drive_cli=None) -> str:
    """Walk or create a folder path under root_id."""
    cli = drive_cli or _get_drive()
    parent = root_id
    for part in path_parts:
        q = (f"'{parent}' in parents and name='{part}' "
             "and mimeType='application/vnd.google-apps.folder' and trashed=false")
        res = cli.files().list(q=q, spaces="drive", fields="files(id,name)", supportsAllDrives=True).execute()
        items = res.get("files", [])
        if items:
            parent = items[0]["id"]
        else:
            meta = {"name": part, "mimeType": "application/vnd.google-apps.folder", "parents": [parent]}
            newf = cli.files().create(body=meta, fields="id", supportsAllDrives=True).execute()
            parent = newf["id"]
    return parent

def move_drive_file(file_id: str, office: str, city_code: str, action: str, decision: str):
    """Move a file from Pending → Approved/Rejected in the correct folder path."""
    drive_cli = _get_drive()
    root_id = st.secrets.get("drive", {}).get("approvals", "")
    city_folder = city_folder_name(city_code)
    path_parts = [office, city_folder, action, decision]
    new_folder_id = ensure_drive_subfolder(root_id, path_parts, drive_cli)

    file = drive_cli.files().get(fileId=file_id, fields="parents", supportsAllDrives=True).execute()
    prev_parents = ",".join(file.get("parents", []))

    drive_cli.files().update(
        fileId=file_id,
        addParents=new_folder_id,
        removeParents=prev_parents,
        fields="id, parents",
        supportsAllDrives=True
    ).execute()

# =============================================================================
# SHEETS HELPERS
# =============================================================================
def _norm_header(h: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (h or "").strip().lower())

def canon_inventory_columns(df: pd.DataFrame) -> pd.DataFrame:
    rename, drop_cols = {}, []
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
    sh = get_sh(); wanted = EMPLOYEE_WS.strip().lower()
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
        ws = get_or_create_ws(PENDING_DEVICE_WS); df = pd.DataFrame(ws.get_all_records())
        return reorder_columns(df, PENDING_DEVICE_COLS)
    if ws_title == PENDING_TRANSFER_WS:
        ws = get_or_create_ws(PENDING_TRANSFER_WS); df = pd.DataFrame(ws.get_all_records())
        return reorder_columns(df, PENDING_TRANSFER_COLS)
    if ws_title == EMPLOYEE_WS:
        ws = get_employee_ws(); df = pd.DataFrame(ws.get_all_records())
        return reorder_columns(df, EMPLOYEE_CANON_COLS)
    if ws_title == DEVICE_CATALOG_WS:
        ws = get_or_create_ws(DEVICE_CATALOG_WS); df = pd.DataFrame(ws.get_all_records())
        return reorder_columns(df, CATALOG_COLS)
    ws = get_or_create_ws(ws_title); data = ws.get_all_records(); df = pd.DataFrame(data)
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
        if ws_title == DEVICE_CATALOG_WS:  return pd.DataFrame(columns=CATALOG_COLS)
        return pd.DataFrame()

def write_worksheet(ws_title, df):
    if ws_title == INVENTORY_WS:
        df = canon_inventory_columns(df); df = reorder_columns(df, INVENTORY_COLS)
    if ws_title == PENDING_DEVICE_WS:   df = reorder_columns(df, PENDING_DEVICE_COLS)
    if ws_title == PENDING_TRANSFER_WS: df = reorder_columns(df, PENDING_TRANSFER_COLS)
    if ws_title == EMPLOYEE_WS:
        ws = get_employee_ws()
    else:
        ws = get_or_create_ws(ws_title)
    ws.clear(); set_with_dataframe(ws, df); st.cache_data.clear()

def append_to_worksheet(ws_title, new_data):
    ws = get_or_create_ws(ws_title)
    df_existing = pd.DataFrame(ws.get_all_records())
    if ws_title == INVENTORY_WS:
        df_existing = canon_inventory_columns(df_existing); df_existing = reorder_columns(df_existing, INVENTORY_COLS)
    if ws_title == PENDING_DEVICE_WS:   df_existing = reorder_columns(df_existing, PENDING_DEVICE_COLS)
    if ws_title == PENDING_TRANSFER_WS: df_existing = reorder_columns(df_existing, PENDING_TRANSFER_COLS)
    df_combined = pd.concat([df_existing, new_data], ignore_index=True)
    set_with_dataframe(ws, df_combined); st.cache_data.clear()

def normalize_serial(s: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", (s or "").strip().upper())

def unique_nonempty(df: pd.DataFrame, col: str) -> list[str]:
    if df.empty or col not in df.columns:
        return []
    vals = [str(x).strip() for x in df[col].dropna().astype(str).tolist()]
    return sorted({v for v in vals if v})

def _get_catalog_df() -> pd.DataFrame:
    return read_worksheet(DEVICE_CATALOG_WS)

def get_device_from_catalog_by_serial(serial: str) -> dict:
    df = _get_catalog_df()
    if df.empty:
        return {}
    df["__snorm"] = df["Serial Number"].astype(str).map(normalize_serial)
    sn = normalize_serial(serial)
    hit = df[df["__snorm"] == sn]
    if hit.empty:
        return {}
    row = hit.iloc[0].to_dict()
    for k in list(row.keys()):
        if k.startswith("__"):
            row.pop(k, None)
    return row

# =============================================================================
# PDF FILLING
# =============================================================================
def _registration_field_map() -> dict[str, str]:
    fm: dict[str, str] = {
        "from_name":       "Text Field0",
        "from_mobile":     "Text Field1",
        "from_email":      "Text Field2",
        "from_department": "Text Field3",
        "from_date":       "Text Field4",
        "from_location":   "Text Field5",

        "to_name":         "Text Field6",
        "to_mobile":       "Text Field7",
        "to_email":        "Text Field8",
        "to_department":   "Text Field9",
        "to_date":         "Text Field10",
        "to_location":     "Text Field11",
    }
    for blk in range(4):
        base = 12 + blk * 5
        fm[f"eq{blk+1}_type"]   = f"Text Field{base}"
        fm[f"eq{blk+1}_brand"]  = f"Text Field{base+1}"
        fm[f"eq{blk+1}_model"]  = f"Text Field{base+2}"
        fm[f"eq{blk+1}_specs"]  = f"Text Field{base+3}"
        fm[f"eq{blk+1}_serial"] = f"Text Field{base+4}"
    fm.update({
        "eq_type":   fm["eq1_type"],
        "eq_brand":  fm["eq1_brand"],
        "eq_model":  fm["eq1_model"],
        "eq_specs":  fm["eq1_specs"],
        "eq_serial": fm["eq1_serial"],
    })
    override = st.secrets.get("pdf", {}).get("reg_field_map", {})
    if isinstance(override, dict) and override:
        fm.update(override)
    return fm

def fill_pdf_form(template_bytes: bytes, values: dict[str,str], *, flatten: bool = True) -> bytes:
    reader = PdfReader(io.BytesIO(template_bytes)); writer = PdfWriter()
    for p in reader.pages:
        writer.add_page(p)
    try:
        writer.update_page_form_field_values(writer.pages[0], values)
    except Exception:
        pass
    if "/AcroForm" in reader.trailer["/Root"]:
        ac = reader.trailer["/Root"]["/AcroForm"]
        writer._root_object.update({NameObject("/AcroForm"): ac})
        writer._root_object["/AcroForm"].update({NameObject("/NeedAppearances"): BooleanObject(True)})
    else:
        writer._root_object.update({NameObject("/AcroForm"): DictionaryObject({NameObject("/NeedAppearances"): BooleanObject(True)})})
    if flatten:
        try:
            fields = writer._root_object["/AcroForm"].get("/Fields")
            if fields:
                for f in fields:
                    obj = f.get_object()
                    if obj.get("/FT") == NameObject("/Tx"):
                        flags = int(obj.get("/Ff", 0)); obj.update({NameObject("/Ff"): flags | 1})
            writer._root_object["/AcroForm"].update({NameObject("/Fields"): ArrayObject()})
        except Exception:
            pass
    out = io.BytesIO(); writer.write(out); out.seek(0); return out.read()

# Employee lookup helpers, etc… (continues below in Part 4)


# =========================
# Helpers (Employee lookup)
# =========================

def _find_emp_row_by_name(emp_df: pd.DataFrame, name: str) -> pd.Series | None:
    try:
        if emp_df is None or emp_df.empty or not str(name).strip():
            return None
        name = str(name).strip()
        cand = emp_df[
            (emp_df.get("New Employeer", "").astype(str).str.strip() == name) |
            (emp_df.get("Name", "").astype(str).str.strip() == name)
        ]
        return cand.iloc[0] if not cand.empty else None
    except Exception:
        return None

def _get_emp_value(row: pd.Series, *aliases: str) -> str:
    if row is None:
        return ""
    for col in aliases:
        v = row.get(col, "")
        if str(v).strip():
            return str(v)
    return ""

def _owner_changed(emp_df: pd.DataFrame):
    owner = st.session_state.get("current_owner", UNASSIGNED_LABEL)
    keys = ("reg_contact","reg_email","reg_dept","reg_location","reg_office")
    if owner and owner != UNASSIGNED_LABEL and isinstance(emp_df, pd.DataFrame) and not emp_df.empty:
        r = _find_emp_row_by_name(emp_df, owner)
        if r is not None:
            st.session_state["reg_contact"]  = _get_emp_value(r, "Mobile Number", "Phone", "Mobile")
            st.session_state["reg_email"]    = _get_emp_value(r, "Email", "E-mail")
            st.session_state["reg_dept"]     = _get_emp_value(r, "Department", "Dept")
            st.session_state["reg_location"] = _get_emp_value(r, "Location (KSA)", "Location", "City")
            st.session_state["reg_office"]   = _get_emp_value(r, "Office", "Project", "Site")
            return
    for k in keys:
        st.session_state[k] = ""

def _download_template_bytes_or_public(file_id: str) -> bytes:
    try:
        data = _drive_download_bytes(file_id)
        if data and data[:4] == b"%PDF":
            return data
    except Exception:
        pass
    try:
        buf = io.BytesIO()
        req = _get_user_drive().files().get_media(fileId=file_id)
        MediaIoBaseDownload(buf, req).next_chunk()
        buf.seek(0)
        data = buf.read()
        if data and data[:4] == b"%PDF":
            return data
    except Exception:
        pass
    data = _fetch_public_pdf_bytes(file_id, "")
    return data or b""

# PDF field value builders (registration & transfer)
def build_registration_values(device_row: dict, *, actor_name: str, emp_df: pd.DataFrame | None = None) -> dict[str, str]:
    fm = _registration_field_map()
    curr_owner    = str(device_row.get("Current user", "") or "").strip()
    is_unassigned = (not curr_owner) or (curr_owner == UNASSIGNED_LABEL)
    from_name     = curr_owner if not is_unassigned else (actor_name or device_row.get("Registered by",""))
    from_mobile   = str(device_row.get("Contact Number","") or "")
    from_email    = str(device_row.get("Email Address","") or "")
    from_dept     = str(device_row.get("Department","") or "")
    from_location = str(device_row.get("Location","") or "")
    if not is_unassigned and isinstance(emp_df, pd.DataFrame) and not emp_df.empty:
        r = _find_emp_row_by_name(emp_df, curr_owner)
        if r is not None:
            from_mobile   = from_mobile   or _get_emp_value(r, "Mobile Number", "Phone", "Mobile")
            from_email    = from_email    or _get_emp_value(r, "Email", "E-mail")
            from_dept     = from_dept     or _get_emp_value(r, "Department", "Dept")
            from_location = from_location or _get_emp_value(r, "Location (KSA)", "Location", "City")
    values = {
        fm["from_name"]:       from_name,
        fm["from_mobile"]:     from_mobile,
        fm["from_email"]:      from_email,
        fm["from_department"]: from_dept,
        fm["from_date"]:       datetime.now().strftime("%Y-%m-%d"),
        fm["from_location"]:   from_location,
        fm["to_name"]: "", fm["to_mobile"]: "", fm["to_email"]: "",
        fm["to_department"]: "", fm["to_date"]: "", fm["to_location"]: "",
    }
    specs = []
    office_val = str(device_row.get("Office", "")).strip()
    if not office_val and not is_unassigned and isinstance(emp_df, pd.DataFrame) and not emp_df.empty:
        r = _find_emp_row_by_name(emp_df, curr_owner)
        if r is not None:
            office_val = _get_emp_value(r, "Office", "Project", "Site")
    for label, v in [
        ("CPU", device_row.get("CPU","")),
        ("Memory", device_row.get("Memory","")),
        ("GPU", device_row.get("GPU","")),
        ("Hard Drive 1", device_row.get("Hard Drive 1","")),
        ("Hard Drive 2", device_row.get("Hard Drive 2","")),
        ("Screen Size", device_row.get("Screen Size","")),
        ("Office", office_val),
        ("Notes", device_row.get("Notes","")),
    ]:
        v = str(v).strip()
        if v:
            specs.append(f"{label}: {v}")
    specs_txt = " | ".join(specs)
    values.update({
        fm["eq_type"]:   device_row.get("Device Type",""),
        fm["eq_brand"]:  device_row.get("Brand",""),
        fm["eq_model"]:  device_row.get("Model",""),
        fm["eq_specs"]:  specs_txt,
        fm["eq_serial"]: device_row.get("Serial Number",""),
    })
    return values

def build_transfer_values(inv_row: pd.Series, new_owner: str, *, emp_df: pd.DataFrame) -> dict[str, str]:
    fm = _registration_field_map()
    values = {
        fm["from_name"]:       str(inv_row.get("Current user", "")),
        fm["from_mobile"]:     str(inv_row.get("Contact Number", "")),
        fm["from_email"]:      str(inv_row.get("Email Address", "")),
        fm["from_department"]: str(inv_row.get("Department", "")),
        fm["from_date"]:       datetime.now().strftime("%Y-%m-%d"),
        fm["from_location"]:   str(inv_row.get("Location", "")),
    }
    to_mobile = to_email = to_dept = to_loc = ""
    try:
        if isinstance(emp_df, pd.DataFrame) and not emp_df.empty:
            r = _find_emp_row_by_name(emp_df, new_owner)
            if r is not None:
                to_mobile = _get_emp_value(r, "Mobile Number", "Phone", "Mobile")
                to_email  = _get_emp_value(r, "Email", "E-mail")
                to_dept   = _get_emp_value(r, "Department", "Dept")
                to_loc    = _get_emp_value(r, "Location (KSA)", "Location", "City")
    except Exception:
        pass
    values.update({
        fm["to_name"]:       new_owner.strip(),
        fm["to_mobile"]:     to_mobile,
        fm["to_email"]:      to_email,
        fm["to_department"]: to_dept,
        fm["to_date"]:       datetime.now().strftime("%Y-%m-%d"),
        fm["to_location"]:   to_loc,
    })
    specs = []
    for label in ["CPU","Memory","GPU","Hard Drive 1","Hard Drive 2","Screen Size","Office","Notes"]:
        val = str(inv_row.get(label, "")).strip()
        if val:
            specs.append(f"{label}: {val}")
    specs_txt = " | ".join(specs)
    values.update({
        fm["eq_type"]:   str(inv_row.get("Device Type","")),
        fm["eq_brand"]:  str(inv_row.get("Brand","")),
        fm["eq_model"]:  str(inv_row.get("Model","")),
        fm["eq_specs"]:  specs_txt,
        fm["eq_serial"]: str(inv_row.get("Serial Number","")),
    })
    return values

# =============================================================================
# UI (header and tabs)
# =============================================================================
def render_header():
    c_title, c_user = st.columns([7, 3], gap="small")
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
        st.dataframe(df, use_container_width=True, hide_index=True)

# =========================
# Register Device Tab
# =========================
def register_device_tab():
    st.subheader("📝 Register New Device")

    # defaults
    st.session_state.setdefault("reg_email", "")
    st.session_state.setdefault("reg_contact", "")
    st.session_state.setdefault("reg_dept", "")
    st.session_state.setdefault("reg_location", "")
    st.session_state.setdefault("reg_office", "")
    st.session_state.setdefault("current_owner", UNASSIGNED_LABEL)

    emp_df = read_worksheet(EMPLOYEE_WS)
    employee_names = sorted({*unique_nonempty(emp_df, "New Employeer"), *unique_nonempty(emp_df, "Name")})
    owner_options = [UNASSIGNED_LABEL] + employee_names

    st.selectbox(
        "Current owner (at registration)",
        owner_options,
        index=owner_options.index(st.session_state["current_owner"])
            if st.session_state["current_owner"] in owner_options else 0,
        key="current_owner",
        on_change=_owner_changed,
        args=(emp_df,),
    )

    with st.form("register_device", clear_on_submit=False):
        r1c1, r1c2, r1c3 = st.columns(3)
        with r1c1: serial = st.text_input("Serial Number *")
        with r1c2: device = st.text_input("Device Type *")
        with r1c3: brand  = st.text_input("Brand")

        r2c1, r2c2, r2c3 = st.columns(3)
        with r2c1: model  = st.text_input("Model")
        with r2c2: cpu    = st.text_input("CPU")
        with r2c3: mem    = st.text_input("Memory")

        r3c1, r3c2, r3c3 = st.columns(3)
        with r3c1: hdd1 = st.text_input("Hard Drive 1")
        with r3c2: hdd2 = st.text_input("Hard Drive 2")
        with r3c3: gpu  = st.text_input("GPU")

        r4c1, r4c2, r4c3 = st.columns(3)
        with r4c1: screen = st.text_input("Screen Size")
        with r4c2: st.text_input("Email Address", key="reg_email")
        with r4c3: st.text_input("Contact Number", key="reg_contact")

        r5c1, r5c2, r5c3 = st.columns(3)
        with r5c1: st.text_input("Department", key="reg_dept")
        with r5c2: st.text_input("Location", key="reg_location")
        with r5c3: st.text_input("Office", key="reg_office")

        notes = st.text_area("Notes", height=80)

        st.divider()
        c_download = st.form_submit_button("Download register new device")

        st.markdown("**Signed ICT Equipment Form (PDF)**")
        pdf_file = st.file_uploader("Upload signed PDF", type=["pdf"], key="reg_pdf")
        submitted = st.form_submit_button("Save Device", type="primary")

    # Generate prefilled form
    if c_download:
        if not serial.strip() or not device.strip():
            st.error("Serial and Device Type required.")
        else:
            now_str = datetime.now().strftime(DATE_FMT)
            actor = st.session_state.get("username", "")
            row = {
                "Serial Number": serial.strip(),
                "Device Type": device.strip(),
                "Brand": brand.strip(), "Model": model.strip(), "CPU": cpu.strip(),
                "Hard Drive 1": hdd1.strip(), "Hard Drive 2": hdd2.strip(),
                "Memory": mem.strip(), "GPU": gpu.strip(), "Screen Size": screen.strip(),
                "Current user": st.session_state.get("current_owner", UNASSIGNED_LABEL).strip(),
                "Previous User": "", "TO": "",
                "Department": st.session_state.get("reg_dept","").strip(),
                "Email Address": st.session_state.get("reg_email","").strip(),
                "Contact Number": st.session_state.get("reg_contact","").strip(),
                "Location": st.session_state.get("reg_location","").strip(),
                "Office": st.session_state.get("reg_office","").strip(),
                "Notes": notes.strip(),
                "Date issued": now_str, "Registered by": actor,
            }
            tpl_bytes = _download_template_bytes_or_public(ICT_TEMPLATE_FILE_ID)
            reg_vals  = build_registration_values(row, actor_name=actor, emp_df=emp_df)
            filled    = fill_pdf_form(tpl_bytes, reg_vals, flatten=True)
            st.download_button("📄 Download ICT Registration Form", data=filled, file_name=_ict_filename(serial))

    if submitted:
        if not serial.strip() or not device.strip():
            st.error("Serial and Device Type required.")
            return
        pdf_file_obj = pdf_file or ss.get("reg_pdf")
        if pdf_file_obj is None:
            st.error("Signed ICT Registration PDF required.")
            return
        now_str = datetime.now().strftime(DATE_FMT)
        actor   = st.session_state.get("username", "")
        row = {
            "Serial Number": serial.strip(),
            "Device Type": device.strip(),
            "Brand": brand.strip(), "Model": model.strip(), "CPU": cpu.strip(),
            "Hard Drive 1": hdd1.strip(), "Hard Drive 2": hdd2.strip(),
            "Memory": mem.strip(), "GPU": gpu.strip(), "Screen Size": screen.strip(),
            "Current user": st.session_state.get("current_owner", UNASSIGNED_LABEL).strip(),
            "Previous User": "", "TO": "",
            "Department": st.session_state.get("reg_dept","").strip(),
            "Email Address": st.session_state.get("reg_email","").strip(),
            "Contact Number": st.session_state.get("reg_contact","").strip(),
            "Location": st.session_state.get("reg_location","").strip(),
            "Office": st.session_state.get("reg_office","").strip(),
            "Notes": notes.strip(),
            "Date issued": now_str, "Registered by": actor,
        }
        link, fid = upload_pdf_and_link(pdf_file_obj,
            prefix=f"device_{normalize_serial(serial)}",
            office="Head Office (HO)",
            city_code=row.get("Location", ""),
            action="Register"
        )
        if not fid:
            return
        is_admin = st.session_state.get("role") == "Admin"
        if is_admin:
            inv = read_worksheet(INVENTORY_WS)
            inv_out = pd.concat([inv, pd.DataFrame([row])], ignore_index=True)
            write_worksheet(INVENTORY_WS, inv_out)
            pending = {**row,
                "Approval Status": "Approved","Approval PDF": link,"Approval File ID": fid,
                "Submitted by": actor,"Submitted at": now_str,"Approver": actor,"Decision at": now_str,
            }
            append_to_worksheet(PENDING_DEVICE_WS, pd.DataFrame([pending]))
            st.success("✅ Device registered and approved.")
        else:
            pending = {**row,
                "Approval Status": "Pending","Approval PDF": link,"Approval File ID": fid,
                "Submitted by": actor,"Submitted at": now_str,"Approver": "","Decision at": "",
            }
            append_to_worksheet(PENDING_DEVICE_WS, pd.DataFrame([pending]))
            st.success("🕒 Submitted for admin approval.")

# (transfer_tab, approvals_tab, _approve_device_row, _approve_transfer_row, _reject_row)
# In these functions, after writing to Sheets, call:
#   move_drive_file(fid, "Head Office (HO)", city_code, "Register"/"Transfer", "Approved"/"Rejected")

# =============================================================================
# MAIN
# =============================================================================
def _config_check_ui():
    try:
        sa = _load_sa_info(); sa_email = sa.get("client_email", "(unknown)")
        st.caption(f"Service Account: {sa_email}")
    except Exception as e:
        st.error("Google Service Account credentials missing."); st.code(str(e)); st.stop()
    try:
        _ = get_sh()
    except Exception as e:
        st.error("Cannot open spreadsheet with Service Account."); st.code(str(e)); st.stop()

def run_app():
    if st.session_state.role == "Admin":
    tabs = st.tabs([
        "📇 View Employees","📝 Register Device",
        "📋 View Inventory","🔁 Transfer Device","📜 Transfer Log","✅ Approvals","⬇️ Export",
    ])
    with tabs[0]: employees_view_tab()
    with tabs[1]: register_device_tab()
    with tabs[2]: inventory_tab()
    with tabs[3]: transfer_tab()
    with tabs[4]: history_tab()
    with tabs[5]: approvals_tab()
    with tabs[6]: export_tab()

    else:
        tabs = st.tabs(["📝 Register Device","🔁 Transfer Device","📋 View Inventory","📜 Transfer Log"])
        with tabs[0]: register_device_tab()
        with tabs[1]: transfer_tab()
        with tabs[2]: inventory_tab()
        with tabs[3]: history_tab()

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
