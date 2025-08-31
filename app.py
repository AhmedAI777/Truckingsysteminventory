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
    "Register No.",
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
LOG_COLS = ["Transfer No.", "Device Type","Serial Number","From owner","To owner","Date issued","Registered by"]
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
# =============================================================================
# GOOGLE SHEETS & DRIVE
# =============================================================================
SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive",
]
OAUTH_SCOPES = ["https://www.googleapis.com/auth/drive.file"]
ALLOW_OAUTH_FALLBACK = st.secrets.get("drive", {}).get("allow_oauth_fallback", True)

# <-- PASTE THE FUNCTION HERE
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

def _ict_filename(serial: str, office: str = "HO", location: str = "JEDDAH", seq: str | None = None) -> str:
    office_clean = re.sub(r'[^A-Z0-9]', '', str(office).upper())
    location_clean = re.sub(r'[^A-Z0-9]', '', str(location).upper()[:3])
    sn = re.sub(r'[^A-Z0-9]', '', str(serial).upper())
    s = (seq or "XXXX")  # Use placeholder until counter reserved
    return f"{office_clean}-{location_clean}-REG-{sn}-{s}-{datetime.now().strftime('%Y%m%d')}.pdf"

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
# COUNTER HELPERS (patched)
# =============================================================================
def _reserve_counter_local(counter_type: str) -> str:
    df = read_worksheet("counters")
    if df.empty or counter_type not in df.get("Type", []):
        df = (pd.DataFrame([{"Type": counter_type, "LastUsed": 0}])
              if df.empty else pd.concat([df, pd.DataFrame([{"Type": counter_type, "LastUsed": 0}])], ignore_index=True))
    idx = df[df["Type"] == counter_type].index[0]
    last_used = int(df.loc[idx, "LastUsed"] or 0)
    next_val = last_used + 1
    df.loc[idx, "LastUsed"] = next_val
    write_worksheet("counters", df)
    return f"{next_val:04d}"

def reserve_counter(counter_type: str) -> str:
    url = st.secrets.get("gas", {}).get("counter_url")
    token = st.secrets.get("gas", {}).get("token")
    if url and token:
        try:
            r = requests.post(url, json={"type": counter_type, "token": token}, timeout=10)
            r.raise_for_status()
            js = r.json()
            nxt = str(js.get("next", "")).strip()
            if re.fullmatch(r"\d{4,}", nxt):
                return nxt.zfill(4)
        except Exception as e:
            st.warning(f"Counter service unavailable, using local fallback. ({e})")
    return _reserve_counter_local(counter_type)

def _drive_rename(file_id: str, new_name: str, drive_client=None) -> None:
    try:
        (drive_client or _get_drive()).files().update(
            fileId=file_id,
            body={"name": new_name},
            fields="id",
            supportsAllDrives=True
        ).execute()
    except Exception:
        pass

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
    """
    Matches 'Register and Transfer Device.pdf':
      From (6):   Text Field0..5
      To (6):     Text Field6..11
      Equip #1:   Text Field12..16
      Equip #2:   Text Field17..21
      Equip #3:   Text Field22..26
      Equip #4:   Text Field27..31

    We fill only Equipment #1 by default. Aliases (eq_type/brand/model/specs/serial)
    map to the first equipment block for convenience.
    """
    fm: dict[str, str] = {
        # ----- FROM header -----
        "from_name":       "Text Field0",
        "from_mobile":     "Text Field1",
        "from_email":      "Text Field2",
        "from_department": "Text Field3",
        "from_date":       "Text Field4",
        "from_location":   "Text Field5",

        # ----- TO header -----
        "to_name":         "Text Field6",
        "to_mobile":       "Text Field7",
        "to_email":        "Text Field8",
        "to_department":   "Text Field9",
        "to_date":         "Text Field10",
        "to_location":     "Text Field11",
    }

    # Equipment blocks 1..4
    for blk in range(4):
        base = 12 + blk * 5
        fm[f"eq{blk+1}_type"]   = f"Text Field{base}"
        fm[f"eq{blk+1}_brand"]  = f"Text Field{base+1}"
        fm[f"eq{blk+1}_model"]  = f"Text Field{base+2}"
        fm[f"eq{blk+1}_specs"]  = f"Text Field{base+3}"
        fm[f"eq{blk+1}_serial"] = f"Text Field{base+4}"

    # Aliases to Equipment #1 (used by build_* functions)
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

# =========================
# Helpers (place near others)
# =========================

def _find_emp_row_by_name(emp_df: pd.DataFrame, name: str) -> pd.Series | None:
    """Return first matching employee row by New Employeer or Name."""
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
    """Return first non-empty value among alias columns."""
    if row is None:
        return ""
    for col in aliases:
        v = row.get(col, "")
        if str(v).strip():
            return str(v)
    return ""

def _owner_changed(emp_df: pd.DataFrame):
    """Auto-fill Contact/Email/Department/Location/Office when owner changes."""
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
    """Try SA → OAuth (if configured) → public GET."""
    # 1) Service Account
    try:
        data = _drive_download_bytes(file_id)
        if data and data[:4] == b"%PDF":
            return data
    except Exception:
        pass
    # 2) OAuth user (optional)
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
    # 3) Public (anyone with link)
    data = _fetch_public_pdf_bytes(file_id, "")
    return data or b""

def build_registration_values(
    device_row: dict,
    *,
    actor_name: str,
    emp_df: pd.DataFrame | None = None
) -> dict[str, str]:
    """Build field map values for the registration PDF (TO kept blank)."""
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

    # Specs (include Office; if empty, try Project/Site alias)
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
    """Build field map values for the transfer PDF (FROM current, TO new)."""
    fm = _registration_field_map()
    # FROM (current owner)
    values = {
        fm["from_name"]:       str(inv_row.get("Current user", "")),
        fm["from_mobile"]:     str(inv_row.get("Contact Number", "")),
        fm["from_email"]:      str(inv_row.get("Email Address", "")),
        fm["from_department"]: str(inv_row.get("Department", "")),
        fm["from_date"]:       datetime.now().strftime("%Y-%m-%d"),
        fm["from_location"]:   str(inv_row.get("Location", "")),
    }
    # TO (new owner) with enrichment from Employees
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
    # Equipment specs from inventory row
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
# UI
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
# Full register_device_tab
# =========================
def register_device_tab():
    st.subheader("📝 Register New Device")

    # Safe defaults to avoid selectbox/index errors
    st.session_state.setdefault("reg_email", "")
    st.session_state.setdefault("reg_contact", "")
    st.session_state.setdefault("reg_dept", "")
    st.session_state.setdefault("reg_location", "")
    st.session_state.setdefault("reg_office", "")
    st.session_state.setdefault("current_owner", UNASSIGNED_LABEL)

    # Employees → owner options
    emp_df = read_worksheet(EMPLOYEE_WS)
    employee_names = sorted({*unique_nonempty(emp_df, "New Employeer"), *unique_nonempty(emp_df, "Name")})
    owner_options = [UNASSIGNED_LABEL] + employee_names

    # Owner selector OUTSIDE the form so it auto-fills instantly
    st.selectbox(
        "Current owner (at registration)",
        owner_options,
        index=owner_options.index(st.session_state["current_owner"])
            if st.session_state["current_owner"] in owner_options else 0,
        key="current_owner",
        on_change=_owner_changed,
        args=(emp_df,),
        help="Choosing an employee auto-fills Contact, Email, Department, Location, and Office."
    )

    # --- Form with two submit actions
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
        c_download = st.form_submit_button("Download register new device", use_container_width=True)

        st.markdown("**Signed ICT Equipment Form (PDF)** — required for submission")
        pdf_file = st.file_uploader("Drag & drop signed PDF here", type=["pdf"], key="reg_pdf")
        submitted = st.form_submit_button("Save Device", type="primary", use_container_width=True)

    # Tiny hint that a file is selected
    if ss.get("reg_pdf") is not None:
        st.toast("PDF selected. Click Save Device to submit.", icon="📄")

    # ---- Optional preview of uploaded PDF (opt-in to avoid UI lag with large files)
    preview_pdf = st.checkbox("Preview uploaded PDF (may be slow for large files)", value=False)
    if preview_pdf and ss.get("reg_pdf"):
        ss.reg_pdf_ref = ss.reg_pdf
        try:
            # Guard: don't try to render >8MB to keep UI snappy
            if getattr(ss.reg_pdf_ref, "size", 0) and ss.reg_pdf_ref.size > 8 * 1024 * 1024:
                st.info("PDF is large; preview disabled to avoid lag. You can still submit.")
            else:
                st.caption("Preview: Uploaded signed PDF")
                pdf_viewer(input=ss.reg_pdf_ref.getvalue(), width=700, key="viewer_reg")
        except Exception as e:
            st.warning(f"Preview failed: {e}")

    # --- Generate pre-filled PDF (TO blank)
    if c_download:
        if not serial.strip() or not device.strip():
            st.error("Serial Number and Device Type are required.")
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
            try:
                tpl_bytes = _download_template_bytes_or_public(ICT_TEMPLATE_FILE_ID)
                if not tpl_bytes:
                    sa_email = ""
                    try:
                        sa_email = _load_sa_info().get("client_email","")
                    except Exception:
                        pass
                    raise RuntimeError(
                        f"Template not reachable. Share file ID {ICT_TEMPLATE_FILE_ID} with {sa_email}, "
                        "or enable public access / OAuth fallback."
                    )
                reg_vals  = build_registration_values(row, actor_name=actor, emp_df=emp_df)
                filled    = fill_pdf_form(tpl_bytes, reg_vals, flatten=True)
                st.success("Registration form generated. Sign it and upload below, then click Save Device.")
                st.download_button(
                    "📄 Download ICT Registration Form (pre-filled, TO blank)",
                    data=filled, file_name=_ict_filename(serial), mime="application/pdf",
                )
            except Exception as e:
                st.error("Could not generate the registration PDF.")
                st.caption(str(e))

    # --- Save (PDF required for all roles)
    if submitted:
        if not serial.strip() or not device.strip():
            st.error("Serial Number and Device Type are required.")
            return

        # Prefer the widget variable, fall back to session_state to be safe
        pdf_file_obj = pdf_file or ss.get("reg_pdf")
        if pdf_file_obj is None:
            st.error("Signed ICT Registration PDF is required for submission.")
            return

        s_norm = normalize_serial(serial)
        if not s_norm:
            st.error("Serial Number cannot be blank after normalization.")
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

        with st.status("Uploading signed PDF…", expanded=True) as status:
            try:
                status.write(f"File: {getattr(pdf_file_obj,'name','(no name)')} "
                             f"| MIME: {getattr(pdf_file_obj,'type','(unknown)')} "
                             f"| Size: {getattr(pdf_file_obj,'size',0)} bytes")

                status.write("Sending to Google Drive…")
                link, fid = upload_pdf_and_link(pdf_file_obj, prefix=f"device_{s_norm}")
                if not fid:
                    status.update(label="Upload failed", state="error")
                    st.error("Upload failed. Please check your Drive settings and try again.")
                    return

                status.write("Upload complete. Writing to Sheets…")
                is_admin = st.session_state.get("role") == "Admin"
                if is_admin:
                    inv = read_worksheet(INVENTORY_WS)
                    inv_out = pd.concat(
                        [inv if not inv.empty else pd.DataFrame(columns=INVENTORY_COLS), pd.DataFrame([row])],
                        ignore_index=True
                    )
                    inv_out = reorder_columns(inv_out, INVENTORY_COLS)
                    write_worksheet(INVENTORY_WS, inv_out)

                    pending = {
                        **row,
                        "Approval Status": "Approved",
                        "Approval PDF": link,
                        "Approval File ID": fid,
                        "Submitted by": actor,
                        "Submitted at": now_str,
                        "Approver": actor,
                        "Decision at": now_str,
                    }
                    append_to_worksheet(PENDING_DEVICE_WS, pd.DataFrame([pending]))
                    status.update(label="Saved to Sheets", state="complete")
                    st.success("✅ Device registered and added to Inventory. Signed PDF stored.")
                else:
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
                    status.update(label="Submitted for approval", state="complete")
                    st.success("🕒 Submitted for admin approval. You'll see it in Inventory once approved.")
            except Exception as e:
                status.update(label="Error during upload/save", state="error")
                st.error("An error occurred while uploading or saving.")
                st.caption(str(e))

def transfer_tab():
    st.subheader("🔁 Transfer Device")
    inventory_df = read_worksheet(INVENTORY_WS)
    if inventory_df.empty:
        st.warning("Inventory is empty.")
        return

    serial_list = sorted(inventory_df["Serial Number"].dropna().astype(str).unique().tolist())
    serial = st.selectbox("Serial Number", ["— Select —"] + serial_list)
    chosen_serial = None if serial == "— Select —" else serial

    emp_df = read_worksheet(EMPLOYEE_WS)
    employee_names = sorted({*unique_nonempty(emp_df, "New Employeer"), *unique_nonempty(emp_df, "Name")})
    new_owner = st.selectbox("New Owner (from Employees)", ["— Select —"] + employee_names)
    new_owner = "" if new_owner == "— Select —" else new_owner

    pdf_file = st.file_uploader("Signed ICT Transfer Form (PDF)", type=["pdf"], key="transfer_pdf")

    # Pre-filled transfer PDF (FROM current, TO new) — flattened
    if chosen_serial and new_owner:
        match = inventory_df[inventory_df["Serial Number"].astype(str) == chosen_serial]
        if not match.empty:
            inv_row = match.iloc[0]
            try:
                # More resilient if you prefer: _download_template_bytes_or_public(TRANSFER_TEMPLATE_FILE_ID)
                tpl_bytes = _drive_download_bytes(TRANSFER_TEMPLATE_FILE_ID)
                tr_vals   = build_transfer_values(inv_row, new_owner, emp_df=emp_df)
                filled    = fill_pdf_form(tpl_bytes, tr_vals, flatten=True)
                st.download_button(
                    "📄 Download ICT Transfer Form (pre-filled)",
                    data=filled, file_name=_transfer_filename(chosen_serial), mime="application/pdf",
                    help="Sign, then upload the signed PDF above."
                )
            except Exception as e:
                st.warning("Could not generate transfer form. Check drive.transfer_template_file_id or PDF fields.")
                st.caption(str(e))

    # Optional live preview
    if ss.get("transfer_pdf"):
        ss.transfer_pdf_ref = ss.transfer_pdf
    if ss.transfer_pdf_ref:
        st.caption("Preview: Uploaded signed Transfer PDF")
        try:
            pdf_viewer(input=ss.transfer_pdf_ref.getvalue(), width=700, key="viewer_trans")
        except Exception:
            pass

    is_admin = st.session_state.get("role") == "Admin"
    do_transfer = st.button("Transfer Now" if is_admin else "Submit Transfer for Approval", type="primary",
                            disabled=not (chosen_serial and new_owner))

    if do_transfer:
        if pdf_file is None:
            st.error("Signed ICT Transfer PDF is required for submission.")
            return

        match = inventory_df[inventory_df["Serial Number"].astype(str) == chosen_serial]
        if match.empty:
            st.warning("Serial number not found.")
            return
        idx = match.index[0]
        prev_user = str(inventory_df.loc[idx, "Current user"] or "")
        now_str   = datetime.now().strftime(DATE_FMT)
        actor     = st.session_state.get("username", "")

        link, fid = upload_pdf_and_link(pdf_file, prefix=f"transfer_{normalize_serial(chosen_serial)}")
        if not fid:
            return

        if is_admin:
            # Apply transfer immediately
            inventory_df.loc[idx, "Previous User"] = prev_user
            inventory_df.loc[idx, "Current user"]  = new_owner.strip()
            inventory_df.loc[idx, "TO"]            = new_owner.strip()
            inventory_df.loc[idx, "Date issued"]   = now_str
            inventory_df.loc[idx, "Registered by"] = actor
            write_worksheet(INVENTORY_WS, inventory_df)

            log_row = {
                "Device Type": inventory_df.loc[idx, "Device Type"],
                "Serial Number": chosen_serial, "From owner": prev_user,
                "To owner": new_owner.strip(), "Date issued": now_str, "Registered by": actor,
            }
            append_to_worksheet(TRANSFERLOG_WS, pd.DataFrame([log_row]))

            # Audit trail in pending sheet as Approved
            pend = {
                "Device Type": inventory_df.loc[idx, "Device Type"],
                "Serial Number": chosen_serial,
                "From owner": prev_user, "To owner": new_owner.strip(),
                "Date issued": now_str, "Registered by": actor,
                "Approval Status": "Approved", "Approval PDF": link, "Approval File ID": fid,
                "Submitted by": actor, "Submitted at": now_str, "Approver": actor, "Decision at": now_str,
            }
            append_to_worksheet(PENDING_TRANSFER_WS, pd.DataFrame([pend]))
            st.success(f"✅ Transfer applied. Signed PDF stored. {prev_user or '(blank)'} → {new_owner.strip()}")
        else:
            pend = {
                "Device Type": inventory_df.loc[idx, "Device Type"],
                "Serial Number": chosen_serial,
                "From owner": prev_user, "To owner": new_owner.strip(),
                "Date issued": now_str, "Registered by": actor,
                "Approval Status": "Pending", "Approval PDF": link, "Approval File ID": fid,
                "Submitted by": actor, "Submitted at": now_str, "Approver": "", "Decision at": "",
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

    with st.form("register_employee", clear_on_submit=True):
        r1c1, r1c2, r1c3 = st.columns(3)
        with r1c1: emp_name = st.text_input("New Employeer *")
        with r1c2: emp_id   = st.text_input("Employee ID", help=f"Suggested next ID: {next_id_suggestion}")
        with r1c3: new_sig  = st.selectbox("New Signature", ["— Select —", "Yes", "No", "Requested"])

        r2c1, r2c2 = st.columns(2)
        with r2c1: Email  = st.text_input("Email")
        with r2c2: active = st.selectbox("Active", ["Active", "Inactive", "Onboarding", "Resigned"])

        r3c1, r3c2, r3c3 = st.columns(3)
        with r3c1: position = st.text_input("Position")
        with r3c2: department = st.text_input("Department")
        with r3c3: location_ksa = st.text_input("Location (KSA)")

        r4c1, r4c2, r4c3 = st.columns(3)
        with r4c1: project = st.text_input("Project")
        with r4c2: teams   = st.selectbox("Microsoft Teams", ["— Select —", "Yes", "No", "Requested"])
        with r4c3: mobile  = st.text_input("Mobile Number")

        submitted = st.form_submit_button("Save Employee", type="primary")

    if submitted:
        if not emp_name.strip():
            st.error("New Employeer is required.")
            return
        if emp_id.strip() and not emp_df.empty and emp_id.strip() in emp_df["Employee ID"].astype(str).values:
            st.error(f"Employee ID '{emp_id}' already exists.")
            return
        row = {
            "New Employeer": emp_name.strip(), "Name": emp_name.strip(),
            "Employee ID": emp_id.strip() if emp_id.strip() else next_id_suggestion,
            "New Signature": new_sig if new_sig != "— Select —" else "",
            "Email": Email.strip(), "Active": active.strip(), "Position": position.strip(),
            "Department": department.strip(), "Location (KSA)": location_ksa.strip(),
            "Project": project.strip(), "Microsoft Teams": teams if teams != "— Select —" else "",
            "Mobile Number": mobile.strip(),
        }
        new_df = pd.concat([emp_df, pd.DataFrame([row])], ignore_index=True) if not emp_df.empty else pd.DataFrame([row])
        new_df = reorder_columns(new_df, EMPLOYEE_CANON_COLS); write_worksheet(EMPLOYEE_WS, new_df)
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
                    info = {k: row.get(k, "") for k in INVENTORY_COLS}; st.json(info)
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
                    reviewed = st.checkbox("I reviewed the attached PDF", key=f"review_dev_{i}") if REQUIRE_REVIEW_CHECK else True
                    a_col, r_col = st.columns(2)
                    if a_col.button("Approve", key=f"approve_dev_{i}", disabled=not reviewed):
                        _approve_device_row(row)
                    if r_col.button("Reject", key=f"reject_dev_{i}"):
                        _reject_row(PENDING_DEVICE_WS, i, row)

    st.markdown("---"); st.markdown("### Pending Transfers")
    df_tr = pending_tr[pending_tr["Approval Status"].isin(["", "Pending"])].reset_index(drop=True)
    if df_tr.empty:
        st.success("No pending transfers.")
    else:
        for i, row in df_tr.iterrows():
            with st.expander(f"SN {row['Serial Number']}: {row['From owner']} → {row['To owner']} (by {row['Submitted by']})", expanded=False):
                c1, c2 = st.columns([3,2])
                with c1:
                    info = {k: row.get(k, "") for k in LOG_COLS}; st.json(info)
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
                    reviewed = st.checkbox("I reviewed the attached PDF", key=f"review_tr_{i}") if REQUIRE_REVIEW_CHECK else True
                    a_col, r_col = st.columns(2)
                    if a_col.button("Approve", key=f"approve_tr_{i}", disabled=not reviewed):
                        _approve_transfer_row(row)
                    if r_col.button("Reject", key=f"reject_tr_{i}"):
                        _reject_row(PENDING_TRANSFER_WS, i, row)

def _approve_device_row(row: pd.Series):
    inv = read_worksheet(INVENTORY_WS)
    now_str = datetime.now().strftime(DATE_FMT); approver = st.session_state.get("username", "")
    new_row = {k: row.get(k, "") for k in INVENTORY_COLS}
    new_row["Registered by"] = approver or new_row.get("Registered by", ""); new_row["Date issued"] = now_str
    inv_out = pd.concat([inv if not inv.empty else pd.DataFrame(columns=INVENTORY_COLS),
                         pd.DataFrame([new_row])], ignore_index=True)
    write_worksheet(INVENTORY_WS, inv_out)
    _mark_decision(PENDING_DEVICE_WS, row, status="Approved"); st.success("✅ Device approved and added to Inventory.")

def _approve_transfer_row(row: pd.Series):
    inv = read_worksheet(INVENTORY_WS)
    if inv.empty:
        st.error("Inventory is empty; cannot apply transfer.")
        return
    sn = str(row.get("Serial Number", "")); match = inv[inv["Serial Number"].astype(str) == sn]
    if match.empty:
        st.error("Serial not found in Inventory.")
        return
    idx = match.index[0]
    now_str = datetime.now().strftime(DATE_FMT); approver = st.session_state.get("username", "")
    prev_user = str(inv.loc[idx, "Current user"] or "")
    inv.loc[idx, "Previous User"] = prev_user
    inv.loc[idx, "Current user"]  = str(row.get("To owner", ""))
    inv.loc[idx, "TO"]            = str(row.get("To owner", ""))
    inv.loc[idx, "Date issued"]   = now_str
    inv.loc[idx, "Registered by"] = approver
    write_worksheet(INVENTORY_WS, inv)
    log_row = {k: row.get(k, "") for k in LOG_COLS}; log_row["Date issued"] = now_str; log_row["Registered by"] = approver
    append_to_worksheet(TRANSFERLOG_WS, pd.DataFrame([log_row]))
    _mark_decision(PENDING_TRANSFER_WS, row, status="Approved"); st.success("✅ Transfer approved and applied.")

def _mark_decision(ws_title: str, row: pd.Series, *, status: str):
    df = read_worksheet(ws_title)
    key_cols = [c for c in ["Serial Number","Submitted at","Submitted by","To owner"] if c in df.columns]
    mask = pd.Series([True] * len(df))
    for c in key_cols:
        mask &= df[c].astype(str) == str(row.get(c, ""))
    if not mask.any() and "Serial Number" in df.columns:
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
    df = read_worksheet(ws_title)
    key_cols = [c for c in ["Serial Number","Submitted at","Submitted by","To owner"] if c in df.columns]
    mask = pd.Series([True] * len(df))
    for c in key_cols:
        mask &= df[c].astype(str) == str(row.get(c, ""))
    idxs = df[mask].index.tolist()
    if not idxs and "Serial Number" in df.columns:
        idxs = df[df["Serial Number"].astype(str) == str(row.get("Serial Number",""))].index.tolist()
    if not idxs:
        return
    idx = idxs[0]
    df.loc[idx, "Approval Status"] = "Rejected"
    df.loc[idx, "Approver"] = st.session_state.get("username","")
    df.loc[idx, "Decision at"] = datetime.now().strftime(DATE_FMT)
    write_worksheet(ws_title, df)
    st.success("❌ Request rejected.")

def export_tab():
    st.subheader("⬇️ Export (always fresh)")
    inv = read_worksheet(INVENTORY_WS); log = read_worksheet(TRANSFERLOG_WS); emp = read_worksheet(EMPLOYEE_WS)
    st.caption(f"Last fetched: {datetime.now().strftime(DATE_FMT)}")
    c1, c2, c3 = st.columns(3)
    with c1: st.download_button("Inventory CSV", inv.to_csv(index=False).encode("utf-8"), "inventory.csv", "text/csv")
    with c2: st.download_button("Transfer Log CSV", log.to_csv(index=False).encode("utf-8"), "transfer_log.csv", "text/csv")
    with c3: st.download_button("Employees CSV", emp.to_csv(index=False).encode("utf-8"), "employees.csv", "text/csv")

# =============================================================================
# UPLOAD: accept octet-stream and show real errors/progress
# =============================================================================
def upload_pdf_and_link(uploaded_file, *, prefix: str) -> Tuple[str, str]:
    """Upload PDF to Drive. Try SA first; on 403 storage quota, fall back to OAuth user (My Drive)."""
    if uploaded_file is None:
        st.error("No file selected.")
        return "", ""

    # Accept common PDF MIME types
    allowed = {
        "application/pdf",
        "application/x-pdf",
        "application/octet-stream",   # browsers often use this
        "binary/octet-stream",
    }
    mime = getattr(uploaded_file, "type", "") or ""
    name = getattr(uploaded_file, "name", "file.pdf")

    # Read bytes once
    try:
        data = uploaded_file.getvalue()
    except Exception as e:
        st.error(f"Failed reading the uploaded file: {e}")
        return "", ""

    if not data:
        st.error("Uploaded file is empty.")
        return "", ""

    # Light PDF validation
    is_pdf_magic = data[:4] == b"%PDF"
    looks_like_pdf = name.lower().endswith(".pdf") or is_pdf_magic
    if mime not in allowed and not looks_like_pdf:
        st.error(f"Only PDF files are allowed. Got type '{mime}' and name '{name}'.")
        return "", ""
    if not is_pdf_magic:
        st.warning("File doesn't start with %PDF header—but continuing. If Drive rejects it, please re-export the PDF.")

    fname = f"{prefix}_{int(time.time())}.pdf"
    folder_id = st.secrets.get("drive", {}).get("approvals", "")
    metadata = {"name": fname}
    if folder_id:
        metadata["parents"] = [folder_id]

    media = MediaIoBaseUpload(io.BytesIO(data), mimetype="application/pdf", resumable=False)

    drive_cli = _get_drive()
    try:
        file = drive_cli.files().create(
            body=metadata, media_body=media, fields="id, webViewLink", supportsAllDrives=True,
        ).execute()
    except HttpError as e:
        # If SA quota exceeded, optionally fall back to OAuth
        if e.resp.status == 403 and "storageQuotaExceeded" in str(e):
            if not ALLOW_OAUTH_FALLBACK:
                st.error("Service Account quota exceeded and OAuth fallback disabled.")
                return "", ""
            try:
                drive_cli = _get_user_drive()
                file = drive_cli.files().create(
                    body=metadata, media_body=media, fields="id, webViewLink", supportsAllDrives=False,
                ).execute()
            except Exception as e2:
                st.error(f"OAuth upload failed: {e2}")
                return "", ""
        else:
            st.error(f"Drive upload failed: {e}")
            return "", ""
    except Exception as e:
        st.error(f"Unexpected error uploading to Drive: {e}")
        return "", ""

    file_id = file.get("id", ""); link = file.get("webViewLink", "")
    if not file_id:
        st.error("Drive did not return a file id.")
        return "", ""

    # Make public if configured (ignore failures)
    try:
        if st.secrets.get("drive", {}).get("public", True):
            _drive_make_public(file_id, drive_client=drive_cli)
    except Exception:
        pass

    return link, file_id

# =============================================================================
# MAIN
# =============================================================================
def _config_check_ui():
    try:
        sa = _load_sa_info(); sa_email = sa.get("client_email", "(unknown)")
        st.caption(f"Service Account: {sa_email}")
    except Exception as e:
        st.error("Google Service Account credentials are missing."); st.code(str(e))
        st.stop()
    try:
        _ = get_sh()
    except Exception as e:
        st.error("Cannot open the spreadsheet with the configured Service Account."); st.code(str(e)); st.stop()

def run_app():
    render_header(); _config_check_ui()
    if st.session_state.role == "Admin":
        tabs = st.tabs([
            "🧑‍💼 Employee Register","📇 View Employees","📝 Register Device",
            "📋 View Inventory","🔁 Transfer Device","📜 Transfer Log","✅ Approvals","⬇️ Export",
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

# Entry
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
