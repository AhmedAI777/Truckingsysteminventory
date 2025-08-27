# ============================================
# Part 1: Imports, Config, Auth, Google Setup
# ============================================

import os
import re
import io
import json
import hmac
import time
import glob
import base64
import zipfile
import hashlib
import requests
from datetime import datetime, timedelta
from typing import Tuple, Optional

import pandas as pd
import streamlit as st
import extra_streamlit_components as stx
from streamlit import session_state as ss
from streamlit_pdf_viewer import pdf_viewer
from streamlit_drawable_canvas import st_canvas
from PIL import Image
from pypdf import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.utils import ImageReader

import gspread
from gspread_dataframe import set_with_dataframe
from google.oauth2.service_account import Credentials
from google.oauth2.credentials import Credentials as UserCredentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload, MediaIoBaseDownload
from googleapiclient.errors import HttpError

# ======================
# STREAMLIT PAGE CONFIG
# ======================
st.set_page_config(page_title="Tracking Inventory Management System", layout="wide")

APP_TITLE = "Tracking Inventory Management System"
SUBTITLE = "Advanced Construction"
DATE_FMT = "%Y-%m-%d %H:%M:%S"
SESSION_TTL_DAYS = 30
SESSION_TTL_SECONDS = SESSION_TTL_DAYS * 24 * 60 * 60
COOKIE_NAME = "ac_auth_v2"

# Google Sheets default URL
SHEET_URL_DEFAULT = "https://docs.google.com/spreadsheets/d/1SHp6gOW4ltsyOT41rwo85e_LELrHkwSwKN33K6XNHFI/edit"

# Template (local file in repo)
TEMPLATE_PATH = "forms/Register and Transfer Device.pdf"

# Folder structure & worksheet names
INVENTORY_WS = "truckinventory"
TRANSFERLOG_WS = "transfer_log"
EMPLOYEE_WS = "mainlists"
PENDING_DEVICE_WS = "pending_device_reg"
PENDING_TRANSFER_WS = "pending_transfers"

# Inventory Columns
INVENTORY_COLS = [
    "Serial Number","Device Type","Brand","Model","CPU",
    "Hard Drive 1","Hard Drive 2","Memory","GPU","Screen Size",
    "Current user","Previous User","TO","Department","Email Address",
    "Contact Number","Location","Office","Notes","Date issued","Registered by"
]

# Transfer Log Columns
LOG_COLS = ["Device Type","Serial Number","From owner","To owner","Date issued","Registered by"]

# Employee Columns
EMPLOYEE_CANON_COLS = [
    "New Employeer","Employee ID","New Signature","Name","Address",
    "Active","Position","Department","Location (KSA)",
    "Project","Microsoft Teams","Mobile Number"
]

# Meta Columns for approvals
APPROVAL_META_COLS = [
    "Approval Status","Approval PDF","Approval File ID",
    "Submitted by","Submitted at","Approver","Decision at"
]

PENDING_DEVICE_COLS = INVENTORY_COLS + APPROVAL_META_COLS
PENDING_TRANSFER_COLS = LOG_COLS + APPROVAL_META_COLS

UNASSIGNED_LABEL = "Unassigned (Stock)"
REQUIRE_REVIEW_CHECK = True

# Cookie Manager
COOKIE_MGR = stx.CookieManager(key="ac_cookie_mgr")

# Pre-init session keys for signature previews
for k in ("reg_sig_owner", "transfer_sig_owner"):
    if k not in ss:
        ss[k] = None

# =====================
# AUTH: Load from secrets
# =====================
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
    exp = iat + SESSION_TTL_SECONDS
    payload = {"u": username, "r": role, "iat": iat, "exp": exp, "v": 1}
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    token = base64.urlsafe_b64encode(raw).decode() + "." + _sign(raw)
    COOKIE_MGR.set(COOKIE_NAME, token, expires_at=datetime.utcnow() + timedelta(seconds=SESSION_TTL_SECONDS), secure=True)

def _read_cookie():
    token = COOKIE_MGR.get(COOKIE_NAME)
    if not token:
        return None
    try:
        data_b64, sig = token.split(".", 1)
        raw = base64.urlsafe_b64decode(data_b64.encode())
        if not _verify_sig(sig, raw):
            return None
        payload = json.loads(raw.decode())
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        return payload
    except Exception:
        return None

def do_login(username: str, role: str):
    st.session_state.authenticated = True
    st.session_state.username = username
    st.session_state.role = role
    st.session_state.just_logged_out = False
    _issue_session_cookie(username, role)
    st.rerun()

def do_logout():
    COOKIE_MGR.delete(COOKIE_NAME)
    st.session_state.clear()
    st.session_state.just_logged_out = True
    st.rerun()

if "cookie_bootstrapped" not in st.session_state:
    st.session_state.cookie_bootstrapped = True
    _ = COOKIE_MGR.get_all()
    st.rerun()

# =====================
# GOOGLE API Setup
# =====================
SCOPES = ["https://www.googleapis.com/auth/spreadsheets", "https://www.googleapis.com/auth/drive"]
OAUTH_SCOPES = ["https://www.googleapis.com/auth/drive.file"]

def _load_sa_info() -> dict:
    raw = st.secrets.get("gcp_service_account", {})
    sa: dict = raw if isinstance(raw, dict) else json.loads(raw)
    pk = sa.get("private_key", "")
    if "\\n" in pk:
        sa["private_key"] = pk.replace("\\n", "\\n")
    return sa

@st.cache_resource
def _get_creds():
    return Credentials.from_service_account_info(_load_sa_info(), scopes=SCOPES)

@st.cache_resource
def _get_gc():
    return gspread.authorize(_get_creds())

@st.cache_resource
def _get_drive():
    return build("drive", "v3", credentials=_get_creds())

def get_sh():
    gc = _get_gc()
    return gc.open_by_url(st.secrets.get("sheets", {}).get("url", SHEET_URL_DEFAULT))


# ============================================
# Part 2: PDF Generation + Signature Overlay
# ============================================

def render_pdf_from_template(template_path: str, field_map: dict, owner_sig=None, admin_sig=None) -> bytes:
    """
    Fill a PDF template with data and optional signatures.
    Args:
        template_path: path to the blank template
        field_map: dict with keys (business fields) -> text values
        owner_sig: bytes of owner signature image (PNG)
        admin_sig: bytes of admin signature image (PNG)
    Returns:
        PDF as bytes
    """
    # Load template
    reader = PdfReader(open(template_path, "rb"))
    page = reader.pages[0]
    width, height = page.mediabox.width, page.mediabox.height

    # Create overlay canvas
    overlay_stream = io.BytesIO()
    c = canvas.Canvas(overlay_stream, pagesize=(width, height))
    c.setFont("Helvetica", 10)

    # Default coordinates (adjust for your template)
    coords = {
        "Name": (60, 780),
        "Mobile": (300, 780),
        "Email": (60, 760),
        "Department": (300, 760),
        "Date": (60, 740),
        "Project": (300, 740),
        "From": (60, 720),
        "To": (300, 720),
        "Device Type": (60, 680),
        "Brand": (150, 680),
        "Model": (240, 680),
        "Specs": (60, 660),
        "Serial": (60, 640),
    }

    # Draw text values
    for label, (x, y) in coords.items():
        val = field_map.get(label, "")
        if val:
            c.drawString(x, y, str(val))

    # Owner signature
    if owner_sig:
        img_owner = ImageReader(io.BytesIO(owner_sig))
        c.drawImage(img_owner, 60, 580, width=100, height=30, mask="auto")

    # Admin signature
    if admin_sig:
        img_admin = ImageReader(io.BytesIO(admin_sig))
        c.drawImage(img_admin, 300, 580, width=100, height=30, mask="auto")

    c.save()
    overlay_stream.seek(0)

    # Merge overlay onto template
    writer = PdfWriter()
    base_page = reader.pages[0]
    overlay_pdf = PdfReader(overlay_stream)
    base_page.merge_page(overlay_pdf.pages[0])
    writer.add_page(base_page)

    out_buf = io.BytesIO()
    writer.write(out_buf)
    out_buf.seek(0)
    return out_buf.read()


def build_field_map_for_register(form_data: dict) -> dict:
    """Map register form data to PDF labels"""
    return {
        "Name": form_data.get("assigned_to", ""),
        "Mobile": form_data.get("contact", ""),
        "Email": form_data.get("email", ""),
        "Department": form_data.get("department", ""),
        "Date": datetime.now().strftime("%Y-%m-%d"),
        "Project": form_data.get("location", ""),
        "From": "IT",
        "To": form_data.get("assigned_to", ""),
        "Device Type": form_data.get("device", ""),
        "Brand": form_data.get("brand", ""),
        "Model": form_data.get("model", ""),
        "Specs": f"{form_data.get('cpu','')}/{form_data.get('mem','')}/{form_data.get('hdd1','')}/{form_data.get('hdd2','')}/{form_data.get('gpu','')}/{form_data.get('screen','')}",
        "Serial": form_data.get("serial", ""),
    }


def build_field_map_for_transfer(device_row: pd.Series, new_owner: str) -> dict:
    """Map transfer data to PDF labels"""
    return {
        "Name": new_owner,
        "Mobile": device_row.get("Contact Number", ""),
        "Email": device_row.get("Email Address", ""),
        "Department": device_row.get("Department", ""),
        "Date": datetime.now().strftime("%Y-%m-%d"),
        "Project": device_row.get("Location", ""),
        "From": device_row.get("Current user", ""),
        "To": new_owner,
        "Device Type": device_row.get("Device Type", ""),
        "Brand": device_row.get("Brand", ""),
        "Model": device_row.get("Model", ""),
        "Specs": f"{device_row.get('CPU','')}/{device_row.get('Memory','')}/{device_row.get('Hard Drive 1','')}/{device_row.get('Hard Drive 2','')}/{device_row.get('GPU','')}/{device_row.get('Screen Size','')}",
        "Serial": device_row.get("Serial Number", ""),
    }

# ============================================
# Part 3: Google Sheets & Drive Helpers + Utils
# ============================================

# ---- Header normalization (optional but helpful) ----
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

# ---- Display name helpers for Drive folder tree ----
def _proj_display_name(code: str) -> str:
    code = (code or "").upper()
    mapping = {"HO": "Head Office (HO)", "ST": "Site (ST)", "FIN": "Finance (FIN)", "IT": "IT (IT)"}
    return mapping.get(code, f"{code} ({code})" if code else "Unknown")

def _city_display_name(code: str) -> str:
    code = (code or "").upper()
    mapping = {"RUH": "Riyadh (RUH)", "JED": "Jeddah (JED)", "TIF": "Taif (TIF)", "MED": "Madinah (MED)"}
    return mapping.get(code, f"{code} ({code})" if code else "Unknown")

def _type_display_name(type_code: str) -> str:
    return "Register" if (type_code or "").upper() == "REG" else "Transfer"

# ---- Drive helpers ----
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

def _get_drive_client_for_writes():
    # prefer service account; if it fails in your environment you can add a user-OAuth fallback later
    try:
        return _get_drive()
    except Exception:
        return _get_drive()

def _find_child_folder_id(parent_id: str, name: str) -> Optional[str]:
    if not parent_id or not name:
        return None
    drive = _get_drive_client_for_writes()
    q = (
        f"'{parent_id}' in parents and "
        f"name='{name}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
    )
    res = drive.files().list(
        q=q, spaces="drive", fields="files(id,name)",
        supportsAllDrives=True, includeItemsFromAllDrives=True
    ).execute()
    files = res.get("files", [])
    return files[0]["id"] if files else None

def _create_child_folder(parent_id: str, name: str) -> str:
    drive = _get_drive_client_for_writes()
    meta = {"name": name, "mimeType": "application/vnd.google-apps.folder", "parents": [parent_id]}
    folder = drive.files().create(body=meta, fields="id", supportsAllDrives=True).execute()
    return folder["id"]

def _ensure_child_folder(parent_id: str, name: str) -> str:
    fid = _find_child_folder_id(parent_id, name)
    return fid or _create_child_folder(parent_id, name)

def _approvals_root_id_from_secrets() -> str:
    cfg = st.secrets.get("drive", {})
    return cfg.get("approvals_root_id") or cfg.get("approvals_folder_id") or cfg.get("approvals") or ""

def ensure_folder_tree(project_code: str, city_code: str, type_code: str, status: Optional[str] = None) -> str:
    """
    Approvals/
      Head Office (HO)/ or Site (ST)/
        Riyadh (RUH)/
          Register/ or Transfer/
            [Pending | Approved | Rejected]
    """
    root_id = _approvals_root_id_from_secrets()
    if not root_id:
        st.error("[drive] approvals_root_id/approvals_folder_id not configured in secrets.")
        return ""

    pid = _ensure_child_folder(root_id, _proj_display_name(project_code))
    cid = _ensure_child_folder(pid, _city_display_name(city_code))
    tid = _ensure_child_folder(cid, _type_display_name(type_code))
    if status:
        sid = _ensure_child_folder(tid, status)
        return sid
    return tid

def move_drive_file(file_id: str, new_parent_id: str):
    if not file_id or not new_parent_id:
        return
    drive = _get_drive_client_for_writes()
    f = drive.files().get(fileId=file_id, fields="parents", supportsAllDrives=True).execute()
    prev_parents = ",".join(f.get("parents", []))
    drive.files().update(
        fileId=file_id,
        addParents=new_parent_id,
        removeParents=prev_parents,
        fields="id, parents",
        supportsAllDrives=True,
    ).execute()

def _is_pdf_bytes(data: bytes) -> bool:
    return isinstance(data, (bytes, bytearray)) and data[:4] == b"%PDF"

def upload_pdf_bytes_and_link(data: bytes, *, prefix: str, parent_folder_id: Optional[str] = None) -> Tuple[str, str]:
    """Upload generated PDF bytes and return (link, file_id)."""
    if not data or not _is_pdf_bytes(data):
        st.error("Generated PDF was invalid.")
        return "", ""
    drive_cli = _get_drive()
    fname = f"{prefix}.pdf"
    folder_id = parent_folder_id or (st.secrets.get("drive", {}).get("approvals_folder_id") or st.secrets.get("drive", {}).get("approvals", ""))
    metadata = {"name": fname}
    if folder_id:
        metadata["parents"] = [folder_id]
    media = MediaIoBaseUpload(io.BytesIO(data), mimetype="application/pdf", resumable=False)

    try:
        file = drive_cli.files().create(
            body=metadata, media_body=media,
            fields="id, webViewLink, parents",
            supportsAllDrives=True,
        ).execute()
    except HttpError as e:
        # optionally handle storage quota fallback here if you use user OAuth
        raise

    file_id = file.get("id", "")
    link = file.get("webViewLink", "")
    if st.secrets.get("drive", {}).get("public", True) and file_id:
        _drive_make_public(file_id, drive_client=drive_cli)
    return link, file_id

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

# ---- Sheets helpers ----
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
        st.warning(f"Multiple worksheets named '{EMPLOYEE_WS}' found; using the first (appear empty).")
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

# ---- Misc helpers ----
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

# ---- Project/city code helpers & counters ----
def project_code_from(text: str) -> str:
    s = (text or "").strip().lower()
    if not s:
        return "HO"
    if re.search(r"\b(ho|head\s*office|hq|head\s*quarters)\b", s): return "HO"
    if re.search(r"\b(st|site|field|project|yard)\b", s): return "ST"
    if "finance" in s: return "FIN"
    if re.fullmatch(r"(it|i\.t\.|information\s*technology)", s): return "IT"
    return "HO"

def city_code_from(text: str) -> str:
    s = (text or "").strip().lower()
    if not s:
        return "RUH"
    pairs = [
        (("riyadh","ruh","riyad"), "RUH"),
        (("jeddah","jed","jdh","jda"), "JED"),
        (("taif","tif"), "TIF"),
        (("madinah","medina","med","al madinah","al-madinah"), "MED"),
    ]
    for keys, code in pairs:
        if any(k in s for k in keys):
            return code
    return "RUH"

def get_next_order_number(type_: str) -> str:
    ws = get_or_create_ws("counters", rows=10, cols=2)
    df = pd.DataFrame(ws.get_all_records())
    default_start = 1 if type_ == "REG" else 2

    if "Type" not in df.columns or "LastUsed" not in df.columns:
        df = pd.DataFrame([{"Type": "REG", "LastUsed": default_start - 1}])

    if type_ not in df.get("Type", pd.Series(dtype=str)).values:
        df = pd.concat([df, pd.DataFrame([{"Type": type_, "LastUsed": default_start - 1}])], ignore_index=True)

    idx = df[df["Type"] == type_].index[0]
    current = int(df.at[idx, "LastUsed"]) + 1
    df.at[idx, "LastUsed"] = current

    ws.clear()
    set_with_dataframe(ws, df)
    return str(current).zfill(4)

# ============================================
# Part 4: Streamlit Tabs for Register & Transfer
# ============================================

def register_device_tab():
    st.subheader("📝 Register New Device")

    emp_df = read_worksheet(EMPLOYEE_WS)
    emp_names = sorted({*unique_nonempty(emp_df, "New Employeer"), *unique_nonempty(emp_df, "Name")})

    with st.form("register_device", clear_on_submit=True):
        # --- Device Info ---
        r1c1, r1c2, r1c3 = st.columns(3)
        with r1c1:
            serial = st.text_input("Serial Number *")
        with r1c2:
            assigned_choice = st.selectbox("Assigned to", [UNASSIGNED_LABEL] + emp_names + ["Type a new name…"])
            assigned_to = st.text_input("Name") if assigned_choice == "Type a new name…" else assigned_choice
        with r1c3:
            device = st.text_input("Device Type *")

        r2c1, r2c2, r2c3 = st.columns(3)
        brand = r2c1.text_input("Brand")
        model = r2c2.text_input("Model")
        cpu = r2c3.text_input("CPU")

        r3c1, r3c2, r3c3 = st.columns(3)
        mem = r3c1.text_input("Memory")
        hdd1 = r3c2.text_input("Hard Drive 1")
        hdd2 = r3c3.text_input("Hard Drive 2")

        r4c1, r4c2, r4c3 = st.columns(3)
        gpu = r4c1.text_input("GPU")
        screen = r4c2.text_input("Screen Size")
        email = r4c3.text_input("Email Address")

        r5c1, r5c2, r5c3 = st.columns(3)
        contact = r5c1.text_input("Contact Number")
        dept = r5c2.text_input("Department")
        location = r5c3.text_input("Location")

        office = st.text_input("Office")
        notes = st.text_area("Notes", height=60)

        st.markdown("### ✍️ Owner Signature")
        owner_canvas = st_canvas(fill_color="rgba(255,255,255,0)", stroke_width=2, stroke_color="#000000",
                                 background_color="#FFFFFF", height=150, width=400, drawing_mode="freedraw",
                                 key="reg_sig_canvas")
        submitted = st.form_submit_button("Save Device", type="primary")

    if not submitted:
        return

    if not serial.strip() or not device.strip():
        st.error("Serial Number and Device Type are required.")
        return

    now_str = datetime.now().strftime(DATE_FMT)
    actor = st.session_state.get("username", "")

    # Prepare base row
    base_row = {
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
        "Current user": assigned_to.strip(),
        "Previous User": "",
        "TO": assigned_to.strip() if assigned_to.strip() and assigned_to.strip() != UNASSIGNED_LABEL else "",
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

    # Signature image (PNG)
    owner_sig_img = None
    if owner_canvas.image_data is not None:
        img_pil = Image.fromarray(owner_canvas.image_data.astype("uint8"), "RGBA")
        buf = io.BytesIO()
        img_pil.save(buf, format="PNG")
        owner_sig_img = buf.getvalue()

    # Auto-generate PDF
    field_map = build_field_map_for_register({
        "serial": serial, "device": device, "brand": brand, "model": model, "cpu": cpu, "mem": mem,
        "hdd1": hdd1, "hdd2": hdd2, "gpu": gpu, "screen": screen, "assigned_to": assigned_to,
        "email": email, "contact": contact, "department": dept, "location": location
    })
    pdf_bytes = render_pdf_from_template(TEMPLATE_PATH, field_map, owner_sig=owner_sig_img)

    serial_norm = normalize_serial(serial)
    project_code = project_code_from(dept or "HO")
    city_code = city_code_from(location or "RUH")
    order_number = get_next_order_number("REG")
    today_str = datetime.now().strftime("%Y%m%d")
    prefix = f"{project_code}-{city_code}-REG-{serial_norm}-{order_number}-{today_str}"

    pending_folder = ensure_folder_tree(project_code, city_code, "REG", "Pending")
    link, fid = upload_pdf_bytes_and_link(pdf_bytes, prefix=prefix, parent_folder_id=pending_folder)
    if not fid:
        st.error("Failed to upload generated PDF.")
        return

    pending = {**base_row,
        "Approval Status": "Pending", "Approval PDF": link, "Approval File ID": fid,
        "Submitted by": actor, "Submitted at": now_str, "Approver": "", "Decision at": "",
    }
    append_to_worksheet(PENDING_DEVICE_WS, pd.DataFrame([pending]))
    st.success("✅ Device submitted for admin approval (PDF generated & uploaded).")


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
    new_owner = st.text_input("Enter new owner name") if new_owner_choice == "Type a new name…" else (new_owner_choice if new_owner_choice != "— Select —" else "")

    st.markdown("### ✍️ Owner Signature (new owner)")
    owner_canvas = st_canvas(fill_color="rgba(255,255,255,0)", stroke_width=2, stroke_color="#000000",
                             background_color="#FFFFFF", height=150, width=400, drawing_mode="freedraw",
                             key="transfer_sig_canvas")

    do_transfer = st.button("Submit Transfer", type="primary", disabled=not (chosen_serial and new_owner.strip()))
    if not do_transfer:
        return

    match = inventory_df[inventory_df["Serial Number"].astype(str) == chosen_serial]
    if match.empty:
        st.error("Serial not found in Inventory.")
        return

    row = match.iloc[0]
    now_str = datetime.now().strftime(DATE_FMT)
    actor = st.session_state.get("username", "")

    owner_sig_img = None
    if owner_canvas.image_data is not None:
        img_pil = Image.fromarray(owner_canvas.image_data.astype("uint8"), "RGBA")
        buf = io.BytesIO()
        img_pil.save(buf, format="PNG")
        owner_sig_img = buf.getvalue()

    # Build PDF
    field_map = build_field_map_for_transfer(row, new_owner)
    pdf_bytes = render_pdf_from_template(TEMPLATE_PATH, field_map, owner_sig=owner_sig_img)

    serial_norm = normalize_serial(chosen_serial)
    dep_val = row.get("Department", "")
    loc_val = row.get("Location", "")
    project_code = project_code_from(dep_val or "HO")
    city_code = city_code_from(loc_val or "RUH")
    order_number = get_next_order_number("TRF")
    today_str = datetime.now().strftime("%Y%m%d")
    prefix = f"{project_code}-{city_code}-TRF-{serial_norm}-{order_number}-{today_str}"

    pending_folder = ensure_folder_tree(project_code, city_code, "TRF", "Pending")
    link, fid = upload_pdf_bytes_and_link(pdf_bytes, prefix=prefix, parent_folder_id=pending_folder)
    if not fid:
        st.error("Failed to upload generated PDF.")
        return

    pend = {
        "Device Type": row.get("Device Type"),
        "Serial Number": chosen_serial,
        "From owner": row.get("Current user"),
        "To owner": new_owner,
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
    st.success("✅ Transfer submitted for admin approval (PDF generated & uploaded).")

# ============================================
# Part 5: Admin Approval & Main App
# ============================================

def approvals_tab():
    st.subheader("✅ Approvals (Admin Only)")
    if st.session_state.get("role") != "Admin":
        st.info("Only Admins can view this section.")
        return

    pending_dev = read_worksheet(PENDING_DEVICE_WS)
    pending_tr = read_worksheet(PENDING_TRANSFER_WS)

    st.markdown("### Pending Device Registrations")
    df_dev = pending_dev[pending_dev["Approval Status"].isin(["", "Pending"])].reset_index(drop=True)
    if df_dev.empty:
        st.success("No pending device registrations.")
    else:
        for i, row in df_dev.iterrows():
            with st.expander(f"{row['Device Type']} — SN {row['Serial Number']} (by {row['Submitted by']})", expanded=False):
                c1, c2 = st.columns([3, 2])
                with c1:
                    st.json({k: row.get(k, "") for k in INVENTORY_COLS})
                    pdf_bytes = _fetch_public_pdf_bytes(row.get("Approval File ID", ""), row.get("Approval PDF", ""))
                    if pdf_bytes:
                        st.caption("Approval PDF Preview")
                        pdf_viewer(input=pdf_bytes, width=700, key=f"viewer_dev_{i}")
                    elif row.get("Approval PDF"):
                        st.markdown(f"[Open Approval PDF]({row['Approval PDF']})")
                with c2:
                    st.markdown("**Admin Signature**")
                    admin_canvas = st_canvas(fill_color="rgba(255,255,255,0)", stroke_width=2, stroke_color="#000000",
                                             background_color="#FFFFFF", height=150, width=400, drawing_mode="freedraw",
                                             key=f"admin_sig_dev_{i}")
                    approve = st.button("Approve", key=f"approve_dev_{i}")
                    reject = st.button("Reject", key=f"reject_dev_{i}")
                    if approve:
                        _approve_device_row(row, admin_canvas)
                    if reject:
                        _reject_row(PENDING_DEVICE_WS, row)

    st.markdown("---")
    st.markdown("### Pending Transfers")
    df_tr = pending_tr[pending_tr["Approval Status"].isin(["", "Pending"])].reset_index(drop=True)
    if df_tr.empty:
        st.success("No pending transfers.")
    else:
        for i, row in df_tr.iterrows():
            with st.expander(f"SN {row['Serial Number']}: {row['From owner']} → {row['To owner']} (by {row['Submitted by']})", expanded=False):
                c1, c2 = st.columns([3, 2])
                with c1:
                    st.json({k: row.get(k, "") for k in LOG_COLS})
                    pdf_bytes = _fetch_public_pdf_bytes(row.get("Approval File ID", ""), row.get("Approval PDF", ""))
                    if pdf_bytes:
                        st.caption("Approval PDF Preview")
                        pdf_viewer(input=pdf_bytes, width=700, key=f"viewer_tr_{i}")
                    elif row.get("Approval PDF"):
                        st.markdown(f"[Open Approval PDF]({row['Approval PDF']})")
                with c2:
                    st.markdown("**Admin Signature**")
                    admin_canvas = st_canvas(fill_color="rgba(255,255,255,0)", stroke_width=2, stroke_color="#000000",
                                             background_color="#FFFFFF", height=150, width=400, drawing_mode="freedraw",
                                             key=f"admin_sig_tr_{i}")
                    approve = st.button("Approve", key=f"approve_tr_{i}")
                    reject = st.button("Reject", key=f"reject_tr_{i}")
                    if approve:
                        _approve_transfer_row(row, admin_canvas)
                    if reject:
                        _reject_row(PENDING_TRANSFER_WS, row)

# -------------------------
# Approval Helpers
# -------------------------
def _approve_device_row(row: pd.Series, admin_canvas):
    inv = read_worksheet(INVENTORY_WS)
    now_str = datetime.now().strftime(DATE_FMT)
    approver = st.session_state.get("username", "")

    # Add admin signature overlay to PDF
    pdf_bytes = _fetch_public_pdf_bytes(row.get("Approval File ID", ""), row.get("Approval PDF", ""))
    admin_sig_img = None
    if admin_canvas.image_data is not None:
        img_pil = Image.fromarray(admin_canvas.image_data.astype("uint8"), "RGBA")
        buf = io.BytesIO()
        img_pil.save(buf, format="PNG")
        admin_sig_img = buf.getvalue()

    if pdf_bytes and admin_sig_img:
        # Re-overlay with admin signature
        reader = PdfReader(io.BytesIO(pdf_bytes))
        page = reader.pages[0]
        width, height = page.mediabox.width, page.mediabox.height
        overlay_stream = io.BytesIO()
        c = canvas.Canvas(overlay_stream, pagesize=(width, height))
        img_admin = ImageReader(io.BytesIO(admin_sig_img))
        c.drawImage(img_admin, 300, 540, width=100, height=30, mask="auto")
        c.save()
        overlay_stream.seek(0)
        writer = PdfWriter()
        page.merge_page(PdfReader(overlay_stream).pages[0])
        writer.add_page(page)
        out_buf = io.BytesIO()
        writer.write(out_buf)
        out_buf.seek(0)
        project_code = project_code_from(row.get("Department", "") or "UNK")
        city_code = city_code_from(row.get("Location", "") or "UNK")
        dest_folder = ensure_folder_tree(project_code, city_code, "REG", "Approved")
        upload_pdf_bytes_and_link(out_buf.read(), prefix=f"APPROVED-{row['Serial Number']}", parent_folder_id=dest_folder)

    new_row = {k: row.get(k, "") for k in INVENTORY_COLS}
    new_row["Registered by"] = approver
    new_row["Date issued"] = now_str

    inv_out = pd.concat([inv, pd.DataFrame([new_row])], ignore_index=True)
    write_worksheet(INVENTORY_WS, inv_out)
    _mark_decision(PENDING_DEVICE_WS, row, status="Approved")
    st.success("✅ Device approved and added to Inventory.")


def _approve_transfer_row(row: pd.Series, admin_canvas):
    inv = read_worksheet(INVENTORY_WS)
    if inv.empty:
        st.error("Inventory empty; cannot apply transfer.")
        return

    idx = inv[inv["Serial Number"].astype(str) == str(row.get("Serial Number", ""))].index
    if idx.empty:
        st.error("Serial not found in Inventory.")
        return

    now_str = datetime.now().strftime(DATE_FMT)
    approver = st.session_state.get("username", "")
    i = idx[0]
    prev_user = str(inv.loc[i, "Current user"] or "")
    inv.loc[i, "Previous User"] = prev_user
    inv.loc[i, "Current user"] = row.get("To owner", "")
    inv.loc[i, "TO"] = row.get("To owner", "")
    inv.loc[i, "Date issued"] = now_str
    inv.loc[i, "Registered by"] = approver
    write_worksheet(INVENTORY_WS, inv)

    # Add admin signature overlay to PDF
    pdf_bytes = _fetch_public_pdf_bytes(row.get("Approval File ID", ""), row.get("Approval PDF", ""))
    admin_sig_img = None
    if admin_canvas.image_data is not None:
        img_pil = Image.fromarray(admin_canvas.image_data.astype("uint8"), "RGBA")
        buf = io.BytesIO()
        img_pil.save(buf, format="PNG")
        admin_sig_img = buf.getvalue()

    if pdf_bytes and admin_sig_img:
        reader = PdfReader(io.BytesIO(pdf_bytes))
        page = reader.pages[0]
        width, height = page.mediabox.width, page.mediabox.height
        overlay_stream = io.BytesIO()
        c = canvas.Canvas(overlay_stream, pagesize=(width, height))
        img_admin = ImageReader(io.BytesIO(admin_sig_img))
        c.drawImage(img_admin, 300, 540, width=100, height=30, mask="auto")
        c.save()
        overlay_stream.seek(0)
        writer = PdfWriter()
        page.merge_page(PdfReader(overlay_stream).pages[0])
        writer.add_page(page)
        out_buf = io.BytesIO()
        writer.write(out_buf)
        out_buf.seek(0)
        project_code = project_code_from(row.get("Department", "") or "UNK")
        city_code = city_code_from(row.get("Location", "") or "UNK")
        dest_folder = ensure_folder_tree(project_code, city_code, "TRF", "Approved")
        upload_pdf_bytes_and_link(out_buf.read(), prefix=f"APPROVED-{row['Serial Number']}", parent_folder_id=dest_folder)

    # Log transfer
    log_row = {k: row.get(k, "") for k in LOG_COLS}
    log_row["Date issued"] = now_str
    log_row["Registered by"] = approver
    append_to_worksheet(TRANSFERLOG_WS, pd.DataFrame([log_row]))
    _mark_decision(PENDING_TRANSFER_WS, row, status="Approved")
    st.success("✅ Transfer approved and applied.")


def _reject_row(ws_title: str, row: pd.Series):
    _mark_decision(ws_title, row, status="Rejected")
    st.info("❌ Request rejected.")


def _mark_decision(ws_title: str, row: pd.Series, *, status: str):
    df = read_worksheet(ws_title)
    mask = (df["Serial Number"].astype(str) == str(row.get("Serial Number", ""))) & (df["Submitted at"] == row.get("Submitted at", ""))
    if not mask.any():
        return
    idx = df[mask].index[0]
    df.loc[idx, "Approval Status"] = status
    df.loc[idx, "Approver"] = st.session_state.get("username", "")
    df.loc[idx, "Decision at"] = datetime.now().strftime(DATE_FMT)
    write_worksheet(ws_title, df)

# -------------------------
# Main App Runner
# -------------------------
def run_app():
    st.title(APP_TITLE)
    st.caption(SUBTITLE)
    if st.session_state.role == "Admin":
        tabs = st.tabs(["🧑‍💼 Employee Register","📇 Employees","📝 Register Device","📋 Inventory","🔁 Transfer Device","📜 Transfer Log","✅ Approvals"])
        with tabs[2]: register_device_tab()
        with tabs[4]: transfer_tab()
        with tabs[6]: approvals_tab()
    else:
        tabs = st.tabs(["📝 Register Device","🔁 Transfer Device"])
        with tabs[0]: register_device_tab()
        with tabs[1]: transfer_tab()

# -------------------------
# Auth UI
# -------------------------
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "just_logged_out" not in st.session_state:
    st.session_state.just_logged_out = False

# try restore session
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
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login", type="primary"):
        user = USERS.get(username)
        if user and _verify_password(password, user["password"]):
            do_login(username, user.get("role", "Staff"))
        else:
            st.error("❌ Invalid username or password.")
