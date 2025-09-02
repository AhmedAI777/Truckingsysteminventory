# app.py — Tracking Inventory Management System (Streamlit + Google Sheets/Drive)
# deps: streamlit gspread gspread-dataframe extra-streamlit-components pandas
#       google-auth google-api-python-client requests PyPDF2 xlsxwriter

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

from google.oauth2.service_account import Credentials
from google.oauth2.credentials import Credentials as UserCredentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload, MediaIoBaseDownload
from googleapiclient.errors import HttpError

from PyPDF2 import PdfReader, PdfWriter
from PyPDF2.generic import NameObject, DictionaryObject, BooleanObject, ArrayObject

# =========================
# Config
# =========================
APP_TITLE = "Tracking Inventory Management System"
SUBTITLE = "Advanced Construction"
DATE_FMT = "%Y-%m-%d %H:%M:%S"

SESSION_TTL_DAYS = 30
SESSION_TTL_SECONDS = SESSION_TTL_DAYS * 24 * 60 * 60
COOKIE_NAME = "ac_auth_v2"

SHEET_URL_DEFAULT = "https://docs.google.com/spreadsheets/d/1SHp6gOW4ltsyOT41rwo85e_LELrHkwSwKN33K6XNHFI/edit"

INVENTORY_WS = "truckinventory"
TRANSFERLOG_WS = "transfer_log"
EMPLOYEE_WS = "mainlists"
PENDING_DEVICE_WS = "pending_device_reg"
PENDING_TRANSFER_WS = "pending_transfers"
DEVICE_CATALOG_WS = st.secrets.get("sheets", {}).get("catalog_ws", "truckingsysteminventory")

INVENTORY_COLS = [
    "Serial Number", "Device Type", "Brand", "Model", "CPU",
    "Hard Drive 1", "Hard Drive 2", "Memory", "GPU", "Screen Size",
    "Current user", "Previous User", "TO",
    "Department", "Email Address", "Contact Number", "Location", "Office",
    "Notes", "Date issued", "Registered by"
]
CATALOG_COLS = [
    "Serial Number", "Device Type", "Brand", "Model", "CPU",
    "Hard Drive 1", "Hard Drive 2", "Memory", "GPU", "Screen Size",
]
LOG_COLS = ["Device Type", "Serial Number", "From owner", "To owner", "Date issued", "Registered by"]

EMPLOYEE_HEADERS = [
    "Name", "Email", "APLUS", "Active", "Position", "Department",
    "Location (KSA)", "Project", "Microsoft Teams", "Mobile Number"
]

APPROVAL_META_COLS = [
    "Approval Status", "Approval PDF", "Approval File ID",
    "Submitted by", "Submitted at", "Approver", "Decision at"
]
PENDING_DEVICE_COLS = INVENTORY_COLS + APPROVAL_META_COLS
PENDING_TRANSFER_COLS = LOG_COLS + APPROVAL_META_COLS

UNASSIGNED_LABEL = "Unassigned (Stock)"

ICT_TEMPLATE_FILE_ID = st.secrets.get("drive", {}).get("template_file_id", "1S6mW2sdLWsXNDfltdvLFwt3kFyQaGqjC")
TRANSFER_TEMPLATE_FILE_ID = st.secrets.get("drive", {}).get("transfer_template_file_id", ICT_TEMPLATE_FILE_ID)

INVENTORY_HEADER_SYNONYMS = {
    "user": "Current user",
    "currentuser": "Current user",
    "previoususer": "Previous User",
    "to": "TO",
    "email": "Email Address",
}

COOKIE_MGR = stx.CookieManager(key="ac_cookie_mgr")
for k in ("reg_pdf_ref", "transfer_pdf_ref"):
    ss.setdefault(k, None)

# =========================
# Auth (cookie)
# =========================
def _load_users_from_secrets():
    cfg = st.secrets.get("auth", {}).get("users", [])
    return {u["username"]: {"password": u.get("password", ""), "role": u.get("role", "Staff")} for u in cfg}

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
    for k in ["authenticated", "role", "username"]:
        st.session_state.pop(k, None)
    st.session_state.just_logged_out = True
    st.rerun()

if "cookie_bootstrapped" not in st.session_state:
    st.session_state.cookie_bootstrapped = True
    _ = COOKIE_MGR.get_all()
    st.rerun()

# =========================
# Google APIs (OAuth optional / soft-fail)
# =========================
SCOPES = ["https://www.googleapis.com/auth/spreadsheets", "https://www.googleapis.com/auth/drive"]
OAUTH_SCOPES = ["https://www.googleapis.com/auth/drive.file"]
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
    """Return OAuth user creds if configured; otherwise None (no hard errors)."""
    cfg = st.secrets.get("google_oauth", {}) or {}
    token_json = cfg.get("token_json")

    if token_json:
        try:
            info = json.loads(token_json)
            creds = UserCredentials.from_authorized_user_info(info, OAUTH_SCOPES)
            if not creds.valid and creds.refresh_token:
                creds.refresh(Request())
            return creds
        except Exception:
            return None

    # Optional local OAuth for development if explicitly enabled
    if os.environ.get("LOCAL_OAUTH", "0") == "1":
        client_id = cfg.get("client_id")
        client_secret = cfg.get("client_secret")
        if client_id and client_secret:
            try:
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
                return flow.run_local_server(port=0)
            except Exception:
                return None

    # No OAuth configured
    return None

@st.cache_resource(show_spinner=False)
def _get_user_drive():
    """Return a Drive client for the OAuth user, or None if OAuth isn't configured."""
    creds = _get_user_creds()
    if not creds:
        return None
    return build("drive", "v3", credentials=creds)

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


# =========================
# Drive helpers
# =========================
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

def _drive_resumable_upload(drive_cli, metadata: dict, data: bytes, *, supports_all_drives: bool) -> dict:
    """
    Returns Drive file resource (dict) on success. Raises on hard failure.
    Uses 5MB chunks, exponential backoff, and retries chunk uploads on transient errors
    including TLS EOF.
    """
    # 5 MB chunks keep connections stable on some hosts
    media = MediaIoBaseUpload(io.BytesIO(data), mimetype="application/pdf",
                              chunksize=5 * 1024 * 1024, resumable=True)
    request = drive_cli.files().create(
        body=metadata, media_body=media, fields="id, webViewLink",
        supportsAllDrives=supports_all_drives,
    )

    backoff = 1.0
    max_backoff = 16.0
    while True:
        try:
            status, resp = request.next_chunk(num_retries=3)
            if resp is not None:
                # Upload finished
                return resp
            # Optional: you can display progress via status.progress()
        except (ssl.SSLEOFError, IncompleteRead, socket.error, BrokenPipeError) as e:
            # Transient transport issue → wait & retry the same chunk
            time.sleep(backoff)
            backoff = min(max_backoff, backoff * 2)
            continue
        except HttpError as e:
            # Retry 5xx transient errors; propagate others
            if e.resp is not None and 500 <= int(e.resp.status) < 600:
                time.sleep(backoff)
                backoff = min(max_backoff, backoff * 2)
                continue
            raise
        except Exception:
            # Unknown error → small backoff and try once more
            time.sleep(backoff)
            backoff = min(max_backoff, backoff * 2)
            # After a couple of generic retries, re-raise
            # (simple guard)
            if backoff >= max_backoff:
                raise

def upload_pdf_and_link(uploaded_file, *, prefix: str) -> Tuple[str, str]:
    """Upload PDF to Drive. Try Service Account first; on SA quota exceeded,
    optionally fall back to OAuth user (same folder if possible, else user root).
    Returns (webViewLink, file_id) or ("","") on failure.
    """
    if uploaded_file is None:
        st.error("No file selected.")
        return "", ""

    # --- read & validate bytes ---
    allowed = {
        "application/pdf",
        "application/x-pdf",
        "application/octet-stream",
        "binary/octet-stream",
    }
    mime = getattr(uploaded_file, "type", "") or ""
    name = getattr(uploaded_file, "name", "file.pdf")

    try:
        data = uploaded_file.getvalue()
    except Exception as e:
        st.error(f"Failed reading the uploaded file: {e}")
        return "", ""

    if not data:
        st.error("Uploaded file is empty.")
        return "", ""

    is_pdf_magic = data[:4] == b"%PDF"
    looks_like_pdf = name.lower().endswith(".pdf") or is_pdf_magic
    if mime not in allowed and not looks_like_pdf:
        st.error(f"Only PDF files are allowed. Got type '{mime}' and name '{name}'.")
        return "", ""
    if not is_pdf_magic:
        st.warning("File doesn't start with %PDF header—but continuing. If Drive rejects it, please re-export the PDF.")

    # --- target file name & folder ---
    fname = f"{prefix}_{int(time.time())}.pdf"
    folder_id = st.secrets.get("drive", {}).get("approvals", "")
    metadata = {"name": fname}
    if folder_id:
        metadata["parents"] = [folder_id]

    media = MediaIoBaseUpload(io.BytesIO(data), mimetype="application/pdf", resumable=False)

    # --- 1) Try Service Account upload ---
    drive_cli = _get_drive()
    try:
        file = drive_cli.files().create(
            body=metadata, media_body=media, fields="id, webViewLink", supportsAllDrives=True
        ).execute()
    except HttpError as e:
        # SA quota exceeded? optionally fall back to OAuth user
        if e.resp.status == 403 and "storageQuotaExceeded" in str(e):
            if not ALLOW_OAUTH_FALLBACK:
                st.error("Service Account quota exceeded and OAuth fallback disabled.")
                return "", ""

            user_cli = _get_user_drive()
            if user_cli is None:
                st.error("Service Account quota exceeded and no OAuth token configured.")
                return "", ""

            # 2a) Try uploading to the same approvals folder as OAuth user
            try:
                file = user_cli.files().create(
                    body=metadata, media_body=media, fields="id, webViewLink", supportsAllDrives=False
                ).execute()
            except HttpError as e2:
                # If user can't write to that folder, retry to user's My Drive root
                if e2.resp.status in (403, 404):
                    try:
                        meta2 = {"name": fname}  # no parents -> goes to user's My Drive
                        file = user_cli.files().create(
                            body=meta2, media_body=media, fields="id, webViewLink", supportsAllDrives=False
                        ).execute()
                        st.warning(
                            "Uploaded to your My Drive (OAuth user) because the approvals folder "
                            "wasn't writable by the OAuth user."
                        )
                    except Exception as e3:
                        st.error(f"OAuth upload failed (root retry): {e3}")
                        return "", ""
                else:
                    st.error(f"OAuth upload failed: {e2}")
                    return "", ""
            except Exception as e2:
                st.error(f"OAuth upload failed: {e2}")
                return "", ""
        else:
            st.error(f"Drive upload failed: {e}")
            return "", ""
    except Exception as e:
        st.error(f"Unexpected error uploading to Drive: {e}")
        return "", ""

    # --- success -> make public if configured ---
    file_id = file.get("id", "")
    link = file.get("webViewLink", "")
    if not file_id:
        st.error("Drive did not return a file id.")
        return "", ""

    try:
        if st.secrets.get("drive", {}).get("public", True):
            # Try to use the same client that actually uploaded (drive_cli or user_cli)
            try:
                # If we fell back to OAuth above, 'file' came from user_cli; permissions via SA would error.
                # Use a generic attempt: first SA, then OAuth if SA fails.
                _drive_make_public(file_id, drive_client=drive_cli)
            except Exception:
                user_cli = _get_user_drive()
                if user_cli:
                    _drive_make_public(file_id, drive_client=user_cli)
    except Exception:
        pass

    return link, file_id

# =========================
# Sheets helpers
# =========================
def _norm_header(h: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (h or "").strip().lower())

def canon_inventory_columns(df: pd.DataFrame) -> pd.DataFrame:
    rename = {}
    for c in df.columns:
        key = _norm_header(c)
        if key in INVENTORY_HEADER_SYNONYMS:
            rename[c] = INVENTORY_HEADER_SYNONYMS[key]
    if rename:
        df = df.rename(columns=rename)
    if "Email" in df.columns and "Email Address" not in df.columns:
        df = df.rename(columns={"Email": "Email Address"})
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

def _read_employees_df() -> pd.DataFrame:
    ws = get_employee_ws()
    records = ws.get_all_records(expected_headers=EMPLOYEE_HEADERS)
    df = pd.DataFrame(records)
    if "New Employeer" not in df.columns:
        df["New Employeer"] = df.get("Name", "")
    if "Email Address" not in df.columns:
        df["Email Address"] = df.get("Email", "")
    if "Office" not in df.columns:
        df["Office"] = df.get("Project", "")
    return df

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
        return _read_employees_df()
    if ws_title == DEVICE_CATALOG_WS:
        ws = get_or_create_ws(DEVICE_CATALOG_WS)
        df = pd.DataFrame(ws.get_all_records())
        return reorder_columns(df, CATALOG_COLS)
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
        if ws_title == INVENTORY_WS:
            return pd.DataFrame(columns=INVENTORY_COLS)
        if ws_title == TRANSFERLOG_WS:
            return pd.DataFrame(columns=LOG_COLS)
        if ws_title == EMPLOYEE_WS:
            return pd.DataFrame(columns=EMPLOYEE_HEADERS)
        if ws_title == PENDING_DEVICE_WS:
            return pd.DataFrame(columns=PENDING_DEVICE_COLS)
        if ws_title == PENDING_TRANSFER_WS:
            return pd.DataFrame(columns=PENDING_TRANSFER_COLS)
        if ws_title == DEVICE_CATALOG_WS:
            return pd.DataFrame(columns=CATALOG_COLS)
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
        out = pd.DataFrame(df, copy=True)
        for c in EMPLOYEE_HEADERS:
            if c not in out.columns:
                out[c] = ""
        out = out[EMPLOYEE_HEADERS]
        ws.clear()
        set_with_dataframe(ws, out)
        st.cache_data.clear()
        return
    ws = get_or_create_ws(ws_title)
    ws.clear()
    set_with_dataframe(ws, df)
    st.cache_data.clear()

def append_to_worksheet(ws_title, new_data):
    if ws_title == EMPLOYEE_WS:
        ws = get_employee_ws()
        df = pd.DataFrame(new_data)
        if not df.empty:
            row = df.iloc[0]
            payload = [str(row.get(c, "")) for c in EMPLOYEE_HEADERS]
            ws.append_row(payload)
            st.cache_data.clear()
        return
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

# =========================
# PDF
# =========================
def _registration_field_map() -> dict[str, str]:
    fm: dict[str, str] = {
        "from_name": "Text Field0",
        "from_mobile": "Text Field1",
        "from_email": "Text Field2",
        "from_department": "Text Field3",
        "from_date": "Text Field4",
        "from_location": "Text Field5",
        "to_name": "Text Field6",
        "to_mobile": "Text Field7",
        "to_email": "Text Field8",
        "to_department": "Text Field9",
        "to_date": "Text Field10",
        "to_location": "Text Field11",
    }
    for blk in range(4):
        base = 12 + blk * 5
        fm[f"eq{blk+1}_type"] = f"Text Field{base}"
        fm[f"eq{blk+1}_brand"] = f"Text Field{base+1}"
        fm[f"eq{blk+1}_model"] = f"Text Field{base+2}"
        fm[f"eq{blk+1}_specs"] = f"Text Field{base+3}"
        fm[f"eq{blk+1}_serial"] = f"Text Field{base+4}"
    fm.update(
        {"eq_type": fm["eq1_type"], "eq_brand": fm["eq1_brand"], "eq_model": fm["eq1_model"], "eq_specs": fm["eq1_specs"], "eq_serial": fm["eq1_serial"]}
    )
    override = st.secrets.get("pdf", {}).get("reg_field_map", {})
    if isinstance(override, dict) and override:
        fm.update(override)
    return fm

def fill_pdf_form(template_bytes: bytes, values: dict[str, str], *, flatten: bool = True) -> bytes:
    reader = PdfReader(io.BytesIO(template_bytes))
    writer = PdfWriter()
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
                        flags = int(obj.get("/Ff", 0))
                        obj.update({NameObject("/Ff"): flags | 1})
            writer._root_object["/AcroForm"].update({NameObject("/Fields"): ArrayObject()})
        except Exception:
            pass
    out = io.BytesIO()
    writer.write(out)
    out.seek(0)
    return out.read()

def _transfer_field_map() -> dict[str, str]:
    fm: dict[str, str] = {
        "from_name": "Text Field0",
        "from_mobile": "Text Field1",
        "from_email": "Text Field2",
        "from_department": "Text Field3",
        "from_date": "Text Field4",
        "from_location": "Text Field5",
        "to_name": "Text Field6",
        "to_mobile": "Text Field7",
        "to_email": "Text Field8",
        "to_department": "Text Field9",
        "to_date": "Text Field10",
        "to_location": "Text Field11",
    }
    for blk in range(4):
        base = 12 + blk * 5
        fm[f"eq{blk+1}_type"] = f"Text Field{base}"
        fm[f"eq{blk+1}_brand"] = f"Text Field{base+1}"
        fm[f"eq{blk+1}_model"] = f"Text Field{base+2}"
        fm[f"eq{blk+1}_specs"] = f"Text Field{base+3}"
        fm[f"eq{blk+1}_serial"] = f"Text Field{base+4}"
    fm.update(
        {"eq_type": fm["eq1_type"], "eq_brand": fm["eq1_brand"], "eq_model": fm["eq1_model"], "eq_specs": fm["eq1_specs"], "eq_serial": fm["eq1_serial"]}
    )
    override = st.secrets.get("pdf", {}).get("transfer_field_map", {})
    if isinstance(override, dict) and override:
        fm.update(override)
    return fm

# =========================
# Employee helpers
# =========================
def _find_emp_row_by_name(emp_df: pd.DataFrame, name: str) -> pd.Series | None:
    try:
        if emp_df is None or emp_df.empty or not str(name).strip():
            return None
        name = str(name).strip()
        cand = emp_df[
            (emp_df.get("New Employeer", "").astype(str).str.strip() == name)
            | (emp_df.get("Name", "").astype(str).str.strip() == name)
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
    keys = ("reg_contact", "reg_email", "reg_dept", "reg_location", "reg_office")
    if owner and owner != UNASSIGNED_LABEL and isinstance(emp_df, pd.DataFrame) and not emp_df.empty:
        r = _find_emp_row_by_name(emp_df, owner)
        if r is not None:
            st.session_state["reg_contact"] = _get_emp_value(r, "Mobile Number", "Phone", "Mobile")
            st.session_state["reg_email"] = _get_emp_value(r, "Email Address", "Email", "E-mail")
            st.session_state["reg_dept"] = _get_emp_value(r, "Department", "Dept")
            st.session_state["reg_location"] = _get_emp_value(r, "Location (KSA)", "Location", "City")
            st.session_state["reg_office"] = _get_emp_value(r, "Office", "Project", "Site")
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

def build_registration_values(device_row: dict, *, actor_name: str, emp_df: pd.DataFrame | None = None) -> dict[str, str]:
    fm = _registration_field_map()
    curr_owner = str(device_row.get("Current user", "") or "").strip()
    is_unassigned = (not curr_owner) or (curr_owner == UNASSIGNED_LABEL)
    from_name = curr_owner if not is_unassigned else (actor_name or device_row.get("Registered by", ""))
    from_mobile = str(device_row.get("Contact Number", "") or "")
    from_email = str(device_row.get("Email Address", "") or "")
    from_dept = str(device_row.get("Department", "") or "")
    from_location = str(device_row.get("Location", "") or "")
    if not is_unassigned and isinstance(emp_df, pd.DataFrame) and not emp_df.empty:
        r = _find_emp_row_by_name(emp_df, curr_owner)
        if r is not None:
            from_mobile = from_mobile or _get_emp_value(r, "Mobile Number", "Phone", "Mobile")
            from_email = from_email or _get_emp_value(r, "Email Address", "Email", "E-mail")
            from_dept = from_dept or _get_emp_value(r, "Department", "Dept")
            from_location = from_location or _get_emp_value(r, "Location (KSA)", "Location", "City")
    values = {
        fm["from_name"]: from_name,
        fm["from_mobile"]: from_mobile,
        fm["from_email"]: from_email,
        fm["from_department"]: from_dept,
        fm["from_date"]: datetime.now().strftime("%Y-%m-%d"),
        fm["from_location"]: from_location,
        fm["to_name"]: "",
        fm["to_mobile"]: "",
        fm["to_email"]: "",
        fm["to_department"]: "",
        fm["to_date"]: "",
        fm["to_location"]: "",
    }
    specs = []
    office_val = str(device_row.get("Office", "")).strip()
    if not office_val and not is_unassigned and isinstance(emp_df, pd.DataFrame) and not emp_df.empty:
        r = _find_emp_row_by_name(emp_df, curr_owner)
        if r is not None:
            office_val = _get_emp_value(r, "Office", "Project", "Site")
    for label, v in [
        ("CPU", device_row.get("CPU", "")),
        ("Memory", device_row.get("Memory", "")),
        ("GPU", device_row.get("GPU", "")),
        ("Hard Drive 1", device_row.get("Hard Drive 1", "")),
        ("Hard Drive 2", device_row.get("Hard Drive 2", "")),
        ("Screen Size", device_row.get("Screen Size", "")),
        ("Office", office_val),
        ("Notes", device_row.get("Notes", "")),
    ]:
        v = str(v).strip()
        if v:
            specs.append(f"{label}: {v}")
    specs_txt = " | ".join(specs)
    values.update(
        {
            fm["eq_type"]: device_row.get("Device Type", ""),
            fm["eq_brand"]: device_row.get("Brand", ""),
            fm["eq_model"]: device_row.get("Model", ""),
            fm["eq_specs"]: specs_txt,
            fm["eq_serial"]: device_row.get("Serial Number", ""),
        }
    )
    return values

def build_transfer_pdf_values(row: dict, new_owner: str, emp_df: pd.DataFrame) -> dict[str, str]:
    now_str = datetime.now().strftime("%Y-%m-%d")
    from_name = row.get("Current user", "")
    from_email = row.get("Email Address", "") or row.get("Email", "")
    from_phone = row.get("Contact Number", "")
    from_dept = row.get("Department", "")
    from_loc = row.get("Location", "")
    emp_row = emp_df.loc[(emp_df["New Employeer"] == new_owner) | (emp_df["Name"] == new_owner)]
    if not emp_row.empty:
        emp = emp_row.iloc[0]
        to_name = emp.get("Name", new_owner)
        to_email = emp.get("Email Address", emp.get("Email", ""))
        to_phone = emp.get("Mobile Number", "")
        to_dept = emp.get("Department", "")
        to_loc = emp.get("Location (KSA)", "")
    else:
        to_name, to_email, to_phone, to_dept, to_loc = new_owner, "", "", "", ""
    equip = (
        f"CPU: {row.get('CPU','')} | Memory: {row.get('Memory','')} | GPU: {row.get('GPU','')} | "
        f"Hard Drive 1: {row.get('Hard Drive 1','')} | Hard Drive 2: {row.get('Hard Drive 2','')} | "
        f"Screen Size: {row.get('Screen Size','')} | Office: {row.get('Office','')}"
    )
    return {
        "from_name": from_name,
        "from_mobile": from_phone,
        "from_email": from_email,
        "from_department": from_dept,
        "from_date": now_str,
        "from_location": from_loc,
        "to_name": to_name,
        "to_mobile": to_phone,
        "to_email": to_email,
        "to_department": to_dept,
        "to_date": now_str,
        "to_location": to_loc,
        "eq_type": row.get("Device Type", ""),
        "eq_brand": row.get("Brand", ""),
        "eq_model": row.get("Model", ""),
        "eq_specs": equip,
        "eq_serial": row.get("Serial Number", ""),
    }

# =========================
# Approvals state writeback
# =========================
def _mark_decision(ws_name: str, row: dict, *, status: str):
    df = read_worksheet(ws_name)
    now_str = datetime.now().strftime(DATE_FMT)
    actor = st.session_state.get("username", "")
    serial = str(row.get("Serial Number", ""))
    fid = str(row.get("Approval File ID", ""))
    mask = (df["Serial Number"].astype(str) == serial)
    if "Approval File ID" in df.columns and fid:
        mask &= df["Approval File ID"].astype(str) == fid
    idxs = df[mask].index.tolist()
    if not idxs:
        st.warning(f"Could not locate row for Serial {serial} in {ws_name}.")
        return
    idx = idxs[0]
    df.loc[idx, "Approval Status"] = status
    df.loc[idx, "Approver"] = actor
    df.loc[idx, "Decision at"] = now_str
    write_worksheet(ws_name, df)

# =========================
# UI
# =========================
def _ict_filename(serial: str, seq: str = "0008") -> str:
    return f"HO-JED-REG-{re.sub(r'[^A-Z0-9]','',serial.upper())}-{seq}-{datetime.now().strftime('%Y%m%d')}.pdf"

def _transfer_filename(serial: str, seq: str = "0009") -> str:
    return f"HO-JED-TRN-{re.sub(r'[^A-Z0-9]','',serial.upper())}-{seq}-{datetime.now().strftime('%Y%m%d')}.pdf"

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
        st.info("No employees found.")
    else:
        st.dataframe(df, use_container_width=True, hide_index=True)

def inventory_tab():
    st.subheader("📋 Inventory")
    df = read_worksheet(INVENTORY_WS)
    if df.empty:
        st.warning("Inventory is empty.")
    else:
        st.dataframe(df, use_container_width=True, hide_index=True)

def history_tab():
    st.subheader("📜 Transfer Log")
    df = read_worksheet(TRANSFERLOG_WS)
    if df.empty:
        st.info("No transfer history found.")
    else:
        st.dataframe(df, use_container_width=True, hide_index=True)

def employee_register_tab():
    st.subheader("🧑‍💼 Register New Employee")
    with st.form("employee_register", clear_on_submit=True):
        name = st.text_input("Full Name *")
        emp_id = st.text_input("Employee ID (APLUS) *")
        email = st.text_input("Email")
        mobile = st.text_input("Mobile Number")
        position = st.text_input("Position")
        dept = st.text_input("Department")
        loc = st.text_input("Location (KSA)")
        proj = st.text_input("Project / Office")
        teams = st.text_input("Microsoft Teams")
        submitted = st.form_submit_button("Save Employee", type="primary")
    if submitted:
        if not name.strip() or not emp_id.strip():
            st.error("Name and Employee ID are required.")
            return
        new_row = pd.DataFrame(
            [
                {
                    "Name": name.strip(),
                    "Email": email.strip(),
                    "APLUS": emp_id.strip(),
                    "Active": "Yes",
                    "Position": position.strip(),
                    "Department": dept.strip(),
                    "Location (KSA)": loc.strip(),
                    "Project": proj.strip(),
                    "Microsoft Teams": teams.strip(),
                    "Mobile Number": mobile.strip(),
                }
            ]
        )
        append_to_worksheet(EMPLOYEE_WS, new_row)
        st.success(f"✅ Employee '{name}' registered.")

def register_device_tab():
    st.subheader("📝 Register New Device")
    st.session_state.setdefault("current_owner", UNASSIGNED_LABEL)
    emp_df = read_worksheet(EMPLOYEE_WS)
    employee_names = sorted({*unique_nonempty(emp_df, "New Employeer"), *unique_nonempty(emp_df, "Name")})
    owner_options = [UNASSIGNED_LABEL] + employee_names
    st.selectbox(
        "Current owner (at registration)",
        owner_options,
        index=owner_options.index(st.session_state["current_owner"])
        if st.session_state["current_owner"] in owner_options
        else 0,
        key="current_owner",
        on_change=_owner_changed,
        args=(emp_df,),
    )
    with st.form("register_device", clear_on_submit=False):
        r1c1, r1c2, r1c3 = st.columns(3)
        with r1c1:
            st.text_input("Serial Number *", key="reg_serial")
        with r1c2:
            st.text_input("Device Type *", key="reg_device")
        with r1c3:
            st.text_input("Brand", key="reg_brand")
        r2c1, r2c2, r2c3 = st.columns(3)
        with r2c1:
            st.text_input("Model", key="reg_model")
        with r2c2:
            st.text_input("CPU", key="reg_cpu")
        with r2c3:
            st.text_input("Memory", key="reg_mem")
        r3c1, r3c2, r3c3 = st.columns(3)
        with r3c1:
            st.text_input("Hard Drive 1", key="reg_hdd1")
        with r3c2:
            st.text_input("Hard Drive 2", key="reg_hdd2")
        with r3c3:
            st.text_input("GPU", key="reg_gpu")
        r4c1, r4c2, r4c3 = st.columns(3)
        with r4c1:
            st.text_input("Screen Size", key="reg_screen")
        with r4c2:
            st.text_input("Email Address", key="reg_email")
        with r4c3:
            st.text_input("Contact Number", key="reg_contact")
        r5c1, r5c2, r5c3 = st.columns(3)
        with r5c1:
            st.text_input("Department", key="reg_dept")
        with r5c2:
            st.text_input("Location", key="reg_location")
        with r5c3:
            st.text_input("Office", key="reg_office")
        st.text_area("Notes", height=80, key="reg_notes")
        st.divider()
        pdf_file = st.file_uploader("Upload signed PDF", type=["pdf"], key="reg_pdf")
        c1, c2 = st.columns([1, 1])
        with c1:
            download_btn = st.form_submit_button("📄 Download Prefilled PDF")
        with c2:
            submitted = st.form_submit_button("💾 Save Device", type="primary")

    def build_row(now_str, actor):
        return {
            "Serial Number": st.session_state.get("reg_serial", "").strip(),
            "Device Type": st.session_state.get("reg_device", "").strip(),
            "Brand": st.session_state.get("reg_brand", "").strip(),
            "Model": st.session_state.get("reg_model", "").strip(),
            "CPU": st.session_state.get("reg_cpu", "").strip(),
            "Hard Drive 1": st.session_state.get("reg_hdd1", "").strip(),
            "Hard Drive 2": st.session_state.get("reg_hdd2", "").strip(),
            "Memory": st.session_state.get("reg_mem", "").strip(),
            "GPU": st.session_state.get("reg_gpu", "").strip(),
            "Screen Size": st.session_state.get("reg_screen", "").strip(),
            "Current user": st.session_state.get("current_owner", UNASSIGNED_LABEL).strip(),
            "Department": st.session_state.get("reg_dept", "").strip(),
            "Email Address": st.session_state.get("reg_email", "").strip(),
            "Contact Number": st.session_state.get("reg_contact", "").strip(),
            "Location": st.session_state.get("reg_location", "").strip(),
            "Office": st.session_state.get("reg_office", "").strip(),
            "Notes": st.session_state.get("reg_notes", "").strip(),
            "Date issued": now_str,
            "Registered by": actor,
        }

    if download_btn:
        serial = st.session_state.get("reg_serial", "")
        device = st.session_state.get("reg_device", "")
        if not serial or not device:
            st.error("Serial and Device Type required.")
        else:
            now_str = datetime.now().strftime(DATE_FMT)
            actor = st.session_state.get("username", "")
            row = build_row(now_str, actor)
            tpl_bytes = _download_template_bytes_or_public(ICT_TEMPLATE_FILE_ID)
            if not tpl_bytes:
                st.error("Could not load ICT Registration PDF template.")
            else:
                reg_vals = build_registration_values(row, actor_name=actor, emp_df=emp_df)
                filled = fill_pdf_form(tpl_bytes, reg_vals, flatten=True)
                st.download_button("⬇️ Download ICT Registration Form", data=filled, file_name=_ict_filename(serial))

    if submitted:
        serial = st.session_state.get("reg_serial", "")
        device = st.session_state.get("reg_device", "")
        if not serial or not device:
            st.error("Serial Number and Device Type are required.")
            return
        inv_df = read_worksheet(INVENTORY_WS)
        pending_df = read_worksheet(PENDING_DEVICE_WS)
        if serial in inv_df.get("Serial Number", []).tolist() or serial in pending_df.get("Serial Number", []).tolist():
            st.error(f"Serial {serial} already exists in Inventory or Pending.")
            return
        pdf_file_obj = pdf_file or st.session_state.get("reg_pdf")
        if pdf_file_obj is None:
            st.error("Signed ICT Registration PDF is required.")
            return
        now_str = datetime.now().strftime(DATE_FMT)
        actor = st.session_state.get("username", "")
        row = build_row(now_str, actor)
        link, fid = upload_pdf_and_link(
            pdf_file_obj,
            prefix=f"device_{normalize_serial(serial)}",
        )
        if not fid:
            return
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
        st.success("🕒 Device registration submitted for Admin approval.")

def transfer_tab():
    st.subheader("🔄 Device Transfer")
    inv_df = read_worksheet(INVENTORY_WS)
    emp_df = read_worksheet(EMPLOYEE_WS)
    if inv_df.empty:
        st.info("No devices in inventory.")
        return
    serials = inv_df["Serial Number"].dropna().tolist()
    employees = sorted({*unique_nonempty(emp_df, "New Employeer"), *unique_nonempty(emp_df, "Name")})
    with st.form("transfer_form", clear_on_submit=False):
        serial = st.selectbox("Select Serial Number", serials, key="trf_serial")
        new_owner = st.selectbox("Select New Owner", employees, key="trf_new_owner")
        pdf_file = st.file_uploader("Upload signed transfer PDF", type=["pdf"], key="trf_pdf")
        c1, c2 = st.columns([1, 1])
        with c1:
            dl = st.form_submit_button("📄 Download Prefilled Transfer PDF")
        with c2:
            submitted = st.form_submit_button("💾 Submit Transfer Request", type="primary")
    if dl:
        if not serial or not new_owner:
            st.error("Serial number and new owner are required.")
        else:
            row = inv_df.loc[inv_df["Serial Number"] == serial].iloc[0].to_dict()
            transfer_vals = build_transfer_pdf_values(row, new_owner, emp_df)
            field_map = _transfer_field_map()
            mapped_vals = {field_map[k]: v for k, v in transfer_vals.items() if k in field_map}
            tpl_bytes = _download_template_bytes_or_public(TRANSFER_TEMPLATE_FILE_ID)
            if not tpl_bytes:
                st.error("Could not load transfer PDF template.")
            else:
                pdf_bytes = fill_pdf_form(tpl_bytes, mapped_vals)
                st.download_button(
                    "📥 Download Prefilled Transfer PDF",
                    data=pdf_bytes,
                    file_name=_transfer_filename(serial),
                    mime="application/pdf",
                )
    if submitted:
        if not serial or not new_owner:
            st.error("Serial number and new owner required.")
            return
        if pdf_file is None:
            st.error("Signed ICT Transfer PDF is required.")
            return
        row = inv_df.loc[inv_df["Serial Number"] == serial].iloc[0].to_dict()
        now_str = datetime.now().strftime(DATE_FMT)
        actor = st.session_state.get("username", "")
        link, fid = upload_pdf_and_link(
            pdf_file,
            prefix=f"transfer_{normalize_serial(serial)}",
        )
        if not fid:
            return
        pending = {
            **row,
            "From owner": row.get("Current user", ""),  # include actual current owner
            "To owner": new_owner,
            "Approval Status": "Pending",
            "Approval PDF": link,
            "Approval File ID": fid,
            "Submitted by": actor,
            "Submitted at": now_str,
            "Approver": "",
            "Decision at": "",
        }
        append_to_worksheet(PENDING_TRANSFER_WS, pd.DataFrame([pending]))
        st.success("🕒 Transfer request submitted for Admin approval.")

def _approve_device_row(row: pd.Series):
    inv = read_worksheet(INVENTORY_WS)
    now_str = datetime.now().strftime(DATE_FMT)
    approver = st.session_state.get("username", "")
    new_row = {k: row.get(k, "") for k in INVENTORY_COLS}
    new_row["Registered by"] = approver or new_row.get("Registered by", "")
    new_row["Date issued"] = now_str
    inv_out = pd.concat(
        [inv if not inv.empty else pd.DataFrame(columns=INVENTORY_COLS), pd.DataFrame([new_row])],
        ignore_index=True,
    )
    write_worksheet(INVENTORY_WS, inv_out)
    _mark_decision(PENDING_DEVICE_WS, row, status="Approved")
    # Optional: log initial assignment (Stock → current owner)
    try:
        log_row = {
            "Device Type": new_row.get("Device Type", ""),
            "Serial Number": new_row.get("Serial Number", ""),
            "From owner": UNASSIGNED_LABEL,
            "To owner": new_row.get("Current user", ""),
            "Date issued": now_str,
            "Registered by": approver,
        }
        append_to_worksheet(TRANSFERLOG_WS, pd.DataFrame([log_row]))
    except Exception:
        pass
    st.success("✅ Device approved and added to Inventory.")

def _approve_transfer_row(row: pd.Series):
    """Approve a transfer: log correct prev owner and refresh all person fields."""
    inv = read_worksheet(INVENTORY_WS)
    if inv.empty:
        st.error("Inventory is empty; cannot apply transfer.")
        st.stop()
    sn = str(row.get("Serial Number", ""))
    match = inv[inv["Serial Number"].astype(str) == sn]
    if match.empty:
        st.error("Serial not found in Inventory.")
        st.stop()
    idx = match.index[0]
    now_str = datetime.now().strftime(DATE_FMT)
    approver = st.session_state.get("username", "")
    prev_user = str(inv.loc[idx, "Current user"] or "")
    new_user = str(row.get("To owner", ""))

    emp_df = read_worksheet(EMPLOYEE_WS)
    emp_row = _find_emp_row_by_name(emp_df, new_user)

    def _val(*cols: str) -> str:
        return _get_emp_value(emp_row, *cols) if emp_row is not None else ""

    inv.loc[idx, "Previous User"] = prev_user
    inv.loc[idx, "Current user"] = new_user
    inv.loc[idx, "TO"] = new_user
    inv.loc[idx, "Email Address"] = _val("Email Address", "Email", "E-mail")
    inv.loc[idx, "Contact Number"] = _val("Mobile Number", "Phone", "Mobile")
    inv.loc[idx, "Department"] = _val("Department", "Dept")
    inv.loc[idx, "Location"] = _val("Location (KSA)", "Location", "City")
    inv.loc[idx, "Office"] = _val("Office", "Project", "Site")
    inv.loc[idx, "Date issued"] = now_str
    inv.loc[idx, "Registered by"] = approver
    write_worksheet(INVENTORY_WS, inv)

    log_row = {
        "Device Type": row.get("Device Type", ""),
        "Serial Number": sn,
        "From owner": prev_user,
        "To owner": new_user,
        "Date issued": now_str,
        "Registered by": approver,
    }
    append_to_worksheet(TRANSFERLOG_WS, pd.DataFrame([log_row]))

    _mark_decision(PENDING_TRANSFER_WS, row, status="Approved")
    st.success(f"✅ Transfer approved. {prev_user or '(blank)'} → {new_user}. Contact details updated.")

def _reject_row(ws_title: str, row: pd.Series):
    df = read_worksheet(ws_title)
    key_cols = [c for c in ["Serial Number", "Submitted at", "Submitted by", "To owner"] if c in df.columns]
    mask = pd.Series([True] * len(df))
    for c in key_cols:
        mask &= df[c].astype(str) == str(row.get(c, ""))
    idxs = df[mask].index.tolist()
    if not idxs and "Serial Number" in df.columns:
        idxs = df[df["Serial Number"].astype(str) == str(row.get("Serial Number", ""))].index.tolist()
    if not idxs:
        st.warning("Could not locate row to mark as Rejected.")
        return
    idx = idxs[0]
    df.loc[idx, "Approval Status"] = "Rejected"
    df.loc[idx, "Approver"] = st.session_state.get("username", "")
    df.loc[idx, "Decision at"] = datetime.now().strftime(DATE_FMT)
    write_worksheet(ws_title, df)
    st.success("❌ Request rejected.")

def approvals_tab():
    st.subheader("✅ Approvals")
    st.markdown("### 📦 Pending Device Registrations")
    pend_df = read_worksheet(PENDING_DEVICE_WS)
    if pend_df.empty:
        st.info("No pending device registrations.")
    else:
        for i, row in pend_df.iterrows():
            if row.get("Approval Status", "") != "Pending":
                continue
            with st.expander(f"Serial: {row.get('Serial Number')} — {row.get('Device Type')}"):
                st.write(row.to_dict())
                pdf_link = row.get("Approval PDF", "")
                if pdf_link:
                    st.markdown(f"[📄 View PDF]({pdf_link})")
                c1, c2 = st.columns(2)
                with c1:
                    if st.button("✅ Approve", key=f"approve_device_{i}"):
                        _approve_device_row(row)
                        st.rerun()
                with c2:
                    if st.button("❌ Reject", key=f"reject_device_{i}"):
                        _reject_row(PENDING_DEVICE_WS, row)
                        st.rerun()
    st.divider()
    st.markdown("### 🔄 Pending Transfers")
    pend_trf = read_worksheet(PENDING_TRANSFER_WS)
    if pend_trf.empty:
        st.info("No pending transfers.")
    else:
        for i, row in pend_trf.iterrows():
            if row.get("Approval Status", "") != "Pending":
                continue
            with st.expander(f"Serial: {row.get('Serial Number')} — Transfer to {row.get('To owner')}"):
                st.write(row.to_dict())
                pdf_link = row.get("Approval PDF", "")
                if pdf_link:
                    st.markdown(f"[📄 View PDF]({pdf_link})")
                c1, c2 = st.columns(2)
                with c1:
                    if st.button("✅ Approve Transfer", key=f"approve_transfer_{i}"):
                        _approve_transfer_row(row)
                        st.rerun()
                with c2:
                    if st.button("❌ Reject Transfer", key=f"reject_transfer_{i}"):
                        _reject_row(PENDING_TRANSFER_WS, row)
                        st.rerun()

def export_tab():
    st.subheader("⬇️ Export Data")
    sheets = {
        "Inventory": INVENTORY_WS,
        "Employees": EMPLOYEE_WS,
        "Transfer Log": TRANSFERLOG_WS,
        "Pending Device Registrations": PENDING_DEVICE_WS,
        "Pending Transfers": PENDING_TRANSFER_WS,
    }
    choice = st.selectbox("Select sheet to export", list(sheets.keys()))
    if not choice:
        return
    df = read_worksheet(sheets[choice])
    if df.empty:
        st.info("No data available to export.")
        return
    csv = df.to_csv(index=False).encode("utf-8")
    st.download_button(
        label=f"📥 Download {choice} as CSV",
        data=csv,
        file_name=f"{choice.replace(' ', '_').lower()}_{datetime.now().strftime('%Y%m%d')}.csv",
        mime="text/csv",
    )
    excel_buf = io.BytesIO()
    with pd.ExcelWriter(excel_buf, engine="xlsxwriter") as writer:
        df.to_excel(writer, sheet_name=choice[:30], index=False)
    st.download_button(
        label=f"📥 Download {choice} as Excel",
        data=excel_buf.getvalue(),
        file_name=f"{choice.replace(' ', '_').lower()}_{datetime.now().strftime('%Y%m%d')}.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )

# =========================
# App
# =========================
def _config_check_ui():
    try:
        sa = _load_sa_info()
        sa_email = sa.get("client_email", "(unknown)")
        st.caption(f"Service Account: {sa_email}")
    except Exception as e:
        st.error("Google Service Account credentials missing.")
        st.code(str(e))
        st.stop()
    try:
        _ = get_sh()
    except Exception as e:
        st.error("Cannot open spreadsheet with Service Account.")
        st.code(str(e))
        st.stop()

def run_app():
    render_header()
    _config_check_ui()
    if st.session_state.role == "Admin":
        tabs = st.tabs(
            [
                "🧑‍💼 Employee Register",
                "📇 View Employees",
                "📝 Register Device",
                "📋 View Inventory",
                "🔁 Transfer Device",
                "📜 Transfer Log",
                "✅ Approvals",
                "⬇️ Export",
            ]
        )
        with tabs[0]:
            employee_register_tab()
        with tabs[1]:
            employees_view_tab()
        with tabs[2]:
            register_device_tab()
        with tabs[3]:
            inventory_tab()
        with tabs[4]:
            transfer_tab()
        with tabs[5]:
            history_tab()
        with tabs[6]:
            approvals_tab()
        with tabs[7]:
            export_tab()
    else:
        tabs = st.tabs(["📝 Register Device", "🔁 Transfer Device", "📋 View Inventory", "📜 Transfer Log"])
        with tabs[0]:
            register_device_tab()
        with tabs[1]:
            transfer_tab()
        with tabs[2]:
            inventory_tab()
        with tabs[3]:
            history_tab()

# =========================
# Entry
# =========================
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "just_logged_out" not in st.session_state:
    st.session_state.just_logged_out = False

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
