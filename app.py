# app.py — Tracking Inventory Management System (full)
# pip install: streamlit gspread gspread-dataframe extra-streamlit-components pandas \
#              google-auth google-auth-oauthlib google-api-python-client streamlit-pdf-viewer \
#              requests PyPDF2

import os, re, glob, base64, json, hmac, hashlib, time, io
from datetime import datetime, timedelta
import pandas as pd
import requests
from PyPDF2 import PdfReader, PdfWriter
from PyPDF2.generic import NameObject, DictionaryObject, BooleanObject, ArrayObject

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
from PyPDF2.generic import NameObject, DictionaryObject, BooleanObject

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

INVENTORY_COLS = [
    "Serial Number","Device Type","Brand","Model","CPU",
    "Hard Drive 1","Hard Drive 2","Memory","GPU","Screen Size",
    "Current user","Previous User","TO",
    "Department","Email Address","Contact Number","Location","Office",
    "Notes","Date issued","Registered by"
]
LOG_COLS = ["Device Type","Serial Number","From owner","To owner","Date issued","Registered by"]
EMPLOYEE_CANON_COLS = [
    "New Employeer","Employee ID","New Signature","Name","Address",
    "Active","Position","Department","Location (KSA)",
    "Project","Microsoft Teams","Mobile Number","Email"  # "Email" often exists; we'll tolerate either name
]
APPROVAL_META_COLS = [
    "Approval Status","Approval PDF","Approval File ID",
    "Submitted by","Submitted at","Approver","Decision at"
]
PENDING_DEVICE_COLS   = INVENTORY_COLS + APPROVAL_META_COLS
PENDING_TRANSFER_COLS = LOG_COLS + APPROVAL_META_COLS

UNASSIGNED_LABEL = "Unassigned (Stock)"
REQUIRE_REVIEW_CHECK = True

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
INVENTORY_HEADER_SYNONYMS = {"user":"Current user","currentuser":"Current user","previoususer":"Previous User","to":"TO","department1":None}

COOKIE_MGR = stx.CookieManager(key="ac_cookie_mgr")
for k in ("reg_pdf_ref", "transfer_pdf_ref"): ss.setdefault(k, None)

# =============================================================================
# AUTH (users + cookie)
# =============================================================================
def _load_users_from_secrets():
    users_cfg = st.secrets.get("auth", {}).get("users", [])
    users = {}
    for u in users_cfg:
        users[u["username"]] = {"password": u.get("password", ""), "role": u.get("role", "Staff")}
    return users
USERS = _load_users_from_secrets()

def _verify_password(raw: str, stored: str) -> bool: return hmac.compare_digest(str(stored), str(raw))
def _cookie_keys() -> list[str]:
    keys = [st.secrets.get("auth", {}).get("cookie_key", "")]
    keys += st.secrets.get("auth", {}).get("legacy_cookie_keys", [])
    return [k for k in keys if k]
def _sign(raw: bytes, *, key: str | None = None) -> str:
    use = key or st.secrets.get("auth", {}).get("cookie_key", "")
    return hmac.new(use.encode(), raw, hashlib.sha256).hexdigest()
def _verify_sig(sig: str, raw: bytes) -> bool:
    for k in _cookie_keys():
        if hmac.compare_digest(sig, _sign(raw, key=k)): return True
    return False
def _issue_session_cookie(username: str, role: str):
    iat = int(time.time()); exp = iat + (SESSION_TTL_SECONDS if SESSION_TTL_SECONDS > 0 else 0)
    payload = {"u": username, "r": role, "iat": iat, "exp": exp, "v": 1}
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    token = base64.urlsafe_b64encode(raw).decode() + "." + _sign(raw)
    COOKIE_MGR.set(COOKIE_NAME, token,
        expires_at=(datetime.utcnow() + timedelta(seconds=SESSION_TTL_SECONDS)) if SESSION_TTL_SECONDS > 0 else None,
        secure=st.secrets.get("auth", {}).get("cookie_secure", True))
def _read_cookie():
    token = COOKIE_MGR.get(COOKIE_NAME)
    if not token: return None
    try:
        data_b64, sig = token.split(".", 1)
        raw = base64.urlsafe_b64decode(data_b64.encode())
        if not _verify_sig(sig, raw): COOKIE_MGR.delete(COOKIE_NAME); return None
        payload = json.loads(raw.decode())
        if payload.get("exp",0) and int(time.time()) > int(payload["exp"]):
            COOKIE_MGR.delete(COOKIE_NAME); return None
        return payload
    except Exception:
        COOKIE_MGR.delete(COOKIE_NAME); return None
def do_login(username: str, role: str):
    st.session_state.update(authenticated=True, username=username, name=username, role=role, just_logged_out=False)
    _issue_session_cookie(username, role); st.rerun()
def do_logout():
    try: COOKIE_MGR.delete(COOKIE_NAME); COOKIE_MGR.set(COOKIE_NAME,"",expires_at=datetime.utcnow()-timedelta(days=1))
    except Exception: pass
    for k in ["authenticated","role","username","name"]: st.session_state.pop(k, None)
    st.session_state.just_logged_out=True; st.rerun()
if "cookie_bootstrapped" not in st.session_state:
    st.session_state.cookie_bootstrapped=True; _=COOKIE_MGR.get_all(); st.rerun()

# =============================================================================
# STYLE
# =============================================================================
def _inject_font_css(font_path: str, family: str = "ACBrandFont"):
    if not os.path.exists(font_path): return
    ext = os.path.splitext(font_path)[1].lower(); mime = "font/ttf" if ext == ".ttf" else "font/otf"; fmt  = "truetype" if ext == ".ttf" else "opentype"
    try:
        with open(font_path, "rb") as f: b64 = base64.b64encode(f.read()).decode("utf-8")
    except Exception: return
    st.markdown(f"""
    <style>
      @font-face {{ font-family:'{family}'; src:url(data:{mime};base64,{b64}) format('{fmt}'); font-display:swap; }}
      html, body, [class*="css"] {{ font-family:'{family}', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, "Noto Sans", sans-serif !important; }}
      h1,h2,h3,h4,h5,h6, .stTabs [role="tab"] {{ font-family:'{family}', sans-serif !important; }}
      section.main > div {{ padding-top: 0.6rem; }}
    </style>""", unsafe_allow_html=True)
def _font_candidates():
    cands=[]; secrets_font=st.secrets.get("branding",{}).get("font_file"); 
    if secrets_font: cands.append(secrets_font)
    cands+=["company_font.ttf","company_font.otf","ACBrandFont.ttf","ACBrandFont.otf","FounderGroteskCondensed-Regular.otf","Cairo-Regular.ttf"]
    try: cands += sorted(glob.glob("fonts/*.ttf")) + sorted(glob.glob("fonts/*.otf"))
    except Exception: pass
    return cands
def _apply_brand_font():
    fam=st.secrets.get("branding",{}).get("font_family","ACBrandFont")
    for p in _font_candidates():
        if os.path.exists(p): _inject_font_css(p, family=fam); return
def render_header():
    _apply_brand_font()
    c_logo,c_title,c_user = st.columns([1.2,6,3], gap="small")
    with c_logo:
        if os.path.exists("company_logo.jpeg"):
            try: st.image("company_logo.jpeg", use_container_width=True)
            except TypeError: st.image("company_logo.jpeg", use_column_width=True)
    with c_title:
        st.markdown(f"### {APP_TITLE}"); st.caption(SUBTITLE)
    with c_user:
        username=st.session_state.get("username",""); role=st.session_state.get("role","")
        st.markdown(f"""<div style="display:flex;align-items:center;justify-content:flex-end;gap:1rem;">
          <div><div style="font-weight:600;">Welcome, {username or '—'}</div><div>Role: <b>{role or '—'}</b></div></div></div>""", unsafe_allow_html=True)
        if st.session_state.get("authenticated") and st.button("Logout"): do_logout()
    st.markdown("<hr style='margin-top:0.8rem;'>", unsafe_allow_html=True)
def hide_table_toolbar_for_non_admin():
    if st.session_state.get("role")!="Admin":
        st.markdown("""<style>
          div[data-testid="stDataFrame"] div[data-testid="stElementToolbar"]{display:none!important;}
          div[data-testid="stDataEditor"]  div[data-testid="stElementToolbar"]{display:none!important;}
          div[data-testid="stElementToolbar"]{display:none!important;}
        </style>""", unsafe_allow_html=True)

# =============================================================================
# GOOGLE SHEETS & DRIVE
# =============================================================================
SCOPES = ["https://www.googleapis.com/auth/spreadsheets","https://www.googleapis.com/auth/drive"]
OAUTH_SCOPES = ["https://www.googleapis.com/auth/drive.file"]
ALLOW_OAUTH_FALLBACK = st.secrets.get("drive", {}).get("allow_oauth_fallback", True)

def _load_sa_info() -> dict:
    raw = st.secrets.get("gcp_service_account", {}); sa={}
    if isinstance(raw, dict): sa=dict(raw)
    elif isinstance(raw,str) and raw.strip():
        try: sa=json.loads(raw)
        except Exception: sa={}
    if not sa:
        env_json=os.environ.get("GOOGLE_SERVICE_ACCOUNT_JSON","")
        if env_json:
            try: sa=json.loads(env_json)
            except Exception: sa={}
    pk=sa.get("private_key","")
    if isinstance(pk,str) and "\\n" in pk: sa["private_key"]=pk.replace("\\n","\n")
    if "private_key" not in sa: raise RuntimeError("Service account JSON not found or missing 'private_key'.")
    return sa

@st.cache_resource(show_spinner=False)
def _get_creds(): return Credentials.from_service_account_info(_load_sa_info(), scopes=SCOPES)
@st.cache_resource(show_spinner=False)
def _get_gc(): return gspread.authorize(_get_creds())
@st.cache_resource(show_spinner=False)
def _get_drive(): return build("drive","v3",credentials=_get_creds())

@st.cache_resource(show_spinner=False)
def _get_user_creds():
    cfg = st.secrets.get("google_oauth", {}); token_json = cfg.get("token_json")
    if token_json:
        try: info=json.loads(token_json)
        except Exception: info=None
        if not info: st.error("google_oauth.token_json is not valid JSON."); st.stop()
        creds = UserCredentials.from_authorized_user_info(info, OAUTH_SCOPES)
        if not creds.valid and creds.refresh_token: creds.refresh(Request())
        return creds
    if os.environ.get("LOCAL_OAUTH","0")=="1":
        cid=cfg.get("client_id"); cs=cfg.get("client_secret")
        if not cid or not cs: st.error("[google_oauth] client_id/client_secret required for local OAuth."); st.stop()
        flow = InstalledAppFlow.from_client_config({"installed":{
            "client_id":cid,"client_secret":cs,"auth_uri":"https://accounts.google.com/o/oauth2/auth",
            "token_uri":"https://oauth2.googleapis.com/token","redirect_uris":["http://localhost"]}}, scopes=OAUTH_SCOPES)
        return flow.run_local_server(port=0)
    st.error("OAuth token not configured. Add [google_oauth].token_json to secrets or move to Shared drive."); st.stop()

@st.cache_resource(show_spinner=False)
def _get_user_drive(): return build("drive","v3",credentials=_get_user_creds())
@st.cache_resource(show_spinner=False)
def _get_sheet_url(): return st.secrets.get("sheets", {}).get("url", SHEET_URL_DEFAULT)

def get_sh():
    gc=_get_gc(); url=_get_sheet_url(); last_exc=None
    for attempt in range(3):
        try: return gc.open_by_url(url)
        except gspread.exceptions.APIError as e:
            last_exc=e; time.sleep(0.6*(attempt+1))
    st.error("Google Sheets API error while opening the spreadsheet."); raise last_exc

def _drive_make_public(file_id: str, drive_client=None):
    try:
        cli=drive_client or _get_drive()
        cli.permissions().create(fileId=file_id, body={"role":"reader","type":"anyone"},
                                 fields="id", supportsAllDrives=True).execute()
    except Exception: pass
def _is_pdf_bytes(data: bytes) -> bool: return isinstance(data,(bytes,bytearray)) and data[:4]==b"%PDF"

def upload_pdf_and_link(uploaded_file, *, prefix: str) -> tuple[str,str]:
    if uploaded_file is None: return "",""
    if getattr(uploaded_file,"type","") not in ("application/pdf","application/x-pdf","binary/octet-stream"):
        st.error("Only PDF files are allowed."); return "",""
    data=uploaded_file.getvalue()
    if not _is_pdf_bytes(data): st.error("The uploaded file doesn't look like a real PDF."); return "",""

    fname=f"{prefix}_{int(time.time())}.pdf"
    folder_id=st.secrets.get("drive",{}).get("approvals","")
    metadata={"name":fname}; 
    if folder_id: metadata["parents"]=[folder_id]
    media=MediaIoBaseUpload(io.BytesIO(data), mimetype="application/pdf", resumable=False)

    drive_cli=_get_drive()
    try:
        file=drive_cli.files().create(body=metadata, media_body=media, fields="id, webViewLink",
                                      supportsAllDrives=True).execute()
    except HttpError as e:
        if e.resp.status==403 and "storageQuotaExceeded" in str(e):
            if not ALLOW_OAUTH_FALLBACK:
                st.error("SA cannot upload to My Drive. Move folder to Shared drive or enable OAuth fallback."); st.stop()
            drive_cli=_get_user_drive()
            file=drive_cli.files().create(body=metadata, media_body=media, fields="id, webViewLink",
                                          supportsAllDrives=False).execute()
        else: raise
    file_id=file.get("id",""); link=file.get("webViewLink","")
    if st.secrets.get("drive",{}).get("public",True) and file_id: _drive_make_public(file_id, drive_client=drive_cli)
    return link, file_id

def _fetch_public_pdf_bytes(file_id: str, link: str) -> bytes:
    try:
        if file_id:
            url=f"https://drive.google.com/uc?export=download&id={file_id}"
            r=requests.get(url, timeout=15)
            if r.ok and r.content[:4]==b"%PDF": return r.content
    except Exception: pass
    return b""

def _download_drive_file_bytes(file_id: str) -> bytes:
    if not file_id: return b""
    try:
        req=_get_drive().files().get_media(fileId=file_id)
        buf=io.BytesIO(); downloader=MediaIoBaseDownload(buf, req); done=False
        while not done: _,done=downloader.next_chunk()
        data=buf.getvalue(); return data if data[:4]==b"%PDF" else b""
    except Exception:
        try:
            url=f"https://drive.google.com/uc?export=download&id={file_id}"
            r=requests.get(url, timeout=20); 
            if r.ok and r.content[:4]==b"%PDF": return r.content
        except Exception: pass
    return b""

# =============================================================================
# SHEETS HELPERS
# =============================================================================
def _norm_title(t: str) -> str: return (t or "").strip().lower()
def _norm_header(h: str) -> str: return re.sub(r"[^a-z0-9]+", "", (h or "").strip().lower())
def _canon_header(h: str) -> str:
    key=_norm_header(h); return HEADER_SYNONYMS.get(key, h.strip())

def canon_inventory_columns(df: pd.DataFrame) -> pd.DataFrame:
    rename={}; drop_cols=[]
    for c in df.columns:
        key=_norm_header(c)
        if key in INVENTORY_HEADER_SYNONYMS:
            new=INVENTORY_HEADER_SYNONYMS[key]
            if new: rename[c]=new
            else: drop_cols.append(c)
    if rename: df=df.rename(columns=rename)
    if drop_cols: df=df.drop(columns=drop_cols)
    return df.astype(str)

def reorder_columns(df: pd.DataFrame, desired: list[str]) -> pd.DataFrame:
    for c in desired:
        if c not in df.columns: df[c]=""
    tail=[c for c in df.columns if c not in desired]
    return df[desired + tail]

def get_or_create_ws(title, rows=500, cols=80):
    sh=get_sh()
    try: return sh.worksheet(title)
    except gspread.exceptions.WorksheetNotFound: return sh.add_worksheet(title=title, rows=rows, cols=cols)

def get_employee_ws():
    sh=get_sh(); wanted=EMPLOYEE_WS.strip().lower()
    matches=[ws for ws in sh.worksheets() if ws.title.strip().lower()==wanted]
    if not matches: raise RuntimeError(f"Worksheet '{EMPLOYEE_WS}' not found.")
    if len(matches)>1:
        for ws in matches:
            try:
                if len(ws.get_all_values())>1: return ws
            except Exception: pass
        st.warning(f"Multiple worksheets named '{EMPLOYEE_WS}' found; using the first.")
    return matches[0]

@st.cache_data(ttl=120, show_spinner=False)
def _read_worksheet_cached(ws_title: str) -> pd.DataFrame:
    if ws_title==PENDING_DEVICE_WS:
        ws=get_or_create_ws(PENDING_DEVICE_WS); df=pd.DataFrame(ws.get_all_records()); return reorder_columns(df,PENDING_DEVICE_COLS)
    if ws_title==PENDING_TRANSFER_WS:
        ws=get_or_create_ws(PENDING_TRANSFER_WS); df=pd.DataFrame(ws.get_all_records()); return reorder_columns(df,PENDING_TRANSFER_COLS)
    if ws_title==EMPLOYEE_WS:
        ws=get_employee_ws(); df=pd.DataFrame(ws.get_all_records()); return reorder_columns(df,EMPLOYEE_CANON_COLS)
    ws=get_or_create_ws(ws_title); data=ws.get_all_records(); df=pd.DataFrame(data)
    if ws_title==INVENTORY_WS: df=canon_inventory_columns(df); return reorder_columns(df,INVENTORY_COLS)
    if ws_title==TRANSFERLOG_WS: return reorder_columns(df,LOG_COLS)
    return df

def read_worksheet(ws_title):
    try: return _read_worksheet_cached(ws_title)
    except Exception as e:
        st.error(f"Error reading sheet '{ws_title}': {e}")
        if ws_title==INVENTORY_WS:   return pd.DataFrame(columns=INVENTORY_COLS)
        if ws_title==TRANSFERLOG_WS: return pd.DataFrame(columns=LOG_COLS)
        if ws_title==EMPLOYEE_WS:    return pd.DataFrame(columns=EMPLOYEE_CANON_COLS)
        if ws_title==PENDING_DEVICE_WS: return pd.DataFrame(columns=PENDING_DEVICE_COLS)
        if ws_title==PENDING_TRANSFER_WS: return pd.DataFrame(columns=PENDING_TRANSFER_COLS)
        return pd.DataFrame()

def write_worksheet(ws_title, df):
    if ws_title==INVENTORY_WS:
        df=canon_inventory_columns(df); df=reorder_columns(df,INVENTORY_COLS)
    if ws_title==PENDING_DEVICE_WS: df=reorder_columns(df,PENDING_DEVICE_COLS)
    if ws_title==PENDING_TRANSFER_WS: df=reorder_columns(df,PENDING_TRANSFER_COLS)
    ws=get_employee_ws() if ws_title==EMPLOYEE_WS else get_or_create_ws(ws_title)
    ws.clear(); set_with_dataframe(ws, df); st.cache_data.clear()

def append_to_worksheet(ws_title, new_data):
    ws=get_or_create_ws(ws_title); df_existing=pd.DataFrame(ws.get_all_records())
    if ws_title==INVENTORY_WS: df_existing=canon_inventory_columns(df_existing); df_existing=reorder_columns(df_existing,INVENTORY_COLS)
    if ws_title==PENDING_DEVICE_WS: df_existing=reorder_columns(df_existing,PENDING_DEVICE_COLS)
    if ws_title==PENDING_TRANSFER_WS: df_existing=reorder_columns(df_existing,PENDING_TRANSFER_COLS)
    df_combined=pd.concat([df_existing,new_data], ignore_index=True); set_with_dataframe(ws, df_combined); st.cache_data.clear()

# =============================================================================
# COMMON HELPERS
# =============================================================================
def normalize_serial(s: str) -> str: return re.sub(r"[^A-Z0-9]", "", (s or "").strip().upper())
def levenshtein(a: str, b: str, max_dist: int = 1) -> int:
    if a==b: return 0
    la,lb=len(a),len(b)
    if abs(la-lb)>max_dist: return max_dist+1
    if la>lb: a,b=b,a; la,lb=lb,la
    prev=list(range(lb+1))
    for i in range(1,la+1):
        cur=[i]+[0]*lb; row_min=cur[0]; ai=a[i-1]
        for j in range(1,lb+1):
            cost=0 if ai==b[j-1] else 1
            cur[j]=min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost); row_min=min(row_min,cur[j])
        if row_min>max_dist: return max_dist+1
        prev=cur
    return prev[-1]
def unique_nonempty(df: pd.DataFrame, col: str) -> list[str]:
    if df.empty or col not in df.columns: return []
    vals=[str(x).strip() for x in df[col].dropna().astype(str).tolist()]
    return sorted({v for v in vals if v})
def select_with_other(label: str, base_options: list[str], existing_values: list[str]) -> str:
    merged=[o for o in base_options if o]
    for v in existing_values:
        if v and v not in merged: merged.append(v)
    sel=st.selectbox(label, ["— Select —"]+merged+["Other…"])
    if sel=="Other…": return st.text_input(f"{label} (Other)")
    return "" if sel=="— Select —" else sel

# =============================================================================
# DEVICE CATALOG + EMPLOYEES
# =============================================================================
DEVICE_CATALOG_WS = st.secrets.get("sheets", {}).get("catalog_ws", "inventorytracking")
DEVICE_CATALOG_COLS = ["Serial Number","Device Type","Brand","Model","CPU","Hard Drive 1","Hard Drive 2","Memory","GPU","Screen Size"]

@st.cache_data(ttl=120, show_spinner=False)
def _get_catalog_df() -> pd.DataFrame:
    sh=get_sh()
    try: ws=sh.worksheet(DEVICE_CATALOG_WS)
    except gspread.exceptions.WorksheetNotFound:
        try: ws=sh.worksheet(INVENTORY_WS)
        except gspread.exceptions.WorksheetNotFound:
            return pd.DataFrame(columns=DEVICE_CATALOG_COLS)
    df=pd.DataFrame(ws.get_all_records()); df=reorder_columns(df, DEVICE_CATALOG_COLS)
    df["__snorm"]=df["Serial Number"].astype(str).map(normalize_serial); return df

def get_device_from_catalog_by_serial(serial: str) -> dict:
    sn=normalize_serial(serial); df=_get_catalog_df()
    if df.empty: return {}
    hit=df[df["__snorm"]==sn]; return hit.iloc[0].to_dict() if not hit.empty else {}

def serial_is_unique_for_registration(serial: str) -> tuple[bool,str]:
    sn=normalize_serial(serial)
    inv=read_worksheet(INVENTORY_WS)
    if not inv.empty:
        inv["__sn"]=inv["Serial Number"].astype(str).map(normalize_serial)
        if sn in set(inv["__sn"]): return False,"Serial already exists in Inventory."
    pend=read_worksheet(PENDING_DEVICE_WS)
    if not pend.empty and "Serial Number" in pend.columns:
        stcol=pend.get("Approval Status","")
        if isinstance(stcol,pd.Series):
            mask=stcol.fillna("").astype(str).str.strip().str.lower().isin(["","pending"]); pend=pend[mask]
        pend["__sn"]=pend["Serial Number"].astype(str).map(normalize_serial)
        if sn in set(pend["__sn"]): return False,"Serial already exists in pending registrations."
    return True,""

def get_employee_names(active_only: bool=True) -> list[str]:
    df=read_worksheet(EMPLOYEE_WS)
    if df.empty: return []
    if active_only and "Active" in df.columns:
        df=df[df["Active"].astype(str).str.strip().str.lower().eq("active")]
    a=df.get("New Employeer",pd.Series(dtype=str)).astype(str).str.strip()
    b=df.get("Name",pd.Series(dtype=str)).astype(str).str.strip()
    return sorted({n for n in pd.concat([a,b]).tolist() if n})

def _get_employee_record(name: str) -> dict:
    df=read_worksheet(EMPLOYEE_WS)
    if df.empty or not name: return {}
    names=df.copy()
    names["__a"]=names.get("New Employeer","").astype(str).str.strip()
    names["__b"]=names.get("Name","").astype(str).str.strip()
    mask=(names["__a"]==str(name).strip()) | (names["__b"]==str(name).strip())
    return names[mask].iloc[0].to_dict() if mask.any() else {}

# =============================================================================
# PDF TEMPLATE + FILL HELPERS
# =============================================================================
TEMPLATE_FILE_ID = st.secrets.get("drive", {}).get("template_file_id", "1BdbeVEpDuS_hpQgxNLGij5sl01azT_zG")

def get_pdf_template_bytes() -> bytes:
    data=_download_drive_file_bytes(TEMPLATE_FILE_ID)
    if not data: st.error("ICT template form could not be downloaded. Check drive.template_file_id in secrets.")
    return data

def _make_specs(cpu, mem, h1, h2, gpu, screen) -> str:
    parts=[]; 
    if cpu: parts.append(f"CPU: {cpu}")
    if mem: parts.append(f"RAM: {mem}")
    if h1:  parts.append(f"Drive1: {h1}")
    if h2:  parts.append(f"Drive2: {h2}")
    if gpu: parts.append(f"GPU: {gpu}")
    if screen: parts.append(f"Screen: {screen}")
    return " | ".join(parts)

def fill_pdf_form(template_bytes: bytes, values: dict[str, str], *, flatten: bool = False) -> bytes:
    reader = PdfReader(io.BytesIO(template_bytes))
    writer = PdfWriter()
    for p in reader.pages:
        writer.add_page(p)

    # Fill first page fields (extend if your form has fields on other pages)
    try:
        writer.update_page_form_field_values(writer.pages[0], values)
    except Exception:
        pass

    # Ensure appearances are drawn so text shows everywhere
    if "/AcroForm" in reader.trailer["/Root"]:
        ac = reader.trailer["/Root"]["/AcroForm"]
        writer._root_object.update({NameObject("/AcroForm"): ac})
        writer._root_object["/AcroForm"].update({NameObject("/NeedAppearances"): BooleanObject(True)})
    else:
        writer._root_object.update({
            NameObject("/AcroForm"): DictionaryObject({NameObject("/NeedAppearances"): BooleanObject(True)})
        })

    if flatten:
        # 1) Mark all text fields as read-only
        try:
            fields = writer._root_object["/AcroForm"].get("/Fields")
            if fields:
                for f in fields:
                    obj = f.get_object()
                    if obj.get("/FT") == NameObject("/Tx"):
                        flags = int(obj.get("/Ff", 0))
                        obj.update({NameObject("/Ff"): flags | 1})  # ReadOnly bit
            # 2) Clear the field list (most viewers then treat it as non-editable content)
            writer._root_object["/AcroForm"].update({NameObject("/Fields"): ArrayObject()})
        except Exception:
            pass

    out = io.BytesIO()
    writer.write(out)
    out.seek(0)
    return out.read()


def make_form_filename(kind: str, serial: str, counter: int=1) -> str:
    s_norm=normalize_serial(serial); today=datetime.now().strftime("%Y%m%d")
    return f"HO-JED-{kind}-{s_norm}-{counter:04d}-{today}.pdf"

def build_registration_field_map(device_row: dict) -> dict:
    frm=["","","","","",""]; to=["","","","","",""]
    spec=_make_specs(device_row.get("CPU",""),device_row.get("Memory",""),device_row.get("Hard Drive 1",""),
                     device_row.get("Hard Drive 2",""),device_row.get("GPU",""),device_row.get("Screen Size",""))
    dev=[device_row.get("Device Type",""),device_row.get("Brand",""),device_row.get("Model",""),spec,device_row.get("Serial Number","")]
    mapping={}
    for i,val in enumerate(frm,start=0): mapping[f"Text Field{i}"]=val
    for i,val in enumerate(to, start=6): mapping[f"Text Field{i}"]=val
    for i,val in enumerate(dev,start=12): mapping[f"Text Field{i}"]=val
    return mapping

def build_transfer_field_map(device_row: dict, from_name: str, to_name: str) -> dict:
    from_emp=_get_employee_record(from_name); to_emp=_get_employee_record(to_name)
    frm=[ from_emp.get("Name") or from_emp.get("New Employeer","") or from_name,
          from_emp.get("Mobile Number",""),
          from_emp.get("Email") or from_emp.get("Email Address",""),
          from_emp.get("Department",""),
          datetime.now().strftime("%Y-%m-%d"),
          from_emp.get("Location (KSA)") or from_emp.get("Project",""), ]
    to=[ to_emp.get("Name") or to_emp.get("New Employeer","") or to_name,
         to_emp.get("Mobile Number",""),
         to_emp.get("Email") or to_emp.get("Email Address",""),
         to_emp.get("Department",""),
         datetime.now().strftime("%Y-%m-%d"),
         to_emp.get("Location (KSA)") or to_emp.get("Project",""), ]
    spec=_make_specs(device_row.get("CPU",""),device_row.get("Memory",""),device_row.get("Hard Drive 1",""),
                     device_row.get("Hard Drive 2",""),device_row.get("GPU",""),device_row.get("Screen Size",""))
    dev=[device_row.get("Device Type",""),device_row.get("Brand",""),device_row.get("Model",""),spec,device_row.get("Serial Number","")]
    mapping={}
    for i,val in enumerate(frm,start=0): mapping[f"Text Field{i}"]=val
    for i,val in enumerate(to, start=6): mapping[f"Text Field{i}"]=val
    for i,val in enumerate(dev,start=12): mapping[f"Text Field{i}"]=val
    return mapping

# =============================================================================
# VIEWS
# =============================================================================
def employees_view_tab():
    st.subheader("📇 Employees (mainlists)")
    df=read_worksheet(EMPLOYEE_WS)
    if df.empty: st.info("No employees found in 'mainlists'.")
    else: st.dataframe(df, use_container_width=True, hide_index=True)

def inventory_tab():
    st.subheader("📋 Inventory")
    df=read_worksheet(INVENTORY_WS)
    if df.empty: st.warning("Inventory is empty.")
    else:
        if st.session_state.role=="Admin": st.dataframe(df, use_container_width=True)
        else: st.dataframe(df, use_container_width=True, hide_index=True)

def register_device_tab():
    st.subheader("📝 Register New Device")
    pref = ss.get("reg_prefill", {})

    with st.form("register_device", clear_on_submit=False):
        r1c1,r1c2,r1c3 = st.columns(3)
        with r1c1: serial = st.text_input("Serial Number *", value=pref.get("Serial Number",""))
        with r1c2:
            st.caption("Owner set during TRANSFER. Kept Unassigned at registration.")
            _ = st.selectbox("Assigned to", [UNASSIGNED_LABEL], index=0, disabled=True)
            assigned_to = UNASSIGNED_LABEL
        with r1c3: device = st.text_input("Device Type *", value=pref.get("Device Type",""), disabled=True)

        r2c1,r2c2,r2c3 = st.columns(3)
        with r2c1: brand  = st.text_input("Brand", value=pref.get("Brand",""), disabled=True)
        with r2c2: model  = st.text_input("Model", value=pref.get("Model",""), disabled=True)
        with r2c3: cpu    = st.text_input("CPU", value=pref.get("CPU",""), disabled=True)

        r3c1,r3c2,r3c3 = st.columns(3)
        with r3c1: mem   = st.text_input("Memory", value=pref.get("Memory",""), disabled=True)
        with r3c2: hdd1  = st.text_input("Hard Drive 1", value=pref.get("Hard Drive 1",""), disabled=True)
        with r3c3: hdd2  = st.text_input("Hard Drive 2", value=pref.get("Hard Drive 2",""), disabled=True)

        r4c1,r4c2,r4c3 = st.columns(3)
        with r4c1: gpu   = st.text_input("GPU", value=pref.get("GPU",""), disabled=True)
        with r4c2: screen= st.text_input("Screen Size", value=pref.get("Screen Size",""), disabled=True)
        with r4c3: email = st.text_input("Email Address", value="", disabled=True)

        r5c1,r5c2,r5c3 = st.columns(3)
        with r5c1: contact= st.text_input("Contact Number", value="", disabled=True)
        with r5c2: dept   = st.text_input("Department", value="", disabled=True)
        with r5c3: location=st.text_input("Location", value="", disabled=True)

        r6c1,r6c2 = st.columns([1,2])
        with r6c1: office = st.text_input("Office", value="", disabled=True)
        with r6c2: notes  = st.text_area("Notes", value="", height=60, disabled=True)

        pdf_file = st.file_uploader("Signed ICT Equipment Form (PDF) — required for non-admin", type=["pdf"], key="reg_pdf")

        st.markdown("---")
        load_clicked   = st.form_submit_button("🔍 Load from catalog", use_container_width=True)
        submitted      = st.form_submit_button("Save Device", type="primary", use_container_width=True)

    if load_clicked:
        if not serial.strip(): st.error("Enter a Serial Number first, then click Load.")
        else:
            row=get_device_from_catalog_by_serial(serial)
            if not row: st.error("Serial not found in catalog.")
            else:
                ss.reg_prefill=row; st.success("Loaded device details from catalog."); st.rerun()

    # Offer auto-filled registration PDF (From/To blank)
    if serial.strip():
        try:
            tpl=get_pdf_template_bytes()
            if tpl:
                device_row_for_pdf={"Serial Number":serial.strip(),"Device Type":device.strip(),"Brand":brand.strip(),
                                    "Model":model.strip(),"CPU":cpu.strip(),"Hard Drive 1":hdd1.strip(),
                                    "Hard Drive 2":hdd2.strip(),"Memory":mem.strip(),"GPU":gpu.strip(),"Screen Size":screen.strip()}
                reg_map=build_registration_field_map(device_row_for_pdf)
                filled=fill_pdf_form(tpl, reg_map, flatten=False)
                st.download_button("🖨️ Download ICT Equipment Form (registration — From/To blank)",
                    filled, file_name=make_form_filename("REG", serial), mime="application/pdf",
                    key=f"dl_reg_{normalize_serial(serial)}")
                st.caption("Download → sign → re-upload above (non-admin).")
        except Exception as e:
            st.warning(f"Could not prepare auto-filled form: {e}")

    if ss.get("reg_pdf"): ss.reg_pdf_ref=ss.reg_pdf
    if ss.reg_pdf_ref:
        st.caption("Preview: Signed ICT Form (uploaded)")
        try: pdf_viewer(input=ss.reg_pdf_ref.getvalue(), width=700, key="viewer_reg")
        except Exception: pass

    if submitted:
        if not serial.strip(): st.error("Serial Number is required."); return
        ok,msg = serial_is_unique_for_registration(serial)
        if not ok: st.error(f"❌ {msg}"); return
        if not ss.get("reg_prefill"): st.error("Load device details from catalog first."); return

        now_str=datetime.now().strftime(DATE_FMT); actor=st.session_state.get("username","")
        row = {
            "Serial Number": ss.reg_prefill.get("Serial Number","").strip() or serial.strip(),
            "Device Type": ss.reg_prefill.get("Device Type",""), "Brand": ss.reg_prefill.get("Brand",""),
            "Model": ss.reg_prefill.get("Model",""), "CPU": ss.reg_prefill.get("CPU",""),
            "Hard Drive 1": ss.reg_prefill.get("Hard Drive 1",""), "Hard Drive 2": ss.reg_prefill.get("Hard Drive 2",""),
            "Memory": ss.reg_prefill.get("Memory",""), "GPU": ss.reg_prefill.get("GPU",""),
            "Screen Size": ss.reg_prefill.get("Screen Size",""),
            "Current user": UNASSIGNED_LABEL, "Previous User":"", "TO":"",
            "Department":"", "Email Address":"", "Contact Number":"", "Location":"", "Office":"", "Notes":"",
            "Date issued": now_str, "Registered by": actor,
        }
        is_admin = st.session_state.get("role")=="Admin"
        if not is_admin and pdf_file is None:
            st.error("Signed ICT form is required for submission."); return

        if is_admin and pdf_file is None:
            inv_fresh=read_worksheet(INVENTORY_WS)
            inv_out=pd.concat([inv_fresh if not inv_fresh.empty else pd.DataFrame(columns=INVENTORY_COLS),
                               pd.DataFrame([row])], ignore_index=True)
            inv_out=reorder_columns(inv_out, INVENTORY_COLS); write_worksheet(INVENTORY_WS, inv_out)
            ss.reg_prefill={}; st.success("✅ Device registered and added to Inventory.")
        else:
            link,fid=upload_pdf_and_link(pdf_file, prefix=f"device_{normalize_serial(serial)}")
            if not fid: return
            pending={**row,"Approval Status":"Pending","Approval PDF":link,"Approval File ID":fid,
                     "Submitted by":actor,"Submitted at":now_str,"Approver":"","Decision at":""}
            append_to_worksheet(PENDING_DEVICE_WS, pd.DataFrame([pending]))
            ss.reg_prefill={}; st.success("🕒 Submitted for admin approval.")

def transfer_tab():
    st.subheader("🔁 Transfer Device")
    inv_df=read_worksheet(INVENTORY_WS)
    if inv_df.empty: st.warning("Inventory is empty."); return

    serials=sorted(inv_df["Serial Number"].dropna().astype(str).unique())
    emp_names=get_employee_names(active_only=True)

    c1,c2=st.columns([2,2])
    with c1:
        chosen_serial = st.selectbox("Serial Number", ["— Select —"]+serials)
        chosen_serial = None if chosen_serial=="— Select —" else chosen_serial
    with c2:
        new_owner = st.selectbox("New Owner (from Employees)", ["— Select —"]+emp_names)
        new_owner = "" if new_owner=="— Select —" else new_owner

    device_row={}; prev_owner_name=""
    if chosen_serial:
        match=inv_df[inv_df["Serial Number"].astype(str)==chosen_serial]
        if not match.empty:
            device_row=match.iloc[0].to_dict()
            prev_owner_name=str(device_row.get("Current user","") or "")
            st.caption("Current device details")
            st.json({k: device_row.get(k,"") for k in ["Device Type","Brand","Model","CPU","Memory","Hard Drive 1","Hard Drive 2","GPU","Screen Size","Current user"]})

    if new_owner and prev_owner_name and normalize_serial(new_owner)==normalize_serial(prev_owner_name):
        st.warning("New Owner is the same as the current owner.")

    try:
        if chosen_serial and new_owner and device_row:
            tpl=get_pdf_template_bytes()
            if tpl:
                tr_map=build_transfer_field_map(device_row, prev_owner_name, new_owner)
                filled=fill_pdf_form(tpl, tr_map, flatten=False)
                st.download_button("🖨️ Download Transfer ICT Form (auto-filled)",
                    filled, file_name=make_form_filename("TRF", chosen_serial), mime="application/pdf",
                    key=f"dl_trf_{normalize_serial(chosen_serial)}")
                st.caption("Download → sign → upload below, then submit.")
    except Exception as e:
        st.warning(f"Could not prepare transfer form: {e}")

    signed_pdf = st.file_uploader("Signed ICT Transfer Form (PDF) — required for non-admin", type=["pdf"], key="transfer_pdf")

    is_admin = st.session_state.get("role")=="Admin"
    submit_label = "Transfer Now" if is_admin else "Submit Transfer for Approval"
    can_submit = bool(chosen_serial and new_owner and (is_admin or signed_pdf is not None))

    if st.button(submit_label, type="primary", disabled=not can_submit):
        if not chosen_serial: st.error("Select a Serial Number."); return
        if not new_owner: st.error("Select the New Owner from Employees."); return
        match=inv_df[inv_df["Serial Number"].astype(str)==chosen_serial]
        if match.empty: st.error("Serial not found in Inventory."); return

        idx=match.index[0]; prev_user=str(inv_df.loc[idx,"Current user"] or "")
        now_str=datetime.now().strftime(DATE_FMT); actor=st.session_state.get("username","")

        if is_admin and signed_pdf is None:
            inv_df.loc[idx,"Previous User"]=prev_user
            inv_df.loc[idx,"Current user"]=new_owner.strip()
            inv_df.loc[idx,"TO"]=new_owner.strip()
            inv_df.loc[idx,"Date issued"]=now_str
            inv_df.loc[idx,"Registered by"]=actor
            write_worksheet(INVENTORY_WS, reorder_columns(inv_df, INVENTORY_COLS))

            log_row={"Device Type":inv_df.loc[idx,"Device Type"],"Serial Number":chosen_serial,"From owner":prev_user,
                     "To owner":new_owner.strip(),"Date issued":now_str,"Registered by":actor}
            append_to_worksheet(TRANSFERLOG_WS, pd.DataFrame([log_row]))
            st.success(f"✅ Transfer saved: {prev_user or '(blank)'} → {new_owner.strip()}"); return

        link,fid=upload_pdf_and_link(signed_pdf, prefix=f"transfer_{normalize_serial(chosen_serial)}")
        if not fid: return
        pend={"Device Type":inv_df.loc[idx,"Device Type"],"Serial Number":chosen_serial,"From owner":prev_user,
              "To owner":new_owner.strip(),"Date issued":now_str,"Registered by":actor,
              "Approval Status":"Pending","Approval PDF":link,"Approval File ID":fid,
              "Submitted by":actor,"Submitted at":now_str,"Approver":"","Decision at":""}
        append_to_worksheet(PENDING_TRANSFER_WS, pd.DataFrame([pend]))
        st.success("🕒 Transfer submitted for admin approval.")

def history_tab():
    st.subheader("📜 Transfer Log")
    df=read_worksheet(TRANSFERLOG_WS)
    if df.empty: st.info("No transfer history found.")
    else: st.dataframe(df, use_container_width=True, hide_index=True)

def employee_register_tab():
    st.subheader("🧑‍💼 Register New Employee (mainlists)")
    emp_df=read_worksheet(EMPLOYEE_WS)
    try:
        ids=pd.to_numeric(emp_df["Employee ID"], errors="coerce").dropna().astype(int); next_id=str(ids.max()+1) if len(ids) else str(len(emp_df)+1)
    except Exception: next_id=str(len(emp_df)+1)

    dept_existing=unique_nonempty(emp_df,"Department"); pos_existing=unique_nonempty(emp_df,"Position")
    proj_existing=unique_nonempty(emp_df,"Project"); loc_existing=unique_nonempty(emp_df,"Location (KSA)")
    ksa_cities=["Riyadh","Jeddah","Dammam","Khobar","Dhahran","Jubail","Mecca","Medina","Abha","Tabuk","Hail","Buraidah"]

    with st.form("register_employee", clear_on_submit=True):
        r1c1,r1c2,r1c3=st.columns(3)
        with r1c1: emp_name=st.text_input("New Employeer *")
        with r1c2: emp_id=st.text_input("Employee ID", help=f"Suggested next ID: {next_id}")
        with r1c3: new_sig=st.selectbox("New Signature", ["— Select —","Yes","No","Requested"])

        r2c1,r2c2=st.columns(2)
        with r2c1: Email=st.text_input("Email")
        with r2c2: active=st.selectbox("Active", ["Active","Inactive","Onboarding","Resigned"])

        r3c1,r3c2,r3c3=st.columns(3)
        with r3c1: position=select_with_other("Position", ["Engineer","Technician","Manager","Coordinator"], pos_existing)
        with r3c2: department=select_with_other("Department", ["IT","HR","Finance","Operations","Procurement"], dept_existing)
        with r3c3: location_ksa=select_with_other("Location (KSA)", ksa_cities, loc_existing)

        r4c1,r4c2,r4c3=st.columns(3)
        with r4c1: project=select_with_other("Project", ["Head Office","Site"], proj_existing)
        with r4c2: teams=st.selectbox("Microsoft Teams", ["— Select —","Yes","No","Requested"])
        with r4c3: mobile=st.text_input("Mobile Number")

        submitted=st.form_submit_button("Save Employee", type="primary")

    if submitted:
        if not emp_name.strip(): st.error("New Employeer is required."); return
        if emp_id.strip() and not emp_df.empty and emp_id.strip() in emp_df["Employee ID"].astype(str).values:
            st.error(f"Employee ID '{emp_id}' already exists."); return
        row={"New Employeer":emp_name.strip(),"Name":emp_name.strip(),"Employee ID":emp_id.strip() if emp_id.strip() else next_id,
             "New Signature": new_sig if new_sig!="— Select —" else "","Email":Email.strip(),"Active":active.strip(),
             "Position":position.strip(),"Department":department.strip(),"Location (KSA)":location_ksa.strip(),
             "Project":project.strip(),"Microsoft Teams":teams if teams!="— Select —" else "","Mobile Number":mobile.strip()}
        new_df=pd.concat([emp_df, pd.DataFrame([row])], ignore_index=True) if not emp_df.empty else pd.DataFrame([row])
        new_df=reorder_columns(new_df, EMPLOYEE_CANON_COLS); write_worksheet(EMPLOYEE_WS, new_df); st.success("✅ Employee saved.")

def approvals_tab():
    st.subheader("✅ Approvals (Admin)")
    if st.session_state.get("role")!="Admin": st.info("Only Admins can view approvals."); return

    pending_dev=read_worksheet(PENDING_DEVICE_WS); pending_tr=read_worksheet(PENDING_TRANSFER_WS)

    st.markdown("### Pending Device Registrations")
    df_dev=pending_dev[pending_dev.get("Approval Status","").astype(str).str.strip().str.lower().isin(["","pending"])].reset_index(drop=True) if not pending_dev.empty else pending_dev
    if df_dev.empty: st.success("No pending device registrations.")
    else:
        for i,row in df_dev.iterrows():
            with st.expander(f"{row['Device Type']} — SN {row['Serial Number']} (by {row['Submitted by']})", expanded=False):
                c1,c2=st.columns([3,2])
                with c1:
                    st.json({k: row.get(k,"") for k in INVENTORY_COLS})
                    fid=str(row.get("Approval File ID","")).strip(); link=str(row.get("Approval PDF","")).strip()
                    pdf_bytes = _fetch_public_pdf_bytes(fid, link) or _download_drive_file_bytes(fid)
                    if pdf_bytes:
                        st.caption("Approval PDF Preview"); 
                        try: pdf_viewer(input=pdf_bytes, width=700, key=f"viewer_dev_{i}")
                        except Exception: pass
                    elif link: st.markdown(f"[Open Approval PDF]({link})")
                    st.caption(f"File ID: {fid or '—'}")
                with c2:
                    reviewed=True
                    if REQUIRE_REVIEW_CHECK: reviewed=st.checkbox("I reviewed the attached PDF", key=f"review_dev_{i}")
                    a_col,r_col=st.columns(2)
                    if a_col.button("Approve", key=f"approve_dev_{i}", disabled=not reviewed): _approve_device_row(row)
                    if r_col.button("Reject", key=f"reject_dev_{i}"): _reject_row(PENDING_DEVICE_WS, row)

    st.markdown("---"); st.markdown("### Pending Transfers")
    df_tr=pending_tr[pending_tr.get("Approval Status","").astype(str).str.strip().str.lower().isin(["","pending"])].reset_index(drop=True) if not pending_tr.empty else pending_tr
    if df_tr.empty: st.success("No pending transfers.")
    else:
        for i,row in df_tr.iterrows():
            with st.expander(f"SN {row['Serial Number']}: {row['From owner']} → {row['To owner']} (by {row['Submitted by']})", expanded=False):
                c1,c2=st.columns([3,2])
                with c1:
                    st.json({k: row.get(k,"") for k in LOG_COLS})
                    fid=str(row.get("Approval File ID","")).strip(); link=str(row.get("Approval PDF","")).strip()
                    pdf_bytes = _fetch_public_pdf_bytes(fid, link) or _download_drive_file_bytes(fid)
                    if pdf_bytes:
                        st.caption("Approval PDF Preview"); 
                        try: pdf_viewer(input=pdf_bytes, width=700, key=f"viewer_tr_{i}")
                        except Exception: pass
                    elif link: st.markdown(f"[Open Approval PDF]({link})")
                    st.caption(f"File ID: {fid or '—'}")
                with c2:
                    reviewed=True
                    if REQUIRE_REVIEW_CHECK: reviewed=st.checkbox("I reviewed the attached PDF", key=f"review_tr_{i}")
                    a_col,r_col=st.columns(2)
                    if a_col.button("Approve", key=f"approve_tr_{i}", disabled=not reviewed): _approve_transfer_row(row)
                    if r_col.button("Reject", key=f"reject_tr_{i}"): _reject_row(PENDING_TRANSFER_WS, row)

def _approve_device_row(row: pd.Series):
    inv=read_worksheet(INVENTORY_WS); now_str=datetime.now().strftime(DATE_FMT); approver=st.session_state.get("username","")
    new_row={k: row.get(k,"") for k in INVENTORY_COLS}; new_row["Registered by"]=approver or new_row.get("Registered by",""); new_row["Date issued"]=now_str
    inv_out=pd.concat([inv if not inv.empty else pd.DataFrame(columns=INVENTORY_COLS), pd.DataFrame([new_row])], ignore_index=True)
    write_worksheet(INVENTORY_WS, inv_out); _mark_decision(PENDING_DEVICE_WS, row, status="Approved"); st.success("✅ Device approved and added to Inventory.")

def _approve_transfer_row(row: pd.Series):
    inv=read_worksheet(INVENTORY_WS)
    if inv.empty: st.error("Inventory is empty; cannot apply transfer."); return
    sn=str(row.get("Serial Number","")); match=inv[inv["Serial Number"].astype(str)==sn]
    if match.empty: st.error("Serial not found in Inventory."); return
    idx=match.index[0]; now_str=datetime.now().strftime(DATE_FMT); approver=st.session_state.get("username","")
    prev_user=str(inv.loc[idx,"Current user"] or "")
    inv.loc[idx,"Previous User"]=prev_user
    inv.loc[idx,"Current user"]=str(row.get("To owner",""))
    inv.loc[idx,"TO"]=str(row.get("To owner",""))
    inv.loc[idx,"Date issued"]=now_str
    inv.loc[idx,"Registered by"]=approver
    write_worksheet(INVENTORY_WS, inv)
    log_row={k: row.get(k,"") for k in LOG_COLS}; log_row["Date issued"]=now_str; log_row["Registered by"]=approver
    append_to_worksheet(TRANSFERLOG_WS, pd.DataFrame([log_row]))
    _mark_decision(PENDING_TRANSFER_WS, row, status="Approved"); st.success("✅ Transfer approved and applied.")

def _mark_decision(ws_title: str, row: pd.Series, *, status: str):
    df=read_worksheet(ws_title); key_cols=[c for c in ["Serial Number","Submitted at","Submitted by","To owner"] if c in df.columns]
    mask=pd.Series([True]*len(df))
    for c in key_cols: mask &= df[c].astype(str)==str(row.get(c,""))
    if not mask.any() and "Serial Number" in df.columns:
        mask=df["Serial Number"].astype(str)==str(row.get("Serial Number",""))
    idxs=df[mask].index.tolist()
    if not idxs: return
    idx=idxs[0]; df.loc[idx,"Approval Status"]=status; df.loc[idx,"Approver"]=st.session_state.get("username",""); df.loc[idx,"Decision at"]=datetime.now().strftime(DATE_FMT)
    write_worksheet(ws_title, df)

def _reject_row(ws_title: str, row: pd.Series):
    _mark_decision(ws_title, row, status="Rejected"); st.info("❌ Request rejected.")

def export_tab():
    st.subheader("⬇️ Export (always fresh)")
    inv=read_worksheet(INVENTORY_WS); log=read_worksheet(TRANSFERLOG_WS); emp=read_worksheet(EMPLOYEE_WS)
    st.caption(f"Last fetched: {datetime.now().strftime(DATE_FMT)}")
    c1,c2,c3=st.columns(3)
    with c1: st.download_button("Inventory CSV", inv.to_csv(index=False).encode("utf-8"), "inventory.csv","text/csv")
    with c2: st.download_button("Transfer Log CSV", log.to_csv(index=False).encode("utf-8"), "transfer_log.csv","text/csv")
    with c3: st.download_button("Employees CSV", emp.to_csv(index=False).encode("utf-8"), "employees.csv","text/csv")
    st.markdown("---"); st.markdown("**Approvals (Accepted)**")
    approved_dev=read_worksheet(PENDING_DEVICE_WS); approved_tr=read_worksheet(PENDING_TRANSFER_WS)
    if not approved_dev.empty: approved_dev=approved_dev[approved_dev.get("Approval Status","").astype(str)=="Approved"]
    if not approved_tr.empty: approved_tr=approved_tr[approved_tr.get("Approval Status","").astype(str)=="Approved"]
    c4,c5=st.columns(2)
    with c4:
        if not approved_dev.empty: st.download_button("Approved Device Submissions CSV", approved_dev.to_csv(index=False).encode("utf-8"), "approved_device_submissions.csv","text/csv")
        else: st.caption("No approved device submissions yet.")
    with c5:
        if not approved_tr.empty: st.download_button("Approved Transfer Submissions CSV", approved_tr.to_csv(index=False).encode("utf-8"), "approved_transfer_submissions.csv","text/csv")
        else: st.caption("No approved transfer submissions yet.")

# =============================================================================
# MAIN
# =============================================================================
def _config_check_ui():
    try:
        sa=_load_sa_info(); sa_email=sa.get("client_email","(unknown)"); st.caption(f"Service Account: {sa_email}")
    except Exception as e:
        st.error("Google Service Account credentials are missing."); st.code(str(e))
        st.markdown("- Put Service Account JSON under `st.secrets['gcp_service_account']` or env `GOOGLE_SERVICE_ACCOUNT_JSON`.\n"
                    "- Ensure it includes **private_key** and **client_email**.\n"
                    "- Share the Google Sheet URL in `st.secrets['sheets']['url']` with the service account (Editor).\n"
                    "- Add `[drive].template_file_id` for ICT form and `[drive].approvals` for uploads.")
        st.stop()
    try: _=get_sh()
    except Exception as e:
        st.error("Cannot open the spreadsheet with the configured Service Account."); st.code(str(e))
        st.info("Share the sheet with the Service Account email above and try again."); st.stop()

def run_app():
    render_header(); hide_table_toolbar_for_non_admin(); _config_check_ui()
    if st.session_state.role=="Admin":
        tabs=st.tabs(["🧑‍💼 Employee Register","📇 View Employees","📝 Register Device","📋 View Inventory","🔁 Transfer Device","📜 Transfer Log","✅ Approvals","⬇️ Export"])
        with tabs[0]: employee_register_tab()
        with tabs[1]: employees_view_tab()
        with tabs[2]: register_device_tab()
        with tabs[3]: inventory_tab()
        with tabs[4]: transfer_tab()
        with tabs[5]: history_tab()
        with tabs[6]: approvals_tab()
        with tabs[7]: export_tab()
    else:
        tabs=st.tabs(["📝 Register Device","🔁 Transfer Device","📋 View Inventory","📜 Transfer Log"])
        with tabs[0]: register_device_tab()
        with tabs[1]: transfer_tab()
        with tabs[2]: inventory_tab()
        with tabs[3]: history_tab()

# =============================================================================
# ENTRY
# =============================================================================
if "authenticated" not in st.session_state: st.session_state.authenticated=False
if "just_logged_out" not in st.session_state: st.session_state.just_logged_out=False
if not st.session_state.authenticated and not st.session_state.get("just_logged_out"):
    payload=_read_cookie()
    if payload:
        st.session_state.authenticated=True
        st.session_state.username=payload["u"]; st.session_state.name=payload["u"]; st.session_state.role=payload.get("r","")
if st.session_state.authenticated:
    run_app()
else:
    st.subheader("🔐 Sign In")
    username=st.text_input("Username"); password=st.text_input("Password", type="password")
    if st.button("Login", type="primary"):
        user=USERS.get(username)
        if user and _verify_password(password, user["password"]): do_login(username, user.get("role","Staff"))
        else: st.error("❌ Invalid username or password.")
