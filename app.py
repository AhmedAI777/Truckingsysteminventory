# app.py
import os, json, time, hmac, base64, hashlib
from datetime import datetime
from typing import Dict, Optional, Tuple, List
import numpy as np
import pandas as pd
import streamlit as st
from streamlit_gsheets import GSheetsConnection

APP_TITLE = "Tracking Inventory Management System"
SUBTITLE  = "Advanced Construction"
DATE_FMT  = "%Y-%m-%d %H:%M:%S"
st.set_page_config(page_title=APP_TITLE, layout="wide")

# ---------------- AUTH (keeps you signed in across refresh) ----------------
DEFAULT_ADMIN_PW = "admin@2025"
DEFAULT_STAFF_PW = "staff@2025"
ADMINS: Dict[str,str] = dict(getattr(st.secrets.get("auth", {}), "admins", {})) if hasattr(st,"secrets") else {}
STAFFS: Dict[str,str] = dict(getattr(st.secrets.get("auth", {}), "staff", {})) if hasattr(st,"secrets") else {}
if not ADMINS: ADMINS = {f"admin{i}": DEFAULT_ADMIN_PW for i in range(1,6)}
if not STAFFS: STAFFS = {f"staff{i}": DEFAULT_STAFF_PW for i in range(1,16)}
AUTH_SECRET = (st.secrets.get("auth", {}).get("secret") if hasattr(st,"secrets") else None) or "change-me"

def _now(): return int(time.time())
def _tok(u,r,days=30): 
    raw = json.dumps({"u":u,"r":r,"exp":_now()+days*86400}, separators=(",",":")).encode()
    sig = hmac.new(AUTH_SECRET.encode(), raw, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(raw+sig).decode()
def _parse(t:str)->Optional[Tuple[str,str,int]]:
    try:
        b = base64.urlsafe_b64decode(t.encode()); raw, sig = b[:-32], b[-32:]
        if not hmac.compare_digest(sig, hmac.new(AUTH_SECRET.encode(), raw, hashlib.sha256).digest()): return None
        p = json.loads(raw.decode());  return (p["u"], p["r"], p["exp"]) if p["exp"]>_now() else None
    except: return None
def _getq(): 
    try: return st.query_params.get("auth")
    except: 
        v = st.experimental_get_query_params().get("auth",[None]); return v[0] if isinstance(v,list) else v
def _setq(t:Optional[str]):
    try:
        if t is None: st.query_params.pop("auth", None)
        else: st.query_params["auth"] = t
    except:
        if t is None: st.experimental_set_query_params()
        else: st.experimental_set_query_params(auth=t)
def _auth(u,p):
    if u in ADMINS and ADMINS[u]==p: return "admin"
    if u in STAFFS and STAFFS[u]==p: return "staff"
    return None

def ensure_auth():
    if "auth_user" not in st.session_state: st.session_state.auth_user=None; st.session_state.auth_role=None
    if not st.session_state.auth_user:
        t=_getq(); parsed=_parse(t) if t else None
        if parsed:
            u,r,exp=parsed; st.session_state.auth_user=u; st.session_state.auth_role=r
            if exp-_now() < 3*86400: _setq(_tok(u,r))
            return
    if st.session_state.auth_user: return
    st.markdown(f"## {APP_TITLE}"); st.caption(SUBTITLE); st.info("Please sign in to continue.")
    with st.form("login"): 
        u=st.text_input("Username"); p=st.text_input("Password", type="password")
        if st.form_submit_button("Login", type="primary"):
            r=_auth(u.strip(), p)
            if r: st.session_state.auth_user=u.strip(); st.session_state.auth_role=r; _setq(_tok(u.strip(), r)); st.rerun()
            else: st.error("Invalid username or password.")
    st.stop()

def logout_button():
    if st.button("Logout"):
        st.session_state.pop("auth_user", None); st.session_state.pop("auth_role", None); _setq(None); st.rerun()

# ---------------- SHEETS CONNECTION (always pass spreadsheet=) ----------------
SPREADSHEET_URL = (
    st.secrets.get("connections", {}).get("gsheets", {}).get("spreadsheet")
    if hasattr(st,"secrets") else None
) or "https://docs.google.com/spreadsheets/d/1SHp6gOW4ltsyOT41rwo85e_LELrHkwSwKN33K6XNHFI/edit"

INVENTORY_WS   = str(st.secrets.get("inventory_tab",   "0"))          # tab gid or name
TRANSFERLOG_WS = str(st.secrets.get("transferlog_tab", "405007082"))  # tab gid or name
conn = st.connection("gsheets", type=GSheetsConnection)

def _has_sa()->bool:
    try: return bool(st.secrets["connections"]["gsheets"].get("service_account"))
    except: return False
IS_READ_ONLY = not _has_sa()

def _ensure_cols(df: pd.DataFrame, cols: list[str]) -> pd.DataFrame:
    if df is None or df.empty: return pd.DataFrame(columns=cols)
    df = df.fillna(""); 
    for c in cols:
        if c not in df.columns: df[c] = ""
    return df[cols + [c for c in df.columns if c not in cols]]

def read_ws(ws: str, cols: list[str], ttl: int=0) -> pd.DataFrame:
    # Try as-is; if 400 & looks like a name, show hint to switch to gid or publish / SA
    try:
        df = conn.read(spreadsheet=SPREADSHEET_URL, worksheet=(int(ws) if ws.isdigit() else ws), ttl=ttl)
        return _ensure_cols(df, cols)
    except Exception as e:
        # surface better message for 400s
        msg = str(e)
        if "HTTP Error 400" in msg:
            st.warning(
                "Google returned **HTTP 400** for this worksheet.\n\n"
                "- If using **public read-only**, set the sheet to *Anyone with link* and **Publish to the web** (Entire document), "
                "and prefer **GIDs** (e.g. `inventory_tab='0'`).\n"
                "- Or configure a **Service Account** and share the sheet with it (Editor)."
            )
        raise

def safe_read_ws(ws: str, cols: list[str], label: str, ttl: int=0) -> pd.DataFrame:
    try: return read_ws(ws, cols, ttl=ttl)
    except Exception as e:
        st.warning(f"Couldn’t read **{label}** from Google Sheets. Error: {type(e).__name__}")
        return _ensure_cols(None, cols)

def write_ws(ws: str, df: pd.DataFrame) -> Tuple[bool, Optional[str]]:
    try:
        conn.update(spreadsheet=SPREADSHEET_URL, worksheet=(int(ws) if ws.isdigit() else ws), data=df)
        return True, None
    except Exception as e:
        return False, str(e)

def commit_writes(writes: List[Tuple[str, pd.DataFrame]], show_error: bool) -> bool:
    for ws, df in writes:
        ok, err = write_ws(ws, df)
        if not ok:
            if show_error:
                st.error(
                    "Can't write to Google Sheet (public or missing Service Account permissions).\n"
                    "Add a **service_account** in secrets and share the Sheet with that account (Editor).\n\n"
                    f"Details: {err}"
                )
            return False
    return True

# ---------------- COLUMNS ----------------
ALL_COLS = [
    "Serial Number","Device Type","Brand","Model","CPU",
    "Hard Drive 1","Hard Drive 2","Memory","GPU","Screen Size",
    "USER","Previous User","TO","Department","Email Address",
    "Contact Number","Location","Office","Notes","Date issued","Registered by"
]
LOG_COLS = ["Device Type","Serial Number","From owner","To owner","Date issued","Registered by"]

def parse_dates_safe(s: pd.Series) -> pd.Series:
    dt = pd.to_datetime(s, errors="coerce", format=DATE_FMT)
    return dt.dt.strftime(DATE_FMT).replace("NaT","")

def nice_display(df: pd.DataFrame)->pd.DataFrame:
    if df is None or df.empty: return df
    out = df.copy()
    for c in out.columns:
        try:
            if np.issubdtype(out[c].dtype, np.datetime64) or "date" in c.lower():
                out[c] = parse_dates_safe(out[c].astype(str))
        except: pass
    return out.replace({np.nan:""})

# ---------------- UI ----------------
ensure_auth()
USER = st.session_state.auth_user
ROLE = st.session_state.auth_role
IS_ADMIN = ROLE == "admin"

# Hide toolbar for staff
if not IS_ADMIN:
    st.markdown("""
    <style>
      div[data-testid="stDataFrame"] div[data-testid="stElementToolbar"]{display:none !important;}
    </style>""", unsafe_allow_html=True)

# header
c1,c2,c3 = st.columns([1.2,6,3])
with c1:
    if os.path.exists("company_logo.jpeg"): st.image("company_logo.jpeg", use_container_width=True)
with c2:
    st.markdown(f"### {APP_TITLE}"); st.caption(SUBTITLE)
with c3:
    st.markdown(f"**Welcome, {USER}**  \nRole: **{ROLE.capitalize()}**")
    logout_button()
st.markdown("---")

# tabs
tabs = st.tabs(["📦 View Inventory","🔄 Transfer Device","📜 Transfer Log"])

# View
with tabs[0]:
    st.subheader("Current Inventory")
    inv = safe_read_ws(INVENTORY_WS, ALL_COLS, "inventory", ttl=0)
    if not inv.empty and "Date issued" in inv.columns:
        inv["Date issued"] = parse_dates_safe(inv["Date issued"].astype(str))
        _ts = pd.to_datetime(inv["Date issued"], format=DATE_FMT, errors="coerce")
        inv = inv.assign(_ts=_ts).sort_values("_ts", ascending=False, na_position="last").drop(columns="_ts")
    st.dataframe(nice_display(inv), use_container_width=True, hide_index=True)

# Transfer
with tabs[1]:
    st.subheader("Register Ownership Transfer")
    inv2 = safe_read_ws(INVENTORY_WS, ALL_COLS, "inventory")
    serials = sorted(inv2["Serial Number"].astype(str).dropna().unique().tolist())
    pick = st.selectbox("Serial Number", ["— Select —"] + serials)
    chosen = None if pick=="— Select —" else pick
    if chosen:
        row = inv2[inv2["Serial Number"].astype(str)==chosen]
        if not row.empty:
            r = row.iloc[0]
            st.caption(f"Device: {r.get('Device Type','')} • Brand: {r.get('Brand','')} • Model: {r.get('Model','')} • CPU: {r.get('CPU','')}")
    new_owner = st.text_input("New Owner (required)")
    if st.button("Transfer Now", type="primary", disabled=not (chosen and new_owner.strip())):
        idxs = inv2.index[inv2["Serial Number"].astype(str)==chosen].tolist()
        if not idxs: st.error("Serial not found.")
        else:
            i = idxs[0]; prev = inv2.loc[i, "USER"]; now = datetime.now().strftime(DATE_FMT)
            inv2.loc[i,"Previous User"]=str(prev or ""); inv2.loc[i,"USER"]=new_owner.strip()
            inv2.loc[i,"TO"]=new_owner.strip(); inv2.loc[i,"Date issued"]=now; inv2.loc[i,"Registered by"]=USER
            log = safe_read_ws(TRANSFERLOG_WS, LOG_COLS, "transfer log")
            log = pd.concat([log, pd.DataFrame([{
                "Device Type": inv2.loc[i,"Device Type"], "Serial Number": chosen,
                "From owner": str(prev or ""), "To owner": new_owner.strip(),
                "Date issued": now, "Registered by": USER
            }])], ignore_index=True)
            wrote = commit_writes([(INVENTORY_WS, inv2), (TRANSFERLOG_WS, log)], show_error=IS_ADMIN)
            st.success("✅ Transfer saved." if wrote else "✅ Transfer recorded locally; add a Service Account to sync.")

# Log
with tabs[2]:
    st.subheader("Transfer Log")
    log = safe_read_ws(TRANSFERLOG_WS, LOG_COLS, "transfer log", ttl=0)
    if not log.empty and "Date issued" in log.columns:
        log["Date issued"] = parse_dates_safe(log["Date issued"].astype(str))
        _ts = pd.to_datetime(log["Date issued"], format=DATE_FMT, errors="coerce")
        log = log.assign(_ts=_ts).sort_values("_ts", ascending=False, na_position="last").drop(columns="_ts")
    st.dataframe(nice_display(log), use_container_width=True, hide_index=True)

# Diagnostics
with st.expander("🔎 Connection diagnostics"):
    st.json({"spreadsheet": SPREADSHEET_URL})
    st.json({"INVENTORY_WS": INVENTORY_WS, "TRANSFERLOG_WS": TRANSFERLOG_WS})
    try:
        p = conn.read(spreadsheet=SPREADSHEET_URL, worksheet=(int(INVENTORY_WS) if INVENTORY_WS.isdigit() else INVENTORY_WS), nrows=3, ttl=0)
        st.caption(f"Inventory probe: {p.shape}"); st.dataframe(p, use_container_width=True)
    except Exception as e:
        st.error(f"Inventory probe failed: {e}")
    try:
        p = conn.read(spreadsheet=SPREADSHEET_URL, worksheet=(int(TRANSFERLOG_WS) if TRANSFERLOG_WS.isdigit() else TRANSFERLOG_WS), nrows=3, ttl=0)
        st.caption(f"Transfer log probe: {p.shape}"); st.dataframe(p, use_container_width=True)
    except Exception as e:
        st.error(f"Transfer log probe failed: {e}")
