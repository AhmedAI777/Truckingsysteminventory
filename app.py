# # app.py
# import os, json, time, hmac, base64, hashlib
# from io import BytesIO
# from datetime import datetime
# from typing import Dict, Optional, Tuple, List

# import numpy as np
# import pandas as pd
# import streamlit as st
# from streamlit_gsheets import GSheetsConnection

# APP_TITLE = "Tracking Inventory Management System"
# SUBTITLE  = "Advanced Construction"
# DATE_FMT  = "%Y-%m-%d %H:%M:%S"

# st.set_page_config(page_title=APP_TITLE, layout="wide")

# # ============================== AUTH ==============================
# DEFAULT_ADMIN_PW = "admin@2025"
# DEFAULT_STAFF_PW = "staff@2025"

# ADMINS: Dict[str, str] = dict(getattr(st.secrets.get("auth", {}), "admins", {})) if hasattr(st, "secrets") else {}
# STAFFS: Dict[str, str] = dict(getattr(st.secrets.get("auth", {}), "staff", {}))  if hasattr(st, "secrets") else {}
# if not ADMINS: ADMINS = {f"admin{i}": DEFAULT_ADMIN_PW for i in range(1,6)}
# if not STAFFS: STAFFS = {f"staff{i}": DEFAULT_STAFF_PW for i in range(1,16)}

# AUTH_SECRET = (st.secrets.get("auth", {}).get("secret") if hasattr(st,"secrets") else None) or "change-me"

# def _now() -> int: return int(time.time())
# def _tok(u:str, r:str, days:int=30) -> str:
#     raw = json.dumps({"u":u,"r":r,"exp":_now()+days*86400}, separators=(",",":")).encode()
#     sig = hmac.new(AUTH_SECRET.encode(), raw, hashlib.sha256).digest()
#     return base64.urlsafe_b64encode(raw+sig).decode()

# def _parse(t:str) -> Optional[Tuple[str,str,int]]:
#     try:
#         b = base64.urlsafe_b64decode(t.encode()); raw, sig = b[:-32], b[-32:]
#         if not hmac.compare_digest(sig, hmac.new(AUTH_SECRET.encode(), raw, hashlib.sha256).digest()): return None
#         p = json.loads(raw.decode());  return (p["u"], p["r"], p["exp"]) if p["exp"]>_now() else None
#     except: return None

# def _getq():
#     try: return st.query_params.get("auth")
#     except:
#         v = st.experimental_get_query_params().get("auth", [None])
#         return v[0] if isinstance(v, list) else v

# def _setq(t:Optional[str]):
#     try:
#         if t is None: st.query_params.pop("auth", None)
#         else: st.query_params["auth"] = t
#     except:
#         if t is None: st.experimental_set_query_params()
#         else: st.experimental_set_query_params(auth=t)

# def _auth(u:str,p:str)->Optional[str]:
#     if u in ADMINS and ADMINS[u]==p: return "admin"
#     if u in STAFFS and STAFFS[u]==p: return "staff"
#     return None

# def ensure_auth():
#     if "auth_user" not in st.session_state:
#         st.session_state.auth_user=None; st.session_state.auth_role=None
#     if not st.session_state.auth_user:
#         t=_getq(); parsed=_parse(t) if t else None
#         if parsed:
#             u,r,exp=parsed; st.session_state.auth_user=u; st.session_state.auth_role=r
#             if exp-int(time.time())<3*86400: _setq(_tok(u,r))
#             return
#     if st.session_state.auth_user: return
#     st.markdown(f"## {APP_TITLE}"); st.caption(SUBTITLE)
#     with st.form("login"): 
#         u=st.text_input("Username"); p=st.text_input("Password", type="password")
#         if st.form_submit_button("Login", type="primary"):
#             r=_auth(u.strip(), p)
#             if r:
#                 st.session_state.auth_user=u.strip(); st.session_state.auth_role=r
#                 _setq(_tok(u.strip(), r)); st.rerun()
#             else:
#                 st.error("Invalid username or password.")
#     st.stop()

# def logout_button():
#     if st.button("Logout"): 
#         st.session_state.pop("auth_user", None)
#         st.session_state.pop("auth_role", None)
#         _setq(None); st.rerun()

# # ============================ SHEETS =============================
# SPREADSHEET_URL = (
#     st.secrets.get("connections", {}).get("gsheets", {}).get("spreadsheet")
#     if hasattr(st,"secrets") else None
# ) or "https://docs.google.com/spreadsheets/d/1SHp6gOW4ltsyOT41rwo85e_LELrHkwSwKN33K6XNHFI/edit"

# INVENTORY_WS   = str(st.secrets.get("inventory_tab",   "0"))          # gid "0"
# TRANSFERLOG_WS = str(st.secrets.get("transferlog_tab", "405007082"))  # your transfer_log gid

# conn = st.connection("gsheets", type=GSheetsConnection)

# def _has_sa() -> bool:
#     try: return bool(st.secrets["connections"]["gsheets"].get("service_account"))
#     except: return False
# IS_READ_ONLY = not _has_sa()

# def _ensure_cols(df: pd.DataFrame, cols: list[str]) -> pd.DataFrame:
#     if df is None or df.empty: return pd.DataFrame(columns=cols)
#     df = df.fillna("")
#     for c in cols:
#         if c not in df.columns: df[c] = ""
#     return df[cols + [c for c in df.columns if c not in cols]]

# def read_ws(ws:str, cols:list[str], ttl:int=0) -> pd.DataFrame:
#     w = int(ws) if ws.isdigit() else ws
#     df = conn.read(spreadsheet=SPREADSHEET_URL, worksheet=w, ttl=ttl)
#     return _ensure_cols(df, cols)

# def safe_read_ws(ws:str, cols:list[str], label:str, ttl:int=0)->pd.DataFrame:
#     try: return read_ws(ws, cols, ttl=ttl)
#     except Exception as e:
#         st.warning(f"Couldn’t read **{label}** from Google Sheets. Error: {type(e).__name__}")
#         return _ensure_cols(None, cols)

# def write_ws(ws:str, df:pd.DataFrame)->Tuple[bool, Optional[str]]:
#     try:
#         w = int(ws) if ws.isdigit() else ws
#         conn.update(spreadsheet=SPREADSHEET_URL, worksheet=w, data=df)
#         return True, None
#     except Exception as e:
#         return False, str(e)

# def commit_writes(writes: List[Tuple[str, pd.DataFrame]], *, show_error: bool)->bool:
#     for ws, df in writes:
#         ok, err = write_ws(ws, df)
#         if not ok:
#             if show_error:
#                 st.error(
#                     "Cannot write to Google Sheet (public sheet or missing Service Account permissions).\n"
#                     "➡ Add a **service_account** in secrets and share the Sheet with that account as **Editor**.\n\n"
#                     f"Details: {err}"
#                 )
#             return False
#     return True

# # ============================ HELPERS ============================
# ALL_COLS = [
#     "Serial Number","Device Type","Brand","Model","CPU",
#     "Hard Drive 1","Hard Drive 2","Memory","GPU","Screen Size",
#     "USER","Previous User","TO","Department","Email Address",
#     "Contact Number","Location","Office","Notes","Date issued","Registered by"
# ]
# LOG_COLS = ["Device Type","Serial Number","From owner","To owner","Date issued","Registered by"]

# def parse_dates_safe(s: pd.Series)->pd.Series:
#     dt = pd.to_datetime(s, errors="coerce", format=DATE_FMT)
#     return dt.dt.strftime(DATE_FMT).replace("NaT","")

# def nice_display(df: pd.DataFrame)->pd.DataFrame:
#     if df is None or df.empty: return df
#     out = df.copy()
#     for c in out.columns:
#         try:
#             if np.issubdtype(out[c].dtype, np.datetime64) or "date" in c.lower():
#                 out[c] = parse_dates_safe(out[c].astype(str))
#         except: pass
#     return out.replace({np.nan:""})

# def lookup_contact(name: str, inventory: pd.DataFrame) -> Tuple[str, str]:
#     """Auto Email/Phone from secrets first, otherwise last seen in inventory."""
#     try:
#         directory = st.secrets.get("directory", {}).get("users", {})
#         if name in directory:
#             d = directory[name]
#             return d.get("email",""), d.get("phone","")
#     except: pass
#     try:
#         df = inventory[inventory["USER"].astype(str).str.strip().str.lower() == name.strip().lower()]
#         if not df.empty:
#             df = df.copy()
#             if "Date issued" in df.columns:
#                 ts = pd.to_datetime(df["Date issued"], errors="coerce")
#                 df = df.assign(_ts=ts).sort_values("_ts", ascending=False)
#             email = df.iloc[0].get("Email Address","") or ""
#             phone = df.iloc[0].get("Contact Number","") or ""
#             return str(email), str(phone)
#     except: pass
#     return "", ""

# # ============================== UI ===============================
# ensure_auth()
# USER = st.session_state.auth_user
# ROLE = st.session_state.auth_role
# IS_ADMIN = ROLE == "admin"

# # Hide df toolbar for staff
# if not IS_ADMIN:
#     st.markdown("""
#     <style>
#       div[data-testid="stDataFrame"] div[data-testid="stElementToolbar"]{display:none !important;}
#     </style>
#     """, unsafe_allow_html=True)

# # Header
# c1,c2,c3 = st.columns([1.2,6,3])
# with c1:
#     if os.path.exists("company_logo.jpeg"): st.image("company_logo.jpeg", use_container_width=True)
# with c2:
#     st.markdown(f"### {APP_TITLE}"); st.caption(SUBTITLE)
# with c3:
#     st.markdown(f"**Welcome, {USER}**  \nRole: **{ROLE.capitalize()}**")
#     logout_button()
# st.markdown("---")

# # Tabs (admin gets Register + Export)
# if IS_ADMIN:
#     tabs = st.tabs(["📝 Register","📦 View Inventory","🔄 Transfer Device","📜 Transfer Log","⬇ Export"])
# else:
#     tabs = st.tabs(["📦 View Inventory","🔄 Transfer Device","📜 Transfer Log"])

# # ------------------ Register (ADMIN) ------------------
# if IS_ADMIN:
#     with tabs[0]:
#         st.subheader("Register New Inventory Item")
#         with st.form("reg_form", clear_on_submit=True):
#             cA, cB = st.columns(2)
#             with cA:
#                 serial = st.text_input("Serial Number *")
#                 device = st.text_input("Device Type *")
#                 brand  = st.text_input("Brand")
#                 model  = st.text_input("Model")
#                 cpu    = st.text_input("CPU")
#             with cB:
#                 hdd1   = st.text_input("Hard Drive 1")
#                 hdd2   = st.text_input("Hard Drive 2")
#                 mem    = st.text_input("Memory")
#                 gpu    = st.text_input("GPU")
#                 screen = st.text_input("Screen Size")
#             submitted = st.form_submit_button("Save Item", type="primary")
#         if submitted:
#             if not serial.strip() or not device.strip():
#                 st.error("Serial Number and Device Type are required.")
#             else:
#                 inv = safe_read_ws(INVENTORY_WS, ALL_COLS, "inventory")
#                 if serial.strip() in inv["Serial Number"].astype(str).values:
#                     st.error(f"Serial Number '{serial}' already exists.")
#                 else:
#                     row = {
#                         "Serial Number": serial.strip(),
#                         "Device Type": device.strip(),
#                         "Brand": brand.strip(),
#                         "Model": model.strip(),
#                         "CPU": cpu.strip(),
#                         "Hard Drive 1": hdd1.strip(),
#                         "Hard Drive 2": hdd2.strip(),
#                         "Memory": mem.strip(),
#                         "GPU": gpu.strip(),
#                         "Screen Size": screen.strip(),
#                         "USER": "", "Previous User": "", "TO": "",
#                         "Department": "", "Email Address": "", "Contact Number": "",
#                         "Location": "", "Office": "", "Notes": "",
#                         "Date issued": datetime.now().strftime(DATE_FMT),
#                         "Registered by": USER,
#                     }
#                     inv = pd.concat([inv, pd.DataFrame([row])], ignore_index=True)
#                     if commit_writes([(INVENTORY_WS, inv)], show_error=True):
#                         st.success("✅ Saved to Google Sheets.")

# # ------------------ View Inventory ------------------
# with tabs[1 if IS_ADMIN else 0]:
#     st.subheader("Current Inventory")
#     inv = safe_read_ws(INVENTORY_WS, ALL_COLS, "inventory", ttl=0)
#     if not inv.empty and "Date issued" in inv.columns:
#         inv["Date issued"] = parse_dates_safe(inv["Date issued"].astype(str))
#         _ts = pd.to_datetime(inv["Date issued"], format=DATE_FMT, errors="coerce")
#         inv = inv.assign(_ts=_ts).sort_values("_ts", ascending=False, na_position="last").drop(columns="_ts")
#     st.dataframe(nice_display(inv), use_container_width=True, hide_index=True)

# # ------------------ Transfer Device ------------------
# with tabs[2 if IS_ADMIN else 1]:
#     st.subheader("Register Ownership Transfer")
#     inv2 = safe_read_ws(INVENTORY_WS, ALL_COLS, "inventory")
#     serials = sorted(inv2["Serial Number"].astype(str).dropna().unique().tolist())
#     pick = st.selectbox("Serial Number", ["— Select —"] + serials)
#     chosen = None if pick == "— Select —" else pick

#     new_owner = st.text_input("New Owner (required)")

#     auto_email, auto_phone = "", ""
#     if chosen:
#         row = inv2[inv2["Serial Number"].astype(str) == chosen]
#         if not row.empty:
#             r = row.iloc[0]
#             st.caption(
#                 f"Device: {r.get('Device Type','')} • Brand: {r.get('Brand','')} • "
#                 f"Model: {r.get('Model','')} • CPU: {r.get('CPU','')}"
#             )
#         if new_owner.strip():
#             auto_email, auto_phone = lookup_contact(new_owner.strip(), inv2)
#             st.write(f"**Auto Email:** {auto_email or '—'}")
#             st.write(f"**Auto Phone:** {auto_phone or '—'}")

#     do_transfer = st.button("Transfer Now", type="primary", disabled=not (chosen and new_owner.strip()))
#     if do_transfer:
#         idxs = inv2.index[inv2["Serial Number"].astype(str) == chosen].tolist()
#         if not idxs:
#             st.error("Serial not found.")
#         else:
#             i = idxs[0]
#             prev = inv2.loc[i, "USER"]
#             now  = datetime.now().strftime(DATE_FMT)

#             inv2.loc[i, "Previous User"]  = str(prev or "")
#             inv2.loc[i, "USER"]           = new_owner.strip()
#             inv2.loc[i, "TO"]             = new_owner.strip()
#             inv2.loc[i, "Email Address"]  = auto_email
#             inv2.loc[i, "Contact Number"] = auto_phone
#             inv2.loc[i, "Date issued"]    = now
#             inv2.loc[i, "Registered by"]  = USER

#             log = safe_read_ws(TRANSFERLOG_WS, LOG_COLS, "transfer log")
#             log = pd.concat([log, pd.DataFrame([{
#                 "Device Type": inv2.loc[i, "Device Type"],
#                 "Serial Number": chosen,
#                 "From owner": str(prev or ""),
#                 "To owner": new_owner.strip(),
#                 "Date issued": now,
#                 "Registered by": USER,
#             }])], ignore_index=True)

#             wrote = commit_writes([(INVENTORY_WS, inv2), (TRANSFERLOG_WS, log)], show_error=IS_ADMIN)
#             if wrote:
#                 st.success(f"✅ Transfer saved: {prev or '(blank)'} → {new_owner.strip()}")
#             else:
#                 st.error("Transfer couldn’t be written. Add a Service Account & share the sheet with it (Editor).")

# # ------------------ Transfer Log ------------------
# with tabs[3 if IS_ADMIN else 2]:
#     st.subheader("Transfer Log")
#     log = safe_read_ws(TRANSFERLOG_WS, LOG_COLS, "transfer log", ttl=0)
#     if not log.empty and "Date issued" in log.columns:
#         log["Date issued"] = parse_dates_safe(log["Date issued"].astype(str))
#         _ts = pd.to_datetime(log["Date issued"], format=DATE_FMT, errors="coerce")
#         log = log.assign(_ts=_ts).sort_values("_ts", ascending=False, na_position="last").drop(columns="_ts")
#     st.dataframe(nice_display(log), use_container_width=True, hide_index=True)

# # ------------------ Export (ADMIN) ------------------
# if IS_ADMIN:
#     with tabs[4]:
#         st.subheader("Download Exports")
#         inv = safe_read_ws(INVENTORY_WS, ALL_COLS, "inventory")
#         inv_x = BytesIO()
#         with pd.ExcelWriter(inv_x, engine="openpyxl") as w:
#             inv.to_excel(w, index=False)
#         inv_x.seek(0)
#         st.download_button(
#             "⬇ Download Inventory",
#             inv_x.getvalue(),
#             file_name="inventory.xlsx",
#             mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
#         )

#         log = safe_read_ws(TRANSFERLOG_WS, LOG_COLS, "transfer log")
#         log_x = BytesIO()
#         with pd.ExcelWriter(log_x, engine="openpyxl") as w:
#             log.to_excel(w, index=False)
#         log_x.seek(0)
#         st.download_button(
#             "⬇ Download Transfer Log",
#             log_x.getvalue(),
#             file_name="transfer_log.xlsx",
#             mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
#         )




# app.py
import os, json, time, hmac, base64, hashlib
from io import BytesIO
from datetime import datetime
from typing import Dict, Optional, Tuple, List

import numpy as np
import pandas as pd
import streamlit as st

# NEW: use gspread instead of streamlit_gsheets
import gspread
from oauth2client.service_account import ServiceAccountCredentials

APP_TITLE = "Tracking Inventory Management System"
SUBTITLE  = "Advanced Construction"
DATE_FMT  = "%Y-%m-%d %H:%M:%S"

st.set_page_config(page_title=APP_TITLE, layout="wide")

# ============================== AUTH ==============================
DEFAULT_ADMIN_PW = "admin@2025"
DEFAULT_STAFF_PW = "staff@2025"

ADMINS: Dict[str, str] = dict(getattr(st.secrets.get("auth", {}), "admins", {})) if hasattr(st, "secrets") else {}
STAFFS: Dict[str, str] = dict(getattr(st.secrets.get("auth", {}), "staff", {}))  if hasattr(st, "secrets") else {}
if not ADMINS: ADMINS = {f"admin{i}": DEFAULT_ADMIN_PW for i in range(1,6)}
if not STAFFS: STAFFS = {f"staff{i}": DEFAULT_STAFF_PW for i in range(1,16)}

AUTH_SECRET = (st.secrets.get("auth", {}).get("secret") if hasattr(st,"secrets") else None) or "change-me"

def _now() -> int: return int(time.time())
def _tok(u:str, r:str, days:int=30) -> str:
    raw = json.dumps({"u":u,"r":r,"exp":_now()+days*86400}, separators=(",",":")).encode()
    sig = hmac.new(AUTH_SECRET.encode(), raw, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(raw+sig).decode()

def _parse(t:str) -> Optional[Tuple[str,str,int]]:
    try:
        b = base64.urlsafe_b64decode(t.encode()); raw, sig = b[:-32], b[-32:]
        if not hmac.compare_digest(sig, hmac.new(AUTH_SECRET.encode(), raw, hashlib.sha256).digest()): return None
        p = json.loads(raw.decode());  return (p["u"], p["r"], p["exp"]) if p["exp"]>_now() else None
    except: return None

def _getq():
    try: return st.query_params.get("auth")
    except:
        v = st.experimental_get_query_params().get("auth", [None])
        return v[0] if isinstance(v, list) else v

def _setq(t:Optional[str]):
    try:
        if t is None: st.query_params.pop("auth", None)
        else: st.query_params["auth"] = t
    except:
        if t is None: st.experimental_set_query_params()
        else: st.experimental_set_query_params(auth=t)

def _auth(u:str,p:str)->Optional[str]:
    if u in ADMINS and ADMINS[u]==p: return "admin"
    if u in STAFFS and STAFFS[u]==p: return "staff"
    return None

def ensure_auth():
    if "auth_user" not in st.session_state:
        st.session_state.auth_user=None; st.session_state.auth_role=None
    if not st.session_state.auth_user:
        t=_getq(); parsed=_parse(t) if t else None
        if parsed:
            u,r,exp=parsed; st.session_state.auth_user=u; st.session_state.auth_role=r
            if exp-int(time.time())<3*86400: _setq(_tok(u,r))
