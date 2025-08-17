# import hashlib
# from io import BytesIO
# from datetime import datetime
# import numpy as np
# import pandas as pd
# import streamlit as st
# from streamlit_gsheets import GSheetsConnection

# # =============================
# # APP SETTINGS
# # =============================
# APP_TITLE = "Tracking Inventory Management System"
# SUBTITLE  = "AdvancedConstruction"
# DATE_FMT  = "%Y-%m-%d %H:%M:%S"

# st.set_page_config(page_title=APP_TITLE, layout="wide")

# # =============================
# # GOOGLE SHEETS CONNECTION
# # =============================
# GS = st.secrets.get("connections", {}).get("gsheets", {})
# SPREADSHEET   = GS.get("spreadsheet", "")
# MODE          = GS.get("type", "public").lower()   # "gspread" enables write, "public" is read-only
# CAN_WRITE     = MODE == "gspread"

# INVENTORY_WS  = st.secrets.get("inventory_tab", "0")          # gid or sheet name
# TRANSFER_WS   = st.secrets.get("transferlog_tab", "405007082")  # gid or sheet name

# conn = st.connection("gsheets", type=GSheetsConnection)

# # =============================
# # AUTH
# # =============================
# def _sha256(s: str) -> str:
#     return hashlib.sha256(s.encode("utf-8")).hexdigest()

# def check_credentials(username: str, password: str):
#     """
#     Return 'admin' | 'staff' if valid, else None.
#     Supports:
#       password = "sha256:<hex>"  or  "plain:<text>"  or just the raw text (fallback).
#     """
#     users_root = st.secrets.get("auth", {}).get("users", {})
#     rec = users_root.get(username)
#     if not rec:
#         return None
#     stored = str(rec.get("password", ""))
#     role = str(rec.get("role", "staff")).lower()

#     if stored.startswith("sha256:"):
#         ok = _sha256(password) == stored.split("sha256:", 1)[1].strip()
#     elif stored.startswith("plain:"):
#         ok = password == stored.split("plain:", 1)[1]
#     else:
#         ok = password == stored  # fallback

#     return role if ok else None

# def logout():
#     for k in ("user", "role", "is_admin"):
#         st.session_state.pop(k, None)
#     st.rerun()

# def login_screen():
#     st.markdown(f"## {APP_TITLE}")
#     st.markdown(f"**{SUBTITLE}**")
#     st.write("")
#     c1, c2, c3 = st.columns([1, 1.2, 1])
#     with c2:
#         st.markdown("### 🔐 Sign in")
#         with st.form("login_form", clear_on_submit=False):
#             u = st.text_input("Username", autocomplete="username")
#             p = st.text_input("Password", type="password", autocomplete="current-password")
#             submitted = st.form_submit_button("Login", type="primary", use_container_width=True)
#         if submitted:
#             role = check_credentials(u.strip(), p)
#             if role:
#                 st.session_state.user = u.strip()
#                 st.session_state.role = role
#                 st.session_state.is_admin = (role == "admin")
#                 st.rerun()
#             else:
#                 st.error("Invalid username or password.")
#     st.stop()

# # Gate app until logged in
# if "user" not in st.session_state:
#     login_screen()

# IS_ADMIN = st.session_state.get("is_admin", False)

# # =============================
# # HELPERS
# # =============================
# ALL_COLS = [
#     "Serial Number","Device Type","Brand","Model","CPU",
#     "Hard Drive 1","Hard Drive 2","Memory","GPU","Screen Size",
#     "USER","Previous User","TO","Department","Email Address",
#     "Contact Number","Location","Office","Notes","Date issued","Registered by"
# ]
# LOG_COLS = ["Device Type","Serial Number","From owner","To owner","Date issued","Registered by"]

# def _ws_arg(x):
#     s = str(x).strip()
#     try:
#         return int(s)     # gid number
#     except Exception:
#         return s          # sheet name

# def _ensure_cols(df: pd.DataFrame, cols: list[str]) -> pd.DataFrame:
#     if df is None or df.empty:
#         return pd.DataFrame(columns=cols)
#     df = df.fillna("")
#     for c in cols:
#         if c not in df.columns:
#             df[c] = ""
#     return df[cols + [c for c in df.columns if c not in cols]]

# def nice_display(df: pd.DataFrame) -> pd.DataFrame:
#     if df is None or df.empty:
#         return df
#     out = df.copy()
#     for col in out.columns:
#         try:
#             if np.issubdtype(out[col].dtype, np.datetime64) or "date" in col.lower():
#                 s = pd.to_datetime(out[col], errors="ignore")
#                 if hasattr(s, "dt"):
#                     out[col] = s.dt.strftime(DATE_FMT)
#         except Exception:
#             pass
#     out = out.replace({np.nan: ""})
#     for c in out.columns:
#         out[c] = out[c].astype(str).replace({"NaT": "", "nan": "", "NaN": ""})
#     return out

# def load_ws(worksheet, cols):
#     try:
#         df = conn.read(spreadsheet=SPREADSHEET, worksheet=_ws_arg(worksheet), ttl=0)
#         return _ensure_cols(df, cols)
#     except Exception as e:
#         st.warning(
#             f"Couldn’t read from Google Sheets (worksheet={worksheet}). "
#             f"Check sharing/GID. Error: {type(e).__name__}"
#         )
#         return _ensure_cols(None, cols)

# def save_ws(worksheet, df):
#     if not CAN_WRITE:
#         st.error("This app is running in READ-ONLY mode (connection type 'public'). Use 'gspread' to enable writes.")
#         return False
#     try:
#         conn.update(spreadsheet=SPREADSHEET, worksheet=_ws_arg(worksheet), data=df)
#         return True
#     except Exception as e:
#         st.error(f"Write failed: {type(e).__name__}")
#         return False

# # =============================
# # HEADER (who is logged in + logout)
# # =============================
# r1, r2 = st.columns([1, 0.2])
# with r1:
#     st.markdown(f"### Welcome, **{st.session_state.user}**  &nbsp;&nbsp;|&nbsp;  Role: **{'Admin' if IS_ADMIN else 'Staff'}**")
# with r2:
#     st.button("Logout", on_click=logout, use_container_width=True)

# st.write("---")

# # =============================
# # TABS (role-based)
# # =============================
# tab_reg, tab_inv, tab_xfer, tab_log, tab_export = st.tabs(
#     ["📝 Register", "📦 View Inventory", "🔄 Transfer Device", "📜 Transfer Log", "⬇ Export"]
# )

# # --- Register (admins only) ---
# with tab_reg:
#     st.subheader("Register New Inventory Item")
#     if not IS_ADMIN:
#         st.info("Registration is restricted to admins.")
#     else:
#         with st.form("reg_form", clear_on_submit=False):
#             c1, c2 = st.columns(2)
#             with c1:
#                 serial = st.text_input("Serial Number *")
#                 device = st.text_input("Device Type *")
#                 brand  = st.text_input("Brand")
#                 model  = st.text_input("Model")
#                 cpu    = st.text_input("CPU")
#             with c2:
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
#                 inv = load_ws(INVENTORY_WS, ALL_COLS)
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
#                         "Registered by": st.session_state.user,
#                     }
#                     inv = pd.concat([inv, pd.DataFrame([row])], ignore_index=True)
#                     if save_ws(INVENTORY_WS, inv):
#                         st.success("✅ Saved to Google Sheets.")

# # --- View Inventory (everyone) ---
# with tab_inv:
#     st.subheader("Current Inventory")
#     inv = load_ws(INVENTORY_WS, ALL_COLS)
#     st.dataframe(nice_display(inv), use_container_width=True, hide_index=True)

# # --- Transfer Device (everyone; write needs gspread) ---
# with tab_xfer:
#     st.subheader("Register Ownership Transfer")
#     inv = load_ws(INVENTORY_WS, ALL_COLS)
#     serials = sorted(inv["Serial Number"].astype(str).dropna().unique().tolist())
#     pick = st.selectbox("Serial Number", ["— Select —"] + serials)
#     chosen_serial = None if pick == "— Select —" else pick

#     if chosen_serial:
#         row = inv[inv["Serial Number"].astype(str) == chosen_serial]
#         if not row.empty:
#             r = row.iloc[0]
#             st.caption(f"Device: {r.get('Device Type','')} • Brand: {r.get('Brand','')} • "
#                        f"Model: {r.get('Model','')} • CPU: {r.get('CPU','')}")
#         else:
#             st.warning("Serial not found in inventory.")

#     new_owner = st.text_input("New Owner (required)")
#     do_transfer = st.button(
#         "Transfer Now",
#         type="primary",
#         disabled=not (chosen_serial and new_owner.strip() and CAN_WRITE)
#     )

#     if do_transfer:
#         idx_list = inv.index[inv["Serial Number"].astype(str) == chosen_serial].tolist()
#         if not idx_list:
#             st.error(f"Device with Serial Number {chosen_serial} not found!")
#         else:
#             idx = idx_list[0]
#             prev_user = inv.loc[idx, "USER"]

#             inv.loc[idx, "Previous User"] = str(prev_user or "")
#             inv.loc[idx, "USER"] = new_owner.strip()
#             inv.loc[idx, "TO"] = new_owner.strip()
#             inv.loc[idx, "Date issued"] = datetime.now().strftime(DATE_FMT)
#             inv.loc[idx, "Registered by"] = st.session_state.user

#             log = load_ws(TRANSFER_WS, LOG_COLS)
#             log_row = {
#                 "Device Type": inv.loc[idx, "Device Type"],
#                 "Serial Number": chosen_serial,
#                 "From owner": str(prev_user or ""),
#                 "To owner": new_owner.strip(),
#                 "Date issued": datetime.now().strftime(DATE_FMT),
#                 "Registered by": st.session_state.user,
#             }
#             log = pd.concat([log, pd.DataFrame([log_row])], ignore_index=True)

#             ok1 = save_ws(INVENTORY_WS, inv)
#             ok2 = save_ws(TRANSFER_WS, log)
#             if ok1 and ok2:
#                 st.success(f"✅ Transfer saved: {prev_user or '(blank)'} → {new_owner.strip()}")

# # --- Transfer Log (sorted; clean numbering) ---
# with tab_log:
#     st.subheader("Transfer Log")
#     log = load_ws(TRANSFER_WS, LOG_COLS)
#     if not log.empty and "Date issued" in log.columns:
#         log["Date issued"] = pd.to_datetime(log["Date issued"], errors="coerce")
#         log = log.sort_values("Date issued", ascending=False, na_position="last").reset_index(drop=True)
#     if not log.empty:
#         log.insert(0, "#", range(1, len(log) + 1))
#     st.dataframe(nice_display(log), use_container_width=True, hide_index=True)

# # --- Export (admins only) ---
# with tab_export:
#     st.subheader("Download Exports")
#     if not IS_ADMIN:
#         st.info("Export is restricted to admins.")
#     else:
#         inv = load_ws(INVENTORY_WS, ALL_COLS)
#         inv_x = BytesIO()
#         with pd.ExcelWriter(inv_x, engine="openpyxl") as w:
#             inv.to_excel(w, index=False)
#         inv_x.seek(0)
#         st.download_button("⬇ Download Inventory", inv_x.getvalue(),
#                            file_name="inventory.xlsx",
#                            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

#         log = load_ws(TRANSFER_WS, LOG_COLS)
#         log_x = BytesIO()
#         with pd.ExcelWriter(log_x, engine="openpyxl") as w:
#             log.to_excel(w, index=False)
#         log_x.seek(0)
#         st.download_button("⬇ Download Transfer Log", log_x.getvalue(),
#                            file_name="transfer_log.xlsx",
#                            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

# app.py

# app.py
# app.py

import os
from io import BytesIO
from datetime import datetime
from typing import Dict

import numpy as np
import pandas as pd
import streamlit as st
from streamlit_gsheets import GSheetsConnection


# =============================================================================
# BASIC APP SETTINGS
# =============================================================================
APP_TITLE = "Tracking Inventory Equipment System"
SUBTITLE  = "AdvancedConstruction"
DATE_FMT  = "%Y-%m-%d %H:%M:%S"

# Page config first
st.set_page_config(page_title=APP_TITLE, layout="wide")

# Optional: CSS to reduce/hide Streamlit header toolbar (no set_option needed)
st.markdown("""
<style>
/* Hide the floating header toolbar (Share/⋯) - safe fallback */
div[data-testid="stToolbar"] { display: none !important; }
</style>
""", unsafe_allow_html=True)


# =============================================================================
# AUTH SETUP (simple in-app auth; override via secrets if you want)
# =============================================================================
DEFAULT_ADMIN_PW = "admin@2025"
DEFAULT_STAFF_PW = "staff@2025"

ADMINS: Dict[str, str] = dict(getattr(st.secrets, "auth", {}).get("admins", {})) if hasattr(st, "secrets") else {}
STAFFS: Dict[str, str] = dict(getattr(st.secrets, "auth", {}).get("staff", {})) if hasattr(st, "secrets") else {}

if not ADMINS:
    ADMINS = {f"admin{i}": DEFAULT_ADMIN_PW for i in range(1, 6)}
if not STAFFS:
    STAFFS = {f"staff{i}": DEFAULT_STAFF_PW for i in range(1, 16)}

def authenticate(username: str, password: str):
    if username in ADMINS and ADMINS[username] == password:
        return "admin"
    if username in STAFFS and STAFFS[username] == password:
        return "staff"
    return None

def ensure_auth():
    """Gate: show login page until authenticated."""
    if "auth_user" not in st.session_state:
        st.session_state.auth_user = None
        st.session_state.auth_role = None

    if st.session_state.auth_user and st.session_state.auth_role:
        return True

    # ---------- Login page ----------
    c = st.container()
    with c:
        # Top strip with logo + title even on login
        _render_top_header(show_logout=False)

        st.info("Please sign in to continue.")
        with st.form("login_form", clear_on_submit=False):
            u = st.text_input("Username")
            p = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Login", type="primary")
        if submitted:
            role = authenticate(u.strip(), p)
            if role:
                st.session_state.auth_user = u.strip()
                st.session_state.auth_role = role
                st.rerun()
            else:
                st.error("Invalid username or password.")
    st.stop()


# =============================================================================
# GOOGLE SHEETS CONNECTION
# =============================================================================
# Prefer secrets:
# [connections.gsheets]
# spreadsheet = "https://docs.google.com/spreadsheets/d/XXXXXXXXXXXX/edit"
SPREADSHEET = (
    getattr(getattr(st, "secrets", {}), "connections", {})
        .get("gsheets", {})
        .get("spreadsheet")
)
if not SPREADSHEET:
    # Fallback to your provided sheet URL
    SPREADSHEET = "https://docs.google.com/spreadsheets/d/1SHp6gOW4ltsyOT41rwo85e_LELrHkwSwKN33K6XNHFI/edit"

# Worksheet identifiers (tab name or gid as string)
INVENTORY_WS   = str(st.secrets.get("inventory_tab", "0"))          # first sheet gid "0"
TRANSFERLOG_WS = str(st.secrets.get("transferlog_tab", "405007082"))

conn = st.connection("gsheets", type=GSheetsConnection)


# =============================================================================
# HELPERS
# =============================================================================
def _ensure_cols(df: pd.DataFrame, cols: list[str]) -> pd.DataFrame:
    if df is None or df.empty:
        return pd.DataFrame(columns=cols)
    df = df.fillna("")
    for c in cols:
        if c not in df.columns:
            df[c] = ""
    # keep expected first, extras after
    return df[cols + [c for c in df.columns if c not in cols]]

def nice_display(df: pd.DataFrame) -> pd.DataFrame:
    if df is None or df.empty:
        return df

    out = df.copy()

    # Columns to treat as dates (adjust list if you add more date fields)
    date_like_cols = [c for c in out.columns if "date" in c.lower()]

    # Try the app's main format first, then some common fallbacks
    fallback_formats = [
        "%Y-%m-%d",               # 2025-08-17
        "%d/%m/%Y %H:%M:%S",      # 17/08/2025 06:43:01
        "%m/%d/%Y %H:%M:%S",      # 08/17/2025 06:43:01
        "%d/%m/%Y",               # 17/08/2025
        "%m/%d/%Y",               # 08/17/2025
    ]

    for col in out.columns:
        # Clean up text-y columns
        out[col] = out[col].replace({np.nan: ""})
        try:
            out[col] = out[col].astype(str).replace({"NaT": "", "nan": "", "NaN": ""})
        except Exception:
            pass

        if col in date_like_cols:
            s = out[col].astype(str).str.strip()
            s = s.where(s != "", None)

            # 1) Try the declared app format
            parsed = pd.to_datetime(s, format=DATE_FMT, errors="coerce")

            # 2) Fill remaining NaT with known fallback formats
            if parsed.isna().any():
                for fmt in fallback_formats:
                    mask = parsed.isna()
                    if not mask.any():
                        break
                    parsed_try = pd.to_datetime(s[mask], format=fmt, errors="coerce")
                    parsed.loc[mask] = parsed_try

            # 3) Final stringify
            out[col] = parsed.dt.strftime(DATE_FMT).fillna("")

    return out


def read_ws(worksheet: str, cols: list[str], ttl: int = 0) -> pd.DataFrame:
    """Strict read; raises on error."""
    df = conn.read(spreadsheet=SPREADSHEET, worksheet=worksheet, ttl=ttl)
    return _ensure_cols(df, cols)

def safe_read_ws(worksheet: str, cols: list[str], label: str, ttl: int = 0) -> pd.DataFrame:
    try:
        return read_ws(worksheet, cols, ttl=ttl)
    except Exception as e:
        st.warning(
            f"Couldn’t read **{label}** from Google Sheets. "
            f"Check sharing, tab name (or gid), or publishing. Error: {type(e).__name__}"
        )
        return _ensure_cols(None, cols)

def write_ws(worksheet: str, df: pd.DataFrame):
    conn.update(spreadsheet=SPREADSHEET, worksheet=worksheet, data=df)

def logout_button():
    if st.button("Logout"):
        for k in ("auth_user", "auth_role"):
            st.session_state.pop(k, None)
        st.rerun()

def _logo_path_in_repo(filename: str = "company_logo.jpeg") -> str | None:
    """Return absolute path to logo if present next to app.py, else None."""
    try:
        here = os.path.dirname(os.path.abspath(__file__))
    except NameError:
        here = os.getcwd()
    p = os.path.join(here, filename)
    return p if os.path.exists(p) else None

def _render_top_header(show_logout: bool = True):
    """Title + logo on left; signed-in chip under it on left; optional logout on right."""
    # first row: logo + title (left), logout (right)
    lcol, spacer, rcol = st.columns([6, 4, 2], gap="small")

    with lcol:
        logo = _logo_path_in_repo()
        if logo:
            st.image(logo, width=120)
        st.markdown(f"## {APP_TITLE}")
        st.caption(SUBTITLE)

    with rcol:
        if show_logout:
            logout_button()

    # second row: signed-in chip on left
    if "auth_user" in st.session_state and st.session_state.auth_user:
        chip = f"**Signed in as:** `{st.session_state.auth_user}`  •  **Role:** `{st.session_state.auth_role.capitalize()}`"
        st.markdown(f"<div style='margin-top:-10px;'>{chip}</div>", unsafe_allow_html=True)

    st.markdown("---")


# =============================================================================
# DATA MODEL (columns)
# =============================================================================
ALL_COLS = [
    "Serial Number","Device Type","Brand","Model","CPU",
    "Hard Drive 1","Hard Drive 2","Memory","GPU","Screen Size",
    "USER","Previous User","TO","Department","Email Address",
    "Contact Number","Location","Office","Notes","Date issued","Registered by"
]
LOG_COLS = ["Device Type","Serial Number","From owner","To owner","Date issued","Registered by"]


# =============================================================================
# MAIN
# =============================================================================
ensure_auth()
USER = st.session_state.auth_user
ROLE = st.session_state.auth_role
IS_ADMIN = ROLE == "admin"

# Hide table toolbars for STAFF (eye/download/fullscreen)
if not IS_ADMIN:
    st.markdown("""
        <style>
        div[data-testid="stDataFrame"] div[data-testid="stElementToolbar"] { display:none !important; }
        div[data-testid="stDataEditor"] div[data-testid="stElementToolbar"] { display:none !important; }
        div[data-testid="stElementToolbar"] { display:none !important; }
        </style>
    """, unsafe_allow_html=True)

# Top header (logo+title left; logout right; user chip left)
_render_top_header(show_logout=True)

# Tabs per role
if IS_ADMIN:
    tabs = st.tabs(["📝 Register", "📦 View Inventory", "🔄 Transfer Device", "📜 Transfer Log", "⬇ Export"])
else:
    # Staff: NO Register, NO Export
    tabs = st.tabs(["📦 View Inventory", "🔄 Transfer Device", "📜 Transfer Log"])

# ----------------------------- Admin: Register
if IS_ADMIN:
    with tabs[0]:
        st.subheader("Register New Inventory Item")
        with st.form("reg_form", clear_on_submit=True):
            c1, c2 = st.columns(2)
            with c1:
                serial = st.text_input("Serial Number *")
                device = st.text_input("Device Type *")
                brand  = st.text_input("Brand")
                model  = st.text_input("Model")
                cpu    = st.text_input("CPU")
            with c2:
                hdd1   = st.text_input("Hard Drive 1")
                hdd2   = st.text_input("Hard Drive 2")
                mem    = st.text_input("Memory")
                gpu    = st.text_input("GPU")
                screen = st.text_input("Screen Size")
            submitted = st.form_submit_button("Save Item", type="primary")

        if submitted:
            if not serial.strip() or not device.strip():
                st.error("Serial Number and Device Type are required.")
            else:
                inv = safe_read_ws(INVENTORY_WS, ALL_COLS, "inventory")
                if serial.strip() in inv["Serial Number"].astype(str).values:
                    st.error(f"Serial Number '{serial}' already exists.")
                else:
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
                        "USER": "", "Previous User": "", "TO": "",
                        "Department": "", "Email Address": "", "Contact Number": "",
                        "Location": "", "Office": "", "Notes": "",
                        "Date issued": datetime.now().strftime(DATE_FMT),
                        "Registered by": USER,
                    }
                    inv = pd.concat([inv, pd.DataFrame([row])], ignore_index=True)
                    write_ws(INVENTORY_WS, inv)
                    st.success("✅ Saved to Google Sheets.")

# ----------------------------- View Inventory
view_tab_index = 1 if IS_ADMIN else 0
with tabs[view_tab_index]:
    st.subheader("Current Inventory")

    inv = safe_read_ws(INVENTORY_WS, ALL_COLS, "inventory", ttl=0)
    if not inv.empty and "Date issued" in inv.columns:
        _ts = pd.to_datetime(inv["Date issued"], errors="coerce")
        inv = inv.assign(_ts=_ts).sort_values("_ts", ascending=False, na_position="last").drop(columns="_ts")

    st.dataframe(nice_display(inv), use_container_width=True, hide_index=True)

# ----------------------------- Transfer Device
transfer_tab_index = 2 if IS_ADMIN else 1
with tabs[transfer_tab_index]:
    st.subheader("Register Ownership Transfer")

    inv = safe_read_ws(INVENTORY_WS, ALL_COLS, "inventory")
    serials = sorted(inv["Serial Number"].astype(str).dropna().unique().tolist())
    pick = st.selectbox("Serial Number", ["— Select —"] + serials)
    chosen_serial = None if pick == "— Select —" else pick

    if chosen_serial:
        row = inv[inv["Serial Number"].astype(str) == chosen_serial]
        if not row.empty:
            r = row.iloc[0]
            st.caption(
                f"Device: {r.get('Device Type','')} • Brand: {r.get('Brand','')} • "
                f"Model: {r.get('Model','')} • CPU: {r.get('CPU','')}"
            )
        else:
            st.warning("Serial not found in inventory.")

    new_owner = st.text_input("New Owner (required)")
    do_transfer = st.button("Transfer Now", type="primary", disabled=not (chosen_serial and new_owner.strip()))

    if do_transfer:
        idx_list = inv.index[inv["Serial Number"].astype(str) == chosen_serial].tolist()
        if not idx_list:
            st.error(f"Device with Serial Number {chosen_serial} not found!")
        else:
            idx = idx_list[0]
            prev_user = inv.loc[idx, "USER"]

            # Update inventory row
            inv.loc[idx, "Previous User"] = str(prev_user or "")
            inv.loc[idx, "USER"] = new_owner.strip()
            inv.loc[idx, "TO"] = new_owner.strip()
            inv.loc[idx, "Date issued"] = datetime.now().strftime(DATE_FMT)
            inv.loc[idx, "Registered by"] = USER

            # Append to transfer log
            log = safe_read_ws(TRANSFERLOG_WS, LOG_COLS, "transfer log")
            log_row = {
                "Device Type": inv.loc[idx, "Device Type"],
                "Serial Number": chosen_serial,
                "From owner": str(prev_user or ""),
                "To owner": new_owner.strip(),
                "Date issued": datetime.now().strftime(DATE_FMT),
                "Registered by": USER,
            }
            log = pd.concat([log, pd.DataFrame([log_row])], ignore_index=True)

            # Save
            write_ws(INVENTORY_WS, inv)
            write_ws(TRANSFERLOG_WS, log)
            st.success(f"✅ Transfer saved: {prev_user or '(blank)'} → {new_owner.strip()}")

# ----------------------------- Transfer Log
log_tab_index = 3 if IS_ADMIN else 2
with tabs[log_tab_index]:
    st.subheader("Transfer Log")
    log = safe_read_ws(TRANSFERLOG_WS, LOG_COLS, "transfer log", ttl=0)
    if not log.empty and "Date issued" in log.columns:
        _ts = pd.to_datetime(log["Date issued"], errors="coerce")
        log = log.assign(_ts=_ts).sort_values("_ts", ascending=False, na_position="last").drop(columns="_ts")
        log["Date issued"] = pd.to_datetime(log["Date issued"], errors="coerce").dt.strftime(DATE_FMT)
    st.dataframe(nice_display(log), use_container_width=True, hide_index=True)

# ----------------------------- Admin: Export
if IS_ADMIN:
    with tabs[4]:
        st.subheader("Download Exports")

        inv = safe_read_ws(INVENTORY_WS, ALL_COLS, "inventory")
        inv_x = BytesIO()
        with pd.ExcelWriter(inv_x, engine="openpyxl") as w:
            inv.to_excel(w, index=False)
        inv_x.seek(0)
        st.download_button(
            "⬇ Download Inventory", inv_x.getvalue(),
            file_name="inventory.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )

        log = safe_read_ws(TRANSFERLOG_WS, LOG_COLS, "transfer log")
        log_x = BytesIO()
        with pd.ExcelWriter(log_x, engine="openpyxl") as w:
            log.to_excel(w, index=False)
        log_x.seek(0)
        st.download_button(
            "⬇ Download Transfer Log", log_x.getvalue(),
            file_name="transfer_log.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )

# ----------------------------- (Optional) Connection diagnostics
with st.expander("🔎 Connection diagnostics"):
    st.json({"spreadsheet": SPREADSHEET})
    st.json({"INVENTORY_WS": INVENTORY_WS, "TRANSFERLOG_WS": TRANSFERLOG_WS})

    try:
        probe_inv = conn.read(spreadsheet=SPREADSHEET, worksheet=INVENTORY_WS, nrows=3, ttl=0)
        st.caption(f"Inventory probe: {probe_inv.shape}")
        st.dataframe(probe_inv, use_container_width=True)
    except Exception as e:
        st.error(f"Inventory probe failed: {e}")

    try:
        probe_log = conn.read(spreadsheet=SPREADSHEET, worksheet=TRANSFERLOG_WS, nrows=3, ttl=0)
        st.caption(f"Transfer log probe: {probe_log.shape}")
        st.dataframe(probe_log, use_container_width=True)
    except Exception as e:
        st.error(f"Transfer log probe failed: {e}")
