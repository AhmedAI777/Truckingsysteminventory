# app.py — Streamlit Tracking Inventory
# - Persistent login via signed URL token (st.query_params)
# - Header: logo + title + Logout aligned far-right (near Share)
# - Times New Roman styling and tidy spacing
# - No experimental_rerun, no use_column_width
# - Arrow-safe UI rendering (for_display) to avoid mixed-type errors

import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime
from io import BytesIO
import json
import os
import shutil
import base64
import hmac
import hashlib

# ========================
# Branding / Header Config
# ========================
APP_TITLE   = "AdvancedConstruction"
APP_TAGLINE = "Tracking Inventory Management System"

LOGO_FILE = "assets/company_logo.png"
ICON_FILE = "assets/favicon.png"

LOGO_WIDTH  = 120        # px for header logo
TITLE_SIZE  = 44         # px for title
EMOJI_FALLBACK = "🖥️"

# ========================
# Page Config
# ========================
st.set_page_config(
    page_title="Tracking Inventory System",
    page_icon=ICON_FILE if os.path.exists(ICON_FILE) else EMOJI_FALLBACK,
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ========================
# CSS — Times New Roman + header/button polish + spacing
# ========================
st.markdown(f"""
<style>
html, body, .stApp, .stApp * {{
  font-family: "Times New Roman", Times, serif !important;
}}
[data-testid="stSidebar"] {{ display: none !important; }}

.block-container {{
  padding-top: 1.6rem;   /* comfortable, not too big */
  max-width: 1100px;
}}

/* Header row handled by columns; just size/logo/text styles here */
.brand-logo {{ width: {LOGO_WIDTH}px; height:auto; }}
.brand-title {{ font-weight:700; font-size:{TITLE_SIZE}px; margin:0; line-height:1.1; }}
.brand-tag   {{ margin:2px 0 0; color:#64748b; font-weight:400; }}
.header-divider {{ height:1px; background:#e5e7eb; margin:12px 0 18px; }}

/* Buttons */
.stButton > button {{
  height: 38px; padding: 0 .9rem; border-radius: 8px; font-weight: 600;
}}
.logout-col .stButton > button {{
  background:#f3f4f6; color:#111827; border:1px solid #e5e7eb;
}}
.logout-col .stButton > button:hover {{ background:#e5e7eb; }}

/* Tabs + subheaders spacing */
.stTabs {{ margin-top: 6px; }}
section[tabindex="0"] h2 {{ margin-top: 8px; }}

#MainMenu, footer {{ visibility:hidden; }}
</style>
""", unsafe_allow_html=True)

# ========================
# Session defaults
# ========================
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
if "role" not in st.session_state:
    st.session_state["role"] = None
if "username" not in st.session_state:
    st.session_state["username"] = ""

# ========================
# Secrets / Users
# ========================
AUTH_SECRET = st.secrets.get("auth_secret", "change-me")  # set strong value in .streamlit/secrets.toml

try:
    USERS = json.loads(st.secrets["users_json"])
except Exception:
    st.error("Missing `users_json` in secrets. Example: "
             '[{"username":"admin","password":"123","role":"admin"}]')
    st.stop()

def get_user_role(username: str):
    for u in USERS:
        if u.get("username") == username:
            return u.get("role")
    return None

# ========================
# Token helpers (URL-based persistence) — st.query_params
# ========================
def make_token(username: str) -> str:
    return hmac.new(
        AUTH_SECRET.encode("utf-8"),
        msg=username.encode("utf-8"),
        digestmod=hashlib.sha256
    ).hexdigest()

def set_auth_query_params(username: str):
    # Keep URL clean with only our needed params
    st.query_params.clear()
    st.query_params.update({"u": username, "t": make_token(username)})

def clear_auth_query_params():
    st.query_params.clear()

def try_auto_login_from_url():
    """If URL has valid ?u=<user>&t=<token>, set authenticated session after refresh."""
    if st.session_state.get("authenticated"):
        return
    params = st.query_params
    u = params.get("u")
    t = params.get("t")
    if not u or not t:
        return
    expected = make_token(u)
    if hmac.compare_digest(t, expected):
        role = get_user_role(u)
        if role:
            st.session_state["authenticated"] = True
            st.session_state["username"] = u
            st.session_state["role"] = role

# Try auto-login BEFORE UI renders
try_auto_login_from_url()

# ========================
# Header (logo | title | spacer | logout aligned right)
# ========================
def show_header():
    c_logo, c_text, c_spacer, c_btn = st.columns([0.12, 0.68, 0.10, 0.10])

    with c_logo:
        if os.path.exists(LOGO_FILE):
            st.image(LOGO_FILE, width=LOGO_WIDTH)  # fixed width (no deprecated param)
        else:
            st.markdown(f"<div style='font-size:44px;line-height:1'>{EMOJI_FALLBACK}</div>", unsafe_allow_html=True)

    with c_text:
        st.markdown(
            f"<h1 class='brand-title'>{APP_TITLE}</h1>"
            f"<div class='brand-tag'>{APP_TAGLINE}</div>",
            unsafe_allow_html=True
        )

    with c_spacer:
        st.empty()  # push logout fully to the right (near Share)

    with c_btn:
        st.markdown("<div class='logout-col'></div>", unsafe_allow_html=True)
        if st.session_state.get("authenticated"):
            if st.button("Logout", use_container_width=True, key="logout_btn"):
                st.session_state["authenticated"] = False
                st.session_state["role"] = None
                st.session_state["username"] = ""
                clear_auth_query_params()
                st.rerun()

    st.markdown('<div class="header-divider"></div>', unsafe_allow_html=True)

show_header()

# ========================
# Files & Helpers
# ========================
INVENTORY_FILE = "truckinventory.xlsx"
TRANSFER_LOG_PRIMARY = "transferlog.xlsx"
TRANSFER_LOG_ALT = "transferlogin.xlsx"
TRANSFER_LOG_FILE = (
    TRANSFER_LOG_PRIMARY if os.path.exists(TRANSFER_LOG_PRIMARY)
    else (TRANSFER_LOG_ALT if os.path.exists(TRANSFER_LOG_ALT) else TRANSFER_LOG_PRIMARY)
)

BACKUP_FOLDER = "backups"
os.makedirs(BACKUP_FOLDER, exist_ok=True)

def backup_file(file_path):
    if os.path.exists(file_path):
        base = os.path.basename(file_path).split(".")[0]
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        shutil.copy(file_path, f"{BACKUP_FOLDER}/{base}_{ts}.xlsx")

def ensure_inventory_file():
    if not os.path.exists(INVENTORY_FILE):
        cols = ["Device Type", "Serial Number", "USER", "Previous User", "TO", "Date issued", "Registered by"]
        pd.DataFrame(columns=cols).to_excel(INVENTORY_FILE, index=False)

def ensure_transfer_log_file():
    if not os.path.exists(TRANSFER_LOG_FILE):
        cols = ["Device Type", "Serial Number", "From owner", "To owner", "Date issued", "Registered by"]
        pd.DataFrame(columns=cols).to_excel(TRANSFER_LOG_FILE, index=False)

def load_inventory() -> pd.DataFrame:
    ensure_inventory_file()
    return pd.read_excel(INVENTORY_FILE)

def load_transfer_log() -> pd.DataFrame:
    ensure_transfer_log_file()
    return pd.read_excel(TRANSFER_LOG_FILE)

def save_inventory(df: pd.DataFrame):
    backup_file(INVENTORY_FILE)
    df.to_excel(INVENTORY_FILE, index=False)

def save_transfer_log(df: pd.DataFrame):
    backup_file(TRANSFER_LOG_FILE)
    df.to_excel(TRANSFER_LOG_FILE, index=False)

# Arrow-safe display-only copy (keeps NaN as empty strings and casts to str)
def for_display(df: pd.DataFrame) -> pd.DataFrame:
    if df is None or df.empty:
        return df
    out = df.copy()
    out = out.replace({np.nan: ""})
    for c in out.columns:
        out[c] = out[c].astype(str)
    return out

# ========================
# Auth (login card)
# ========================
if not st.session_state.get("authenticated", False):
    st.subheader("Sign in")
    in_user = st.text_input("Username", placeholder="your.username")
    in_pass = st.text_input("Password", type="password", placeholder="••••••••")
    if st.button("Login", type="primary"):
        role = None
        for u in USERS:
            if u.get("username") == in_user and u.get("password") == in_pass:
                role = u.get("role"); break
        if role:
            st.session_state["authenticated"] = True
            st.session_state["role"] = role
            st.session_state["username"] = in_user
            set_auth_query_params(in_user)  # persist via URL
            st.success(f"✅ Logged in as {in_user} ({role})")
            st.rerun()
        else:
            st.error("❌ Invalid username or password")
    st.stop()

# ========================
# Tabs (main app)
# ========================
tabs = ["📦 View Inventory", "🔄 Transfer Device", "📜 View Transfer Log"]
if st.session_state.get("role") == "admin":
    tabs.append("⬇ Export Files")
tab_objects = st.tabs(tabs)

# TAB 1 – View Inventory
with tab_objects[0]:
    st.subheader("Current Inventory")
    df_inventory = load_inventory()
    if st.session_state.get("role") == "admin":
        st.dataframe(for_display(df_inventory), use_container_width=True)
    else:
        st.table(for_display(df_inventory))

# TAB 2 – Transfer Device
with tab_objects[1]:
    st.subheader("Register Ownership Transfer")
    serial_number = st.text_input("Enter Serial Number")
    new_owner = st.text_input("Enter NEW Owner's Name")
    registered_by = st.session_state.get("username", "")
    if st.button("Transfer Now", type="primary"):
        if not serial_number.strip() or not new_owner.strip():
            st.error("⚠ All fields are required.")
            st.stop()

        df_inventory = load_inventory()
        df_log = load_transfer_log()

        if "Serial Number" not in df_inventory.columns:
            st.error("Inventory file is missing 'Serial Number' column.")
            st.stop()

        if serial_number not in df_inventory["Serial Number"].values:
            st.error(f"Device with Serial Number {serial_number} not found!")
        else:
            idx = df_inventory[df_inventory["Serial Number"] == serial_number].index[0]
            from_owner  = df_inventory.loc[idx, "USER"] if "USER" in df_inventory.columns else ""
            device_type = df_inventory.loc[idx, "Device Type"] if "Device Type" in df_inventory.columns else ""

            if "Previous User" in df_inventory.columns:
                df_inventory.loc[idx, "Previous User"] = from_owner
            if "USER" in df_inventory.columns:
                df_inventory.loc[idx, "USER"] = new_owner
            if "TO" in df_inventory.columns:
                df_inventory.loc[idx, "TO"] = new_owner
            if "Date issued" in df_inventory.columns:
                df_inventory.loc[idx, "Date issued"] = datetime.now().strftime("%m/%d/%Y %H:%M:%S")
            if "Registered by" in df_inventory.columns:
                df_inventory.loc[idx, "Registered by"] = registered_by

            log_entry = {
                "Device Type": device_type,
                "Serial Number": serial_number,
                "From owner": from_owner,
                "To owner": new_owner,
                "Date issued": datetime.now().strftime("%m/%d/%Y %H:%M:%S"),
                "Registered by": registered_by
            }
            df_log = pd.concat([df_log, pd.DataFrame([log_entry])], ignore_index=True)
            save_inventory(df_inventory)
            save_transfer_log(df_log)
            st.success(f"✅ Transfer logged: {from_owner} → {new_owner}")

# TAB 3 – View Transfer Log
with tab_objects[2]:
    st.subheader("Transfer Log History")
    df_log = load_transfer_log()
    if st.session_state.get("role") == "admin":
        st.dataframe(for_display(df_log), use_container_width=True)
    else:
        st.table(for_display(df_log))

# TAB 4 – Export Files (Admins Only)
if st.session_state.get("role") == "admin" and len(tab_objects) > 3:
    with tab_objects[3]:
        st.subheader("Download Updated Files")

        # Inventory export
        df_inventory = load_inventory()
        out_inv = BytesIO()
        with pd.ExcelWriter(out_inv, engine="openpyxl") as writer:
            df_inventory.to_excel(writer, index=False)
        out_inv.seek(0)
        st.download_button(
            label="⬇ Download Inventory",
            data=out_inv.getvalue(),
            file_name="truckinventory_updated.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )

        # Transfer log export
        df_log = load_transfer_log()
        out_log = BytesIO()
        with pd.ExcelWriter(out_log, engine="openpyxl") as writer:
            df_log.to_excel(writer, index=False)
        out_log.seek(0)
        st.download_button(
            label="⬇ Download Transfer Log",
            data=out_log.getvalue(),
            file_name="transferlog_updated.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
