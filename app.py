# app.py — Streamlit Tracking Inventory (no sidebar, top-left logo, clean layout)

import streamlit as st
import pandas as pd
from datetime import datetime
from io import BytesIO
import json
import os
import shutil

# ========================
# Branding / Assets
# ========================
APP_TITLE   = "AdvancedConstruction"
APP_TAGLINE = "Tracking Inventory Management System"
EMOJI_FALLBACK = "🖥️"

# Use repo images (you already have these)
LOGO_FILE = "assets/company_logo.png"
ICON_FILE = "assets/favicon.png"

# ========================
# Page Config (first Streamlit call)
# ========================
st.set_page_config(
    page_title="Tracking Inventory System",
    page_icon=ICON_FILE if os.path.exists(ICON_FILE) else EMOJI_FALLBACK,
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ========================
# Global CSS (hide sidebar, nicer header + login card)
# ========================
st.markdown("""
<style>
/* Hide the left sidebar entirely */
[data-testid="stSidebar"] { display: none !important; }

/* Page width & padding */
.block-container { padding-top: 1.75rem; max-width: 1100px; }

/* Header layout */
.app-header { display:flex; align-items:center; gap:14px; }
.app-header .title-wrap h1 { margin:0; line-height:1.1; font-weight:800; }
.app-header .title-wrap p { margin:2px 0 0; color:#64748b; }

/* Divider under header */
.header-divider { height:1px; background:#e5e7eb; margin:12px 0 20px; }

/* Login card */
.login-card {
  background:#ffffff; border-radius:14px; padding:22px;
  box-shadow:0 2px 14px rgba(15,23,42,.08); max-width:560px; margin:14px auto 0;
}

/* Buttons & inputs polish */
.stButton>button { border-radius:10px; font-weight:600; padding:.55rem 1.0rem; }
.stTextInput input { border-radius:10px !important; }

/* Hide Streamlit chrome if you prefer a cleaner look */
#MainMenu {visibility:hidden;} footer {visibility:hidden;}
</style>
""", unsafe_allow_html=True)

# ========================
# Session defaults (avoid AttributeError)
# ========================
st.session_state.setdefault("authenticated", False)
st.session_state.setdefault("role", None)
st.session_state.setdefault("username", "")

# ========================
# Users (from secrets)
# ========================
try:
    USERS = json.loads(st.secrets["users_json"])
except Exception:
    st.error("Missing `users_json` in secrets. Example: "
             '[{"username":"admin","password":"123","role":"admin"}]')
    st.stop()

def check_credentials(username: str, password: str):
    for u in USERS:
        if u.get("username") == username and u.get("password") == password:
            return u.get("role")
    return None

# ========================
# Header (logo top-left + title; logout top-right when signed in)
# ========================
def render_header():
    st.markdown('<div class="app-header">', unsafe_allow_html=True)
    # Logo
    if os.path.exists(LOGO_FILE):
        st.image(LOGO_FILE, width=56)
    else:
        st.markdown(f"<div style='font-size:48px;line-height:1'>{EMOJI_FALLBACK}</div>", unsafe_allow_html=True)

    # Title + tagline
    st.markdown(
        f"<div class='title-wrap'><h1>{APP_TITLE}</h1>"
        f"<p>{APP_TAGLINE}</p></div>",
        unsafe_allow_html=True
    )

    # Push a logout button to the right when authenticated
    if st.session_state.get("authenticated"):
        _, col_btn = st.columns([0.82, 0.18])
        with col_btn:
            if st.button("Log out"):
                for k in ("authenticated", "role", "username"):
                    if k in st.session_state:
                        del st.session_state[k]
                st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)
    st.markdown('<div class="header-divider"></div>', unsafe_allow_html=True)

render_header()

# ========================
# Files & Helpers
# ========================
INVENTORY_FILE = "truckinventory.xlsx"
TRANSFER_LOG_PRIMARY = "transferlog.xlsx"
TRANSFER_LOG_ALT = "transferlogin.xlsx"
TRANSFER_LOG_FILE = (TRANSFER_LOG_PRIMARY if os.path.exists(TRANSFER_LOG_PRIMARY)
                     else (TRANSFER_LOG_ALT if os.path.exists(TRANSFER_LOG_ALT) else TRANSFER_LOG_PRIMARY))

BACKUP_FOLDER = "backups"
os.makedirs(BACKUP_FOLDER, exist_ok=True)

def backup_file(file_path):
    if os.path.exists(file_path):
        base = os.path.basename(file_path).split(".")[0]
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        shutil.copy(file_path, f"{BACKUP_FOLDER}/{base}_{ts}.xlsx")

def normalize_for_display(df: pd.DataFrame) -> pd.DataFrame:
    for c in df.columns:
        if df[c].dtype == "object" or str(df[c].dtype).startswith("datetime"):
            df[c] = df[c].astype(str)
    return df

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
    return normalize_for_display(pd.read_excel(INVENTORY_FILE))

def load_transfer_log() -> pd.DataFrame:
    ensure_transfer_log_file()
    return normalize_for_display(pd.read_excel(TRANSFER_LOG_FILE))

def save_inventory(df: pd.DataFrame):
    backup_file(INVENTORY_FILE)
    normalize_for_display(df).to_excel(INVENTORY_FILE, index=False)

def save_transfer_log(df: pd.DataFrame):
    backup_file(TRANSFER_LOG_FILE)
    normalize_for_display(df).to_excel(TRANSFER_LOG_FILE, index=False)

# ========================
# Auth (centered login card)
# ========================
if not st.session_state.get("authenticated", False):
    st.markdown('<div class="login-card">', unsafe_allow_html=True)
    st.subheader("Sign in")
    in_user = st.text_input("Username", placeholder="your.username")
    in_pass = st.text_input("Password", type="password", placeholder="••••••••")
    if st.button("Login", type="primary"):
        role = check_credentials(in_user, in_pass)
        if role:
            st.session_state["authenticated"] = True
            st.session_state["role"] = role
            st.session_state["username"] = in_user
            st.success(f"✅ Logged in as {in_user} ({role})")
            st.rerun()
        else:
            st.error("❌ Invalid username or password")
    st.markdown('</div>', unsafe_allow_html=True)
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
        st.dataframe(df_inventory, use_container_width=True)
    else:
        st.table(df_inventory)

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
            from_owner = df_inventory.loc[idx, "USER"] if "USER" in df_inventory.columns else ""
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
        st.dataframe(df_log, use_container_width=True)
    else:
        st.table(df_log)

# TAB 4 – Export Files (Admins Only)
if st.session_state.get("role") == "admin" and len(tab_objects) > 3:
    with tab_objects[3]:
        st.subheader("Download Updated Files")
        df_inventory = load_inventory()
        out_inv = BytesIO()
        with pd.ExcelWriter(out_inv, engine="openpyxl") as writer:
            df_inventory.to_excel(writer, index=False)
        st.download_button(
            label="⬇ Download Inventory",
            data=out_inv.getvalue(),
            file_name="truckinventory_updated.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
        df_log = load_transfer_log()
        out_log = BytesIO()
        with pd.ExcelWriter(out_log, engine="openpyxl") as writer:
            df_log.to_excel(writer, index=False)
        st.download_button(
            label="⬇ Download Transfer Log",
            data=out_log.getvalue(),
            file_name="transferlog_updated.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
