# app.py — Streamlit Tracking Inventory (robust session + branding)

import streamlit as st
import pandas as pd
from datetime import datetime
from io import BytesIO
import json
import os
import shutil
from PIL import Image

# ========================
# ---- Branding / Assets
# ========================
APP_TITLE   = "AdvancedConstruction"
APP_TAGLINE = "Tracking Inventory Management System"
EMOJI_FALLBACK = "🖥️"

# Your local absolute files (exist only on your Mac)
USER_LOGO_ABS = "/Users/ahmed/Downloads/Logo.png"
USER_ICON_ABS = "/Users/ahmed/Downloads/PC.png"

# Repo files (recommended for deploy)
REPO_LOGO = "assets/company_logo.png"
REPO_ICON = "assets/favicon.png"
os.makedirs("assets", exist_ok=True)  # ensure folder exists for deploy

def pick_asset(abs_path: str, repo_path: str) -> str | None:
    """Prefer absolute path if it exists, else repo path if it exists, else None."""
    if abs_path and os.path.exists(abs_path):
        return abs_path
    if repo_path and os.path.exists(repo_path):
        return repo_path
    return None

LOGO_FILE = pick_asset(USER_LOGO_ABS, REPO_LOGO)
ICON_FILE = pick_asset(USER_ICON_ABS, REPO_ICON)

# ========================
# ---- Page Config (first Streamlit call)
# ========================
st.set_page_config(
    page_title="Tracking Inventory System",
    page_icon=Image.open(ICON_FILE) if ICON_FILE else EMOJI_FALLBACK,
    layout="wide",
)

# ========================
# ---- Session defaults (set early; avoid AttributeError)
# ========================
st.session_state.setdefault("authenticated", False)
st.session_state.setdefault("role", None)
st.session_state.setdefault("username", "")

# ========================
# ---- Light CSS polish
# ========================
st.markdown("""
<style>
  .block-container { padding-top: 2rem; }
  .stButton>button { border-radius: 10px; font-weight: 600; padding: 0.5rem 1rem; }
  .stTextInput input { border-radius: 10px !important; }
  #MainMenu {visibility: hidden;} footer {visibility: hidden;}
</style>
""", unsafe_allow_html=True)

# ========================
# ---- Users from Secrets
# ========================
try:
    USERS = json.loads(st.secrets["users_json"])  # [{"username":"admin","password":"123","role":"admin"}, ...]
except Exception:
    st.error("Missing or invalid `users_json` in `st.secrets`. Add something like:\n"
             '[{"username":"admin","password":"123","role":"admin"}]')
    st.stop()

def check_credentials(username: str, password: str):
    for user in USERS:
        if user.get("username") == username and user.get("password") == password:
            return user.get("role")
    return None

# ========================
# ---- Header & Sidebar
# ========================
def show_header():
    col_logo, col_title = st.columns([1, 9])
    with col_logo:
        if LOGO_FILE and os.path.exists(LOGO_FILE):
            st.image(LOGO_FILE, width=70)
        else:
            st.markdown(f"<div style='font-size:56px;line-height:1'>{EMOJI_FALLBACK}</div>",
                        unsafe_allow_html=True)
    with col_title:
        st.markdown(
            f"<h1 style='margin-bottom:2px'>{APP_TITLE}</h1>"
            f"<p style='color:#64748b;margin-top:0'>{APP_TAGLINE}</p>",
            unsafe_allow_html=True
        )

with st.sidebar:
    if LOGO_FILE and os.path.exists(LOGO_FILE):
        st.image(LOGO_FILE, use_column_width=True)
    else:
        st.markdown(f"### {EMOJI_FALLBACK} {APP_TITLE}")

show_header()

# ========================
# ---- Files & Helpers
# ========================
INVENTORY_FILE = "truckinventory.xlsx"
TRANSFER_LOG_FILE = "transferlog.xlsx"
BACKUP_FOLDER = "backups"
os.makedirs(BACKUP_FOLDER, exist_ok=True)

def backup_file(file_path):
    if os.path.exists(file_path):
        base = os.path.basename(file_path).split(".")[0]
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        shutil.copy(file_path, f"{BACKUP_FOLDER}/{base}_{ts}.xlsx")

def normalize_columns_for_display(df: pd.DataFrame) -> pd.DataFrame:
    for col in df.columns:
        if df[col].dtype == "object" or str(df[col].dtype).startswith("datetime"):
            df[col] = df[col].astype(str)
    return df

def ensure_inventory_file():
    if not os.path.exists(INVENTORY_FILE):
        cols = ["Device Type", "Serial Number", "USER", "Previous User", "TO", "Date issued", "Registered by"]
        pd.DataFrame(columns=cols).to_excel(INVENTORY_FILE, index=False)

def load_inventory() -> pd.DataFrame:
    ensure_inventory_file()
    df = pd.read_excel(INVENTORY_FILE)
    return normalize_columns_for_display(df)

def load_transfer_log() -> pd.DataFrame:
    if not os.path.exists(TRANSFER_LOG_FILE):
        pd.DataFrame(columns=[
            "Device Type", "Serial Number", "From owner", "To owner",
            "Date issued", "Registered by"
        ]).to_excel(TRANSFER_LOG_FILE, index=False)
    df = pd.read_excel(TRANSFER_LOG_FILE)
    return normalize_columns_for_display(df)

def save_inventory(df: pd.DataFrame):
    backup_file(INVENTORY_FILE)
    normalize_columns_for_display(df).to_excel(INVENTORY_FILE, index=False)

def save_transfer_log(df: pd.DataFrame):
    backup_file(TRANSFER_LOG_FILE)
    normalize_columns_for_display(df).to_excel(TRANSFER_LOG_FILE, index=False)

# ========================
# ---- Auth (Login / Logout)
# ========================
if not st.session_state.get("authenticated", False):
    st.subheader("Sign in")
    in_user = st.text_input("Username", placeholder="your.username")
    in_pass = st.text_input("Password", type="password", placeholder="••••••••")
    login_col, _ = st.columns([1, 5])
    with login_col:
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
    st.stop()

with st.sidebar:
    st.markdown("---")
    st.markdown(f"**User:** {st.session_state.get('username','')}")
    st.markdown(f"**Role:** {st.session_state.get('role','')}")
    if st.button("Log out"):
        for k in ("authenticated", "role", "username"):
            if k in st.session_state:
                del st.session_state[k]
        st.rerun()

# ========================
# ---- Tabs
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

            # Update inventory
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

            # Append to transfer log
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

        # Inventory
        df_inventory = load_inventory()
        out_inv = BytesIO()
        with pd.ExcelWriter(out_inv, engine="openpyxl") as writer:
            df_inventory.to_excel(writer, index=False)
        st.download_button(
            label="⬇ Download Inventory",
            data=out_inv.getvalue(),
            file_name="truckinventory_updated.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )

        # Transfer Log
        df_log = load_transfer_log()
        out_log = BytesIO()
        with pd.ExcelWriter(out_log, engine="openpyxl") as writer:
            df_log.to_excel(writer, index=False)
        st.download_button(
            label="⬇ Download Transfer Log",
            data=out_log.getvalue(),
            file_name="transferlog_updated.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
