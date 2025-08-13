# app.py — Streamlit Tracking Inventory (branded)

import streamlit as st
import pandas as pd
from datetime import datetime
from io import BytesIO
import json
import os
import shutil

# ========================
# Branding / Paths
# ========================
APP_TITLE = "Tracking Inventory Management System"
APP_TAGLINE = "Internal tool • AdvancedConstruction"
LOGO_PATH = "/Users/ahmed/Downloads/Logo.png"   # header + sidebar
FAVICON_PATH = "/Users/ahmed/Downloads/PC.png"     # small tab icon (optional)
EMOJI_FALLBACK = "🖥️"

# Page config MUST be the first Streamlit call
st.set_page_config(
    page_title="Tracking Inventory System",
    page_icon=FAVICON_PATH if os.path.exists(FAVICON_PATH) else EMOJI_FALLBACK,
    layout="wide",
)

# Minimal CSS polish
st.markdown(
    """
    <style>
      .block-container { padding-top: 2rem; }
      .stButton>button { border-radius: 10px; font-weight: 600; padding: 0.5rem 1rem; }
      .stTextInput input { border-radius: 10px !important; }
      #MainMenu {visibility: hidden;} footer {visibility: hidden;}
    </style>
    """,
    unsafe_allow_html=True,
)

# ========================
# Load Users from Secrets
# ========================
USERS = json.loads(st.secrets["users_json"])  # e.g. [{"username":"admin","password":"123","role":"admin"}]

# ========================
# File Paths
# ========================
INVENTORY_FILE = "truckinventory.xlsx"
TRANSFER_LOG_FILE = "transferlog.xlsx"
BACKUP_FOLDER = "backups"
os.makedirs(BACKUP_FOLDER, exist_ok=True)
os.makedirs("assets", exist_ok=True)  # ensures folder exists even if logo missing

# ========================
# Helper Functions
# ========================
def backup_file(file_path):
    """Create timestamped backup of a file."""
    if os.path.exists(file_path):
        backup_name = f"{BACKUP_FOLDER}/{os.path.basename(file_path).split('.')[0]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        shutil.copy(file_path, backup_name)

def normalize_columns_for_display(df):
    """Convert object/datetime columns to strings to avoid ArrowTypeError in Streamlit."""
    for col in df.columns:
        if df[col].dtype == "object" or str(df[col].dtype).startswith("datetime"):
            df[col] = df[col].astype(str)
    return df

def ensure_inventory_file():
    """Create an empty inventory file with expected columns if it doesn't exist."""
    if not os.path.exists(INVENTORY_FILE):
        cols = ["Device Type", "Serial Number", "USER", "Previous User", "TO", "Date issued", "Registered by"]
        pd.DataFrame(columns=cols).to_excel(INVENTORY_FILE, index=False)

def load_inventory():
    ensure_inventory_file()
    df = pd.read_excel(INVENTORY_FILE)
    return normalize_columns_for_display(df)

def load_transfer_log():
    try:
        df = pd.read_excel(TRANSFER_LOG_FILE)
    except FileNotFoundError:
        df = pd.DataFrame(columns=[
            "Device Type", "Serial Number", "From owner", "To owner",
            "Date issued", "Registered by"
        ])
        df.to_excel(TRANSFER_LOG_FILE, index=False)
    return normalize_columns_for_display(df)

def save_inventory(df):
    backup_file(INVENTORY_FILE)
    df = normalize_columns_for_display(df)
    df.to_excel(INVENTORY_FILE, index=False)

def save_transfer_log(df):
    backup_file(TRANSFER_LOG_FILE)
    df = normalize_columns_for_display(df)
    df.to_excel(TRANSFER_LOG_FILE, index=False)

def check_credentials(username, password):
    """Verify username and password; return role on success, else None."""
    for user in USERS:
        if user["username"] == username and user["password"] == password:
            return user["role"]
    return None

def show_header():
    col_logo, col_title = st.columns([1, 9])
    with col_logo:
        if os.path.exists(LOGO_PATH):
            st.image(LOGO_PATH, width=70)
        else:
            st.markdown(
                f"<div style='font-size:56px;line-height:1'>{EMOJI_FALLBACK}</div>",
                unsafe_allow_html=True
            )
    with col_title:
        st.markdown(
            f"<h1 style='margin-bottom:2px'>{APP_TITLE}</h1>"
            f"<p style='color:#64748b;margin-top:0'>{APP_TAGLINE}</p>",
            unsafe_allow_html=True
        )

# ========================
# Sidebar (branding + session)
# ========================
with st.sidebar:
    if os.path.exists(LOGO_PATH):
        st.image(LOGO_PATH, use_column_width=True)
    else:
        st.markdown(f"### {EMOJI_FALLBACK} {APP_TITLE}")

# ========================
# Login / Session State
# ========================
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
    st.session_state.role = None
    st.session_state.username = None

show_header()  # show the header above login or main app

if not st.session_state.authenticated:
    st.subheader("Sign in")
    username = st.text_input("Username", placeholder="your.username")
    password = st.text_input("Password", type="password", placeholder="••••••••")
    login_col, _ = st.columns([1, 5])
    with login_col:
        if st.button("Login", type="primary"):
            role = check_credentials(username, password)
            if role:
                st.session_state.authenticated = True
                st.session_state.role = role
                st.session_state.username = username
                st.success(f"✅ Logged in as {username} ({role})")
                st.rerun()
            else:
                st.error("❌ Invalid username or password")
    st.stop()

# Sidebar user block & logout (visible after login)
with st.sidebar:
    st.markdown("---")
    st.markdown(f"**User:** {st.session_state.username}")
    st.markdown(f"**Role:** {st.session_state.role}")
    if st.button("Log out"):
        for k in ("authenticated", "role", "username"):
            if k in st.session_state:
                del st.session_state[k]
        st.rerun()

# ========================
# Tabs
# ========================
tabs = ["📦 View Inventory", "🔄 Transfer Device", "📜 View Transfer Log"]
if st.session_state.role == "admin":
    tabs.append("⬇ Export Files")  # Export tab only for admins

tab_objects = st.tabs(tabs)

# TAB 1 – View Inventory
with tab_objects[0]:
    st.subheader("Current Inventory")
    df_inventory = load_inventory()
    if st.session_state.role == "admin":
        st.dataframe(df_inventory, use_container_width=True)
    else:
        st.table(df_inventory)

# TAB 2 – Transfer Device
with tab_objects[1]:
    st.subheader("Register Ownership Transfer")

    serial_number = st.text_input("Enter Serial Number")
    new_owner = st.text_input("Enter NEW Owner's Name")
    registered_by = st.session_state.username  # Auto-fill with logged-in username

    if st.button("Transfer Now", type="primary"):
        if not serial_number.strip() or not new_owner.strip():
            st.error("⚠ All fields are required.")
            st.stop()

        df_inventory = load_inventory()
        df_log = load_transfer_log()

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

            # Save updated files
            save_inventory(df_inventory)
            save_transfer_log(df_log)

            st.success(f"✅ Transfer logged: {from_owner} → {new_owner}")

# TAB 3 – View Transfer Log
with tab_objects[2]:
    st.subheader("Transfer Log History")
    df_log = load_transfer_log()
    if st.session_state.role == "admin":
        st.dataframe(df_log, use_container_width=True)
    else:
        st.table(df_log)

# TAB 4 – Export Files (Admins Only)
if st.session_state.role == "admin" and len(tab_objects) > 3:
    with tab_objects[3]:
        st.subheader("Download Updated Files")

        # Inventory
        df_inventory = load_inventory()
        output_inv = BytesIO()
        with pd.ExcelWriter(output_inv, engine="openpyxl") as writer:
            df_inventory.to_excel(writer, index=False)
        st.download_button(
            label="⬇ Download Inventory",
            data=output_inv.getvalue(),
            file_name="truckinventory_updated.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )

        # Transfer Log
        df_log = load_transfer_log()
        output_log = BytesIO()
        with pd.ExcelWriter(output_log, engine="openpyxl") as writer:
            df_log.to_excel(writer, index=False)
        st.download_button(
            label="⬇ Download Transfer Log",
            data=output_log.getvalue(),
            file_name="transferlog_updated.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
