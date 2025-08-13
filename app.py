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
LOGO_FILE = "assets/company_logo.png"
ICON_FILE = "assets/favicon.png"

# ========================
# Page Config
# ========================
st.set_page_config(
    page_title="Tracking Inventory System",
    page_icon=ICON_FILE if os.path.exists(ICON_FILE) else "🖥️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ========================
# Custom CSS
# ========================
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Times+New+Roman&display=swap');

[data-testid="stSidebar"] { display: none !important; }

.block-container { padding-top: 2.6rem; max-width: 1100px; }

.brand-title {
  font-family: "Times New Roman", serif;
  font-weight: 800;
  font-size: 38px;
  margin: 0;
}
.brand-tag {
  margin: 3px 0 0;
  color:#64748b;
  font-family: "Times New Roman", serif;
  font-weight: 500;
}
.header-divider { height:1px; background:#e5e7eb; margin:18px 0 28px; }

.stButton>button {
  border-radius:10px;
  font-weight:600;
  padding:.45rem 0.8rem;
}

.stTabs { margin-top: 8px; }

section[tabindex="0"] h2 {
  margin-top: 10px;
}

#MainMenu {visibility:hidden;} footer {visibility:hidden;}
</style>
""", unsafe_allow_html=True)

# ========================
# Session State Defaults
# ========================
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
if "role" not in st.session_state:
    st.session_state["role"] = None
if "username" not in st.session_state:
    st.session_state["username"] = ""

# ========================
# Load Users
# ========================
try:
    USERS = json.loads(st.secrets["users_json"])
except Exception:
    st.error("Missing `users_json` in secrets.")
    st.stop()

def check_credentials(username, password):
    for u in USERS:
        if u.get("username") == username and u.get("password") == password:
            return u.get("role")
    return None

# ========================
# Header
# ========================
def show_header():
    c_logo, c_text, c_btn = st.columns([0.11, 0.74, 0.15])
    with c_logo:
        if os.path.exists(LOGO_FILE):
            st.image(LOGO_FILE, width=64, use_container_width=False)
        else:
            st.markdown("<div style='font-size:44px;line-height:1'>🖥️</div>", unsafe_allow_html=True)
    with c_text:
        st.markdown(f"<h1 class='brand-title'>{APP_TITLE}</h1>", unsafe_allow_html=True)
        st.markdown(f"<div class='brand-tag'>{APP_TAGLINE}</div>", unsafe_allow_html=True)
    with c_btn:
        if st.session_state.get("authenticated"):
            if st.button("Logout"):
                st.session_state["authenticated"] = False
                st.session_state["role"] = None
                st.session_state["username"] = ""
    st.markdown('<div class="header-divider"></div>', unsafe_allow_html=True)

show_header()

# ========================
# Files & Helpers
# ========================
INVENTORY_FILE = "truckinventory.xlsx"
TRANSFER_LOG_FILE = "transferlog.xlsx"
BACKUP_FOLDER = "backups"
os.makedirs(BACKUP_FOLDER, exist_ok=True)

def backup_file(file_path):
    if os.path.exists(file_path):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        shutil.copy(file_path, f"{BACKUP_FOLDER}/{os.path.basename(file_path).split('.')[0]}_{ts}.xlsx")

def load_inventory():
    if not os.path.exists(INVENTORY_FILE):
        pd.DataFrame(columns=["Device Type", "Serial Number", "USER", "Previous User", "TO", "Date issued", "Registered by"]).to_excel(INVENTORY_FILE, index=False)
    return pd.read_excel(INVENTORY_FILE)

def load_transfer_log():
    if not os.path.exists(TRANSFER_LOG_FILE):
        pd.DataFrame(columns=["Device Type", "Serial Number", "From owner", "To owner", "Date issued", "Registered by"]).to_excel(TRANSFER_LOG_FILE, index=False)
    return pd.read_excel(TRANSFER_LOG_FILE)

def save_inventory(df):
    backup_file(INVENTORY_FILE)
    df.to_excel(INVENTORY_FILE, index=False)

def save_transfer_log(df):
    backup_file(TRANSFER_LOG_FILE)
    df.to_excel(TRANSFER_LOG_FILE, index=False)

# ========================
# Login
# ========================
if not st.session_state["authenticated"]:
    st.subheader("Sign in")
    in_user = st.text_input("Username", placeholder="your.username")
    in_pass = st.text_input("Password", type="password", placeholder="••••••••")
    if st.button("Login"):
        role = check_credentials(in_user, in_pass)
        if role:
            st.session_state["authenticated"] = True
            st.session_state["role"] = role
            st.session_state["username"] = in_user
            st.experimental_rerun()
        else:
            st.error("Invalid username or password")
    st.stop()

# ========================
# Tabs
# ========================
tabs = ["📦 View Inventory", "🔄 Transfer Device", "📜 View Transfer Log"]
if st.session_state["role"] == "admin":
    tabs.append("⬇ Export Files")
tab_objects = st.tabs(tabs)

# TAB 1
with tab_objects[0]:
    st.subheader("Current Inventory")
    df_inventory = load_inventory()
    if st.session_state["role"] == "admin":
        st.dataframe(df_inventory, use_container_width=True)
    else:
        st.table(df_inventory)

# TAB 2
with tab_objects[1]:
    st.subheader("Register Ownership Transfer")
    serial_number = st.text_input("Enter Serial Number")
    new_owner = st.text_input("Enter NEW Owner's Name")
    registered_by = st.session_state["username"]
    if st.button("Transfer Now"):
        if not serial_number.strip() or not new_owner.strip():
            st.error("All fields are required.")
        else:
            df_inventory = load_inventory()
            df_log = load_transfer_log()
            if serial_number not in df_inventory["Serial Number"].values:
                st.error(f"Device with Serial Number {serial_number} not found!")
            else:
                idx = df_inventory[df_inventory["Serial Number"] == serial_number].index[0]
                from_owner = df_inventory.loc[idx, "USER"]
                device_type = df_inventory.loc[idx, "Device Type"]
                df_inventory.loc[idx, "Previous User"] = from_owner
                df_inventory.loc[idx, "USER"] = new_owner
                df_inventory.loc[idx, "TO"] = new_owner
                df_inventory.loc[idx, "Date issued"] = datetime.now().strftime("%m/%d/%Y %H:%M:%S")
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
                st.success(f"Transfer logged: {from_owner} → {new_owner}")

# TAB 3
with tab_objects[2]:
    st.subheader("Transfer Log History")
    df_log = load_transfer_log()
    if st.session_state["role"] == "admin":
        st.dataframe(df_log, use_container_width=True)
    else:
        st.table(df_log)

# TAB 4
if st.session_state["role"] == "admin" and len(tab_objects) > 3:
    with tab_objects[3]:
        st.subheader("Download Updated Files")
        out_inv = BytesIO()
        load_inventory().to_excel(out_inv, index=False)
        st.download_button(
            label="⬇ Download Inventory",
            data=out_inv.getvalue(),
            file_name="truckinventory_updated.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
        out_log = BytesIO()
        load_transfer_log().to_excel(out_log, index=False)
        st.download_button(
            label="⬇ Download Transfer Log",
            data=out_log.getvalue(),
            file_name="transferlog_updated.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
