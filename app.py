
import streamlit as st
import pandas as pd
from datetime import datetime
from io import BytesIO
import json
import os
import shutil

# ========================
# Load Users from Secrets
# ========================
USERS = json.loads(st.secrets["users_json"])

# ========================
# File Paths
# ========================
INVENTORY_FILE = "truckinventory.xlsx"
TRANSFER_LOG_FILE = "transferlog.xlsx"
BACKUP_FOLDER = "backups"
os.makedirs(BACKUP_FOLDER, exist_ok=True)

# ========================
# Helper Functions
# ========================
def backup_file(file_path):
    """Create timestamped backup of a file."""
    if os.path.exists(file_path):
        backup_name = f"{BACKUP_FOLDER}/{os.path.basename(file_path).split('.')[0]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        shutil.copy(file_path, backup_name)

def normalize_columns_for_display(df):
    """Convert object/mixed columns to strings to prevent ArrowTypeError."""
    for col in df.columns:
        if df[col].dtype == "object" or str(df[col].dtype).startswith("datetime"):
            df[col] = df[col].astype(str)
    return df

def load_inventory():
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
    """Verify username and password."""
    for user in USERS:
        if user["username"] == username and user["password"] == password:
            return user["role"]
    return None

# ========================
# Streamlit App Config
# ========================
st.set_page_config(page_title="Trucking Inventory System", page_icon="🖥️", layout="wide")
st.title("🖥️ Trucking Inventory Management System")

# ========================
# Login
# ========================
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
    st.session_state.role = None
    st.session_state.username = None

if not st.session_state.authenticated:
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
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
        st.dataframe(df_inventory)  # interactive
    else:
        st.table(df_inventory)  # static no arrows

# TAB 2 – Transfer Device
with tab_objects[1]:
    st.subheader("Register Ownership Transfer")

    serial_number = st.text_input("Enter Serial Number")
    new_owner = st.text_input("Enter NEW Owner's Name")
    registered_by = st.session_state.username  # Auto-fill with logged-in username

    if st.button("Transfer Now"):
        if not serial_number.strip() or not new_owner.strip():
            st.error("⚠ All fields are required.")
            st.stop()

        df_inventory = load_inventory()
        df_log = load_transfer_log()

        if serial_number not in df_inventory["Serial Number"].values:
            st.error(f"Device with Serial Number {serial_number} not found!")
        else:
            idx = df_inventory[df_inventory["Serial Number"] == serial_number].index[0]
            from_owner = df_inventory.loc[idx, "USER"]
            device_type = df_inventory.loc[idx, "Device Type"]

            # Update inventory
            df_inventory.loc[idx, "Previous User"] = from_owner
            df_inventory.loc[idx, "USER"] = new_owner
            df_inventory.loc[idx, "TO"] = new_owner
            df_inventory.loc[idx, "Date issued"] = datetime.now().strftime("%m/%d/%Y %H:%M:%S")
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
        st.dataframe(df_log)
    else:
        st.table(df_log)

# TAB 4 – Export Files (Admins Only)
if st.session_state.role == "admin" and len(tab_objects) > 3:
    with tab_objects[3]:
        st.subheader("Download Updated Files")

        # Inventory
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
