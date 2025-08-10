import streamlit as st
import pandas as pd
import os
from datetime import datetime

# ========================
# File Paths
# ========================
INVENTORY_PATH = "truckinventory.xlsx"
TRANSFER_LOG_PATH = "transferlog.xlsx"

# ========================
# Helper Functions
# ========================
def load_inventory():
    """Load inventory from Excel."""
    if not os.path.exists(INVENTORY_PATH):
        st.error("Inventory file not found!")
        return pd.DataFrame()
    return pd.read_excel(INVENTORY_PATH)

def save_inventory(df):
    """Save inventory to Excel."""
    df.to_excel(INVENTORY_PATH, index=False)

def load_transfer_log():
    """Load the transfer log from Excel and sort newest first."""
    if not os.path.exists(TRANSFER_LOG_PATH):
        # Create empty transfer log if it doesn't exist
        df = pd.DataFrame(columns=[
            "Device Type", "Serial Number", "From owner", "To owner",
            "Date issued", "Registered by"
        ])
        df.to_excel(TRANSFER_LOG_PATH, index=False)
    else:
        df = pd.read_excel(TRANSFER_LOG_PATH)

    if "Date issued" in df.columns and not df.empty:
        # Ensure datetime type for sorting
        df["Date issued"] = pd.to_datetime(df["Date issued"], errors="coerce")
        df = df.sort_values(by="Date issued", ascending=False)

    return df

def save_transfer_log(df):
    """Save transfer log to Excel."""
    df.to_excel(TRANSFER_LOG_PATH, index=False)

# ========================
# Streamlit UI
# ========================
st.set_page_config(page_title="Trucking Inventory System (Excel Version)", page_icon="🚚", layout="wide")
st.title("🚚 Trucking Inventory Management System (Excel Version)")

tab1, tab2, tab3 = st.tabs(["📦 View Inventory", "🔄 Transfer Device", "📜 Transfer Log"])

# ========================
# TAB 1: VIEW INVENTORY
# ========================
with tab1:
    st.subheader("Current Inventory (Read Only)")
    df_inventory = load_inventory()
    st.dataframe(df_inventory)

# ========================
# TAB 2: TRANSFER DEVICE
# ========================
with tab2:
    st.subheader("Register Ownership Transfer")

    serial_number = st.text_input("Enter Serial Number")
    new_owner = st.text_input("Enter NEW Owner's Name")
    registered_by = st.text_input("Registered By (IT Staff)")

    if st.button("Transfer Now"):
        df_inventory = load_inventory()

        if "Serial Number" not in df_inventory.columns:
            st.error("Inventory file is missing the 'Serial Number' column.")
        elif serial_number not in df_inventory["Serial Number"].values:
            st.error(f"Device with Serial Number {serial_number} not found!")
        else:
            idx = df_inventory[df_inventory["Serial Number"] == serial_number].index[0]
            from_owner = df_inventory.loc[idx, "USER"] if "USER" in df_inventory.columns else "Unknown"
            device_type = df_inventory.loc[idx, "Device Type"] if "Device Type" in df_inventory.columns else "Unknown"
            date_issued = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Update inventory
            if "USER" in df_inventory.columns:
                df_inventory.loc[idx, "USER"] = new_owner
            save_inventory(df_inventory)

            # Log the transfer
            df_transfer_log = load_transfer_log()
            new_entry = {
                "Device Type": device_type,
                "Serial Number": serial_number,
                "From owner": from_owner,
                "To owner": new_owner,
                "Date issued": date_issued,
                "Registered by": registered_by
            }
            df_transfer_log = pd.concat([pd.DataFrame([new_entry]), df_transfer_log], ignore_index=True)
            save_transfer_log(df_transfer_log)

            st.success(f"✅ Transfer Successful from {from_owner} to {new_owner}")

# ========================
# TAB 3: TRANSFER LOG
# ========================
with tab3:
    st.subheader("📜 Transfer Log (Newest First)")
    df_transfer_log = load_transfer_log()
    st.dataframe(df_transfer_log)
