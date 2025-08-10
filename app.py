import streamlit as st
import pandas as pd
from datetime import datetime
import os

# ========================
# Excel File Setup
# ========================
INVENTORY_FILE = "truckinventory.xlsx"
TRANSFER_LOG_FILE = "transferlog.xlsx"

def load_inventory():
    if os.path.exists(INVENTORY_FILE):
        return pd.read_excel(INVENTORY_FILE)
    else:
        st.error(f"Inventory file '{INVENTORY_FILE}' not found!")
        return pd.DataFrame()

def load_transfer_log():
    if os.path.exists(TRANSFER_LOG_FILE):
        return pd.read_excel(TRANSFER_LOG_FILE)
    else:
        # Create new transfer log if it doesn't exist
        df = pd.DataFrame(columns=["Device Type", "Serial Number", "From owner", "To owner", "Date issued", "Registered by"])
        df.to_excel(TRANSFER_LOG_FILE, index=False)
        return df

def save_transfer_log(df):
    df.to_excel(TRANSFER_LOG_FILE, index=False)

# ========================
# STREAMLIT UI
# ========================
st.set_page_config(page_title="Trucking Inventory System", page_icon="🚚", layout="wide")
st.title("🚚 Trucking Inventory Management System (Excel Version)")

tab1, tab2 = st.tabs(["📦 View Inventory", "🔄 Transfer Device"])

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
        df_transfer_log = load_transfer_log()

        if serial_number not in df_inventory["Serial Number"].values:
            st.error(f"Device with Serial Number {serial_number} not found!")
        else:
            idx = df_inventory[df_inventory["Serial Number"] == serial_number].index[0]
            from_owner = df_inventory.loc[idx, "USER"]
            device_type = df_inventory.loc[idx, "Device Type"]
            date_issued = datetime.now().strftime("%m/%d/%Y %H:%M:%S")

            # Append to TransferLog
            new_log_entry = pd.DataFrame([{
                "Device Type": device_type,
                "Serial Number": serial_number,
                "From owner": from_owner,
                "To owner": new_owner,
                "Date issued": date_issued,
                "Registered by": registered_by
            }])

            df_transfer_log = pd.concat([df_transfer_log, new_log_entry], ignore_index=True)
            save_transfer_log(df_transfer_log)

            st.success(f"✅ Transfer Logged in Excel: {from_owner} → {new_owner}")
