import streamlit as st
import pandas as pd
from datetime import datetime
import os

# ========================
# File paths
# ========================
INVENTORY_FILE = "truckinventory.xlsx"
TRANSFER_LOG_FILE = "transferlog.xlsx"

# ========================
# Helper Functions
# ========================
def load_inventory():
    if os.path.exists(INVENTORY_FILE):
        return pd.read_excel(INVENTORY_FILE)
    else:
        st.error(f"{INVENTORY_FILE} not found.")
        return pd.DataFrame()

def save_inventory(df):
    df.to_excel(INVENTORY_FILE, index=False)

def load_transfer_log():
    if os.path.exists(TRANSFER_LOG_FILE):
        return pd.read_excel(TRANSFER_LOG_FILE)
    else:
        # Create empty log with correct headers
        df = pd.DataFrame(columns=[
            "Device Type", "Serial Number", "From owner", "To owner", 
            "Date issued", "Registered by"
        ])
        df.to_excel(TRANSFER_LOG_FILE, index=False)
        return df

def save_transfer_log(df):
    df.to_excel(TRANSFER_LOG_FILE, index=False)

# ========================
# Streamlit UI
# ========================
st.set_page_config(page_title="Trucking Inventory System (Excel Version)", page_icon="🚚", layout="wide")
st.title("🚚 Trucking Inventory Management System (Excel Version)")

tab1, tab2, tab3 = st.tabs(["📦 View Inventory", "🔄 Transfer Device", "🪵 Transfer Log"])

# ========================
# TAB 1: VIEW INVENTORY
# ========================
with tab1:
    st.subheader("Current Inventory (Read Only)")
    df_inventory = load_inventory()
    st.dataframe(df_inventory)

    if not df_inventory.empty:
        st.download_button(
            label="📥 Download Inventory as Excel",
            data=df_inventory.to_excel(index=False, engine='xlsxwriter'),
            file_name="inventory_export.xlsx"
        )

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
        df_log = load_transfer_log()

        if serial_number not in df_inventory["Serial Number"].values:
            st.error(f"Device with Serial Number {serial_number} not found!")
        else:
            idx = df_inventory[df_inventory["Serial Number"] == serial_number].index[0]
            device_type = df_inventory.loc[idx, "Device Type"]

            # ✅ Get last known owner from transfer log if available
            previous_transfers = df_log[df_log["Serial Number"] == serial_number]
            if not previous_transfers.empty:
                from_owner = previous_transfers.iloc[-1]["To owner"]
            else:
                from_owner = df_inventory.loc[idx, "USER"]

            # Update inventory sheet (current owner info)
            df_inventory.loc[idx, "From owner"] = from_owner
            df_inventory.loc[idx, "To owner"] = new_owner
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

            # Save both
            save_inventory(df_inventory)
            save_transfer_log(df_log)

            st.success(f"✅ Transfer logged: {from_owner} → {new_owner}")

# ========================
# TAB 3: TRANSFER LOG
# ========================
with tab3:
    st.subheader("🪵 Transfer Log (Newest First)")
    df_log = load_transfer_log()

    if not df_log.empty:
        df_log_sorted = df_log.iloc[::-1].reset_index(drop=True)
        df_log_sorted.index += 1  # Start numbering from 1
        st.dataframe(df_log_sorted)
