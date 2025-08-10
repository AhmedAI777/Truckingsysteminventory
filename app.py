import streamlit as st
import pandas as pd
from datetime import datetime
import io
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
        return pd.DataFrame(columns=["Serial Number", "Device Type", "Brand", "Model", "CPU",
                                     "Hard Drive 1", "Hard Drive 2", "Memory", "GPU", "Screen Size", "USER"])

def save_inventory(df):
    df.to_excel(INVENTORY_FILE, index=False)

def load_transfer_log():
    if os.path.exists(TRANSFER_LOG_FILE):
        return pd.read_excel(TRANSFER_LOG_FILE)
    else:
        return pd.DataFrame(columns=["No", "Device Type", "Serial Number", "From owner", "To owner",
                                     "Date issued", "Registered by"])

def save_transfer_log(df):
    df.to_excel(TRANSFER_LOG_FILE, index=False)

def get_next_transfer_no(df):
    """Return the next sequential transfer number."""
    if df.empty:
        return 1
    else:
        return int(df["No"].max()) + 1

# ========================
# Streamlit Config
# ========================
st.set_page_config(page_title="Trucking Inventory System (Excel Version)", page_icon="🚚", layout="wide")
st.title("🚚 Trucking Inventory Management System (Excel Version)")

# Initialize session state
if "inventory" not in st.session_state:
    st.session_state.inventory = load_inventory()

if "transfer_log" not in st.session_state:
    st.session_state.transfer_log = load_transfer_log()

# ========================
# Tabs
# ========================
tab1, tab2, tab3 = st.tabs(["📦 View Inventory", "🔄 Transfer Device", "📜 Transfer Log"])

# ========================
# TAB 1 - Inventory
# ========================
with tab1:
    st.subheader("Current Inventory (Read Only)")
    st.dataframe(st.session_state.inventory)

    # Download Inventory Excel
    output_inv = io.BytesIO()
    with pd.ExcelWriter(output_inv, engine='xlsxwriter') as writer:
        st.session_state.inventory.to_excel(writer, index=False, sheet_name="Inventory")
    st.download_button(
        label="📥 Download Inventory Excel",
        data=output_inv.getvalue(),
        file_name="inventory.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

# ========================
# TAB 2 - Transfer Device
# ========================
with tab2:
    st.subheader("Register Ownership Transfer")

    serial_number = st.text_input("Enter Serial Number")
    new_owner = st.text_input("Enter NEW Owner's Name")
    registered_by = st.text_input("Registered By (IT Staff)")

    if st.button("Transfer Now"):
        inv_df = st.session_state.inventory
        log_df = st.session_state.transfer_log

        if serial_number not in inv_df["Serial Number"].values:
            st.error(f"Device with Serial Number {serial_number} not found in inventory!")
        else:
            idx = inv_df[inv_df["Serial Number"] == serial_number].index[0]
            from_owner = inv_df.loc[idx, "USER"]
            device_type = inv_df.loc[idx, "Device Type"]
            date_issued = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Update inventory
            inv_df.loc[idx, "USER"] = new_owner

            # Append to transfer log with permanent number
            next_no = get_next_transfer_no(log_df)
            new_entry = pd.DataFrame([{
                "No": next_no,
                "Device Type": device_type,
                "Serial Number": serial_number,
                "From owner": from_owner,
                "To owner": new_owner,
                "Date issued": date_issued,
                "Registered by": registered_by
            }])

            log_df = pd.concat([log_df, new_entry], ignore_index=True)

            # Save changes permanently
            st.session_state.inventory = inv_df
            st.session_state.transfer_log = log_df
            save_inventory(inv_df)
            save_transfer_log(log_df)

            st.success(f"✅ Transfer Successful from {from_owner} to {new_owner} (Entry No. {next_no})")

# ========================
# TAB 3 - Transfer Log
# ========================
with tab3:
    st.subheader("📜 Transfer Log (Newest First)")

    log_df = st.session_state.transfer_log.copy()
    log_df = log_df.sort_values(by="No", ascending=False).reset_index(drop=True)

    st.dataframe(log_df)
