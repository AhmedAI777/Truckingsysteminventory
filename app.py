import streamlit as st
import pandas as pd
from datetime import datetime
from io import BytesIO

# ========================
# File Paths
# ========================
INVENTORY_FILE = "truckinventory.xlsx"
TRANSFER_LOG_FILE = "transferlog.xlsx"

# ========================
# Load Data
# ========================
def load_inventory():
    return pd.read_excel(INVENTORY_FILE)

def load_transfer_log():
    try:
        return pd.read_excel(TRANSFER_LOG_FILE)
    except FileNotFoundError:
        df = pd.DataFrame(columns=[
            "Device Type", "Serial Number", "From owner", "To owner",
            "Date issued", "Registered by"
        ])
        df.to_excel(TRANSFER_LOG_FILE, index=False)
        return df

def save_inventory(df):
    df.to_excel(INVENTORY_FILE, index=False)

def save_transfer_log(df):
    df.to_excel(TRANSFER_LOG_FILE, index=False)

# ========================
# Streamlit App
# ========================
st.set_page_config(page_title="Trucking Inventory System", page_icon="🚚", layout="wide")
st.title("🚚 Trucking Inventory Management System")

tab1, tab2, tab3, tab4 = st.tabs([
    "📦 View Inventory", 
    "🔄 Transfer Device", 
    "📜 View Transfer Log", 
    "⬇ Export Files"
])

# TAB 1 – View Inventory
with tab1:
    st.subheader("Current Inventory")
    df_inventory = load_inventory()
    st.dataframe(df_inventory)

# TAB 2 – Transfer Device
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
            from_owner = df_inventory.loc[idx, "From owner"] if "From owner" in df_inventory.columns else df_inventory.loc[idx, "USER"]
            device_type = df_inventory.loc[idx, "Device Type"]

            # Update inventory
            df_inventory.loc[idx, "From owner"] = from_owner
            df_inventory.loc[idx, "To owner"] = new_owner
            df_inventory.loc[idx, "Date issued"] = datetime.now().strftime("%m/%d/%Y %H:%M:%S")
            df_inventory.loc[idx, "Registered by"] = registered_by

            # Append to transfer log with numbering
            log_entry = {
                "Device Type": device_type,
                "Serial Number": serial_number,
                "From owner": from_owner,
                "To owner": new_owner,
                "Date issued": datetime.now().strftime("%m/%d/%Y %H:%M:%S"),
                "Registered by": registered_by
            }
            df_log = pd.concat([df_log, pd.DataFrame([log_entry])], ignore_index=True)

            # Save both files
            save_inventory(df_inventory)
            save_transfer_log(df_log)

            st.success(f"✅ Transfer logged: {from_owner} → {new_owner}")

# TAB 3 – View Transfer Log
with tab3:
    st.subheader("Transfer Log History")
    df_log = load_transfer_log()
    st.dataframe(df_log)

# TAB 4 – Export Files
with tab4:
    st.subheader("Download Updated Files")

    # Export inventory
    output_inv = BytesIO()
    with pd.ExcelWriter(output_inv, engine="openpyxl") as writer:
        df_inventory.to_excel(writer, index=False)
    st.download_button(
        label="⬇ Download Inventory",
        data=output_inv.getvalue(),
        file_name="truckinventory_updated.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

    # Export transfer log
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
