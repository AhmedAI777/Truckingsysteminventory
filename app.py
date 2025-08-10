import streamlit as st
import pandas as pd
import gspread
from google.oauth2.service_account import Credentials
from datetime import datetime

# ========================
# Google Sheets Setup
# ========================
SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive"
]

# Authenticate using credentials stored in Streamlit Secrets
creds = Credentials.from_service_account_info(
    dict(st.secrets["gcp_service_account"]),
    scopes=SCOPES
)

# Authorize the gspread client
client = gspread.authorize(creds)

# Spreadsheet name
SPREADSHEET_NAME = "truckinventory"
worksheet = client.open(SPREADSHEET_NAME).sheet1  # First sheet

# ========================
# Helper Functions
# ========================
def load_data():
    """Load inventory sheet as DataFrame with cleaned column names."""
    data = worksheet.get_all_records()
    df = pd.DataFrame(data)

    # Normalize column names to avoid KeyErrors
    df.columns = df.columns.str.strip()
    return df

def save_data(df):
    """Save updated DataFrame back to Google Sheets."""
    worksheet.clear()
    worksheet.update([df.columns.values.tolist()] + df.values.tolist())

def get_transfer_log_sheet():
    """Get or create the TransferLog sheet."""
    try:
        return client.open(SPREADSHEET_NAME).worksheet("TransferLog")
    except gspread.exceptions.WorksheetNotFound:
        ws = client.open(SPREADSHEET_NAME).add_worksheet(
            title="TransferLog", rows="1000", cols="10"
        )
        ws.append_row([
            "Device Type", "Serial Number", "From owner", "To owner",
            "Date issued", "Registered by"
        ])
        return ws

# ========================
# STREAMLIT UI
# ========================
st.set_page_config(page_title="Trucking Inventory System", page_icon="🚚", layout="wide")
st.title("🚚 Trucking Inventory Management System")

tab1, tab2 = st.tabs(["📦 View Inventory", "🔄 Transfer Device"])

# ========================
# TAB 1: VIEW INVENTORY
# ========================
with tab1:
    st.subheader("Current Inventory")
    df_inventory = load_data()
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
        df_inventory = load_data()

        if serial_number not in df_inventory["Serial Number"].values:
            st.error(f"Device with Serial Number {serial_number} not found!")
        else:
            idx = df_inventory[df_inventory["Serial Number"] == serial_number].index[0]
            from_owner = df_inventory.loc[idx, "To owner"]  # Current owner

            # Update inventory
            df_inventory.loc[idx, "From owner"] = from_owner
            df_inventory.loc[idx, "To owner"] = new_owner
            df_inventory.loc[idx, "Date issued"] = datetime.now().strftime("%m/%d/%Y %H:%M:%S")
            df_inventory.loc[idx, "Registered by"] = registered_by

            # Append to TransferLog
            log_ws = get_transfer_log_sheet()
            device_type = df_inventory.loc[idx, "Device Type"]
            log_ws.append_row([
                device_type,
                serial_number,
                from_owner,
                new_owner,
                datetime.now().strftime("%m/%d/%Y %H:%M:%S"),
                registered_by
            ])

            # Save updated inventory
            save_data(df_inventory)

            st.success(f"✅ Transfer Successful from {from_owner} to {new_owner}")
