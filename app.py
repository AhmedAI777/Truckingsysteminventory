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

client = gspread.authorize(creds)

# Spreadsheet
SPREADSHEET_NAME = "truckinventory"
worksheet = client.open(SPREADSHEET_NAME).sheet1  # Inventory sheet

# ========================
# Helper Functions
# ========================
def normalize_columns(df):
    """Make column names lowercase, strip spaces, and replace spaces with underscores."""
    df.columns = (
        df.columns.str.strip()
                  .str.lower()
                  .str.replace(" ", "_")
    )
    return df

def ensure_required_columns(df):
    """Ensure required columns exist."""
    required_cols = ["device_type", "serial_number", "from_owner", "to_owner", "date_issued", "registered_by"]
    for col in required_cols:
        if col not in df.columns:
            df[col] = ""
    return df

def load_inventory():
    """Load inventory from Google Sheets."""
    data = worksheet.get_all_records()
    df = pd.DataFrame(data)
    df = normalize_columns(df)
    df = ensure_required_columns(df)
    return df

def save_inventory(df):
    """Save inventory back to Google Sheets."""
    worksheet.clear()
    worksheet.update([df.columns.tolist()] + df.values.tolist())

def get_transfer_log_sheet():
    """Get or create TransferLog sheet."""
    try:
        ws = client.open(SPREADSHEET_NAME).worksheet("TransferLog")
    except gspread.exceptions.WorksheetNotFound:
        ws = client.open(SPREADSHEET_NAME).add_worksheet(
            title="TransferLog", rows="1000", cols="10"
        )
        ws.append_row([
            "Device Type", "Serial Number", "From owner", "To owner",
            "Date issued", "Registered by"
        ])
    return ws

def append_to_transfer_log(device_type, serial_number, from_owner, to_owner, registered_by):
    """Append a single row to the TransferLog sheet without deleting history."""
    log_ws = get_transfer_log_sheet()
    log_ws.append_row([
        device_type,
        serial_number,
        from_owner,
        to_owner,
        datetime.now().strftime("%m/%d/%Y %H:%M:%S"),
        registered_by
    ])

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
    df_inventory = load_inventory()
    st.dataframe(df_inventory)

# ========================
# TAB 2: TRANSFER DEVICE
# ========================
with tab2:
    st.subheader("Register Ownership Transfer")

    serial_number = st.text_input("Enter Serial Number").strip()
    new_owner = st.text_input("Enter NEW Owner's Name").strip()
    registered_by = st.text_input("Registered By (IT Staff)").strip()

    if st.button("Transfer Now"):
        df_inventory = load_inventory()

        if serial_number not in df_inventory["serial_number"].values:
            st.error(f"Device with Serial Number {serial_number} not found!")
        else:
            idx = df_inventory[df_inventory["serial_number"] == serial_number].index[0]
            from_owner = df_inventory.loc[idx, "to_owner"]

            # Update main inventory
            df_inventory.loc[idx, "from_owner"] = from_owner
            df_inventory.loc[idx, "to_owner"] = new_owner
            df_inventory.loc[idx, "date_issued"] = datetime.now().strftime("%m/%d/%Y %H:%M:%S")
            df_inventory.loc[idx, "registered_by"] = registered_by

            # Append to log sheet
            device_type = df_inventory.loc[idx, "device_type"]
            append_to_transfer_log(device_type, serial_number, from_owner, new_owner, registered_by)

            # Save updated inventory
            save_inventory(df_inventory)

            st.success(f"✅ Transfer Successful from {from_owner} to {new_owner}")
