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

creds = Credentials.from_service_account_info(
    dict(st.secrets["gcp_service_account"]),
    scopes=SCOPES
)

client = gspread.authorize(creds)
SPREADSHEET_NAME = "truckinventory"
worksheet = client.open(SPREADSHEET_NAME).sheet1

# ========================
# Helper Functions
# ========================
def normalize_columns(df):
    """Make all column names lowercase and strip spaces."""
    df.columns = df.columns.str.strip().str.lower()
    return df

def load_inventory():
    """Load inventory from the first sheet."""
    data = worksheet.get_all_records()
    df = pd.DataFrame(data)
    return normalize_columns(df)

def get_transfer_log_sheet():
    """Get or create the TransferLog worksheet."""
    ss = client.open(SPREADSHEET_NAME)
    try:
        return ss.worksheet("TransferLog")
    except gspread.exceptions.WorksheetNotFound:
        ws = ss.add_worksheet(title="TransferLog", rows="1000", cols="10")
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

        if serial_number not in df_inventory["Serial Number"].values:
            st.error(f"Device with Serial Number {Serial_Number} not found!")
        else:
            idx = df_inventory[df_inventory["Serial Number"] == Serial_Number].index[0]
            from_owner = df_inventory.loc[idx, "user"]  # normalized lowercase
            device_type = df_inventory.loc[idx, "device type"]
            date_issued = datetime.now().strftime("%m/%d/%Y %H:%M:%S")

            # Append to TransferLog sheet
            log_ws = get_transfer_log_sheet()
            log_ws.append_row([
                device_type,
                serial_number,
                from_owner,
                new_owner,
                date_issued,
                registered_by
            ])

            st.success(f"✅ Transfer Logged: {from_owner} → {new_owner}")
