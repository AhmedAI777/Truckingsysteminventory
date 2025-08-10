import streamlit as st
import pandas as pd
import gspread
from google.oauth2.service_account import Credentials
from datetime import datetime
import json
from google.oauth2.service_account import Credentials

# Google Sheets scopes
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

# Your spreadsheet name
SHEET_NAME = "truckinventory"
worksheet = client.open(SHEET_NAME).sheet1

# Example: Read all data
data = worksheet.get_all_records()
st.write("Google Sheet Data:", data)


# ========================
# LOAD DATA
# ========================
def load_data():
    data = worksheet.get_all_records()
    df = pd.DataFrame(data)
    return df

def save_data(df):
    worksheet.clear()
    worksheet.update([df.columns.values.tolist()] + df.values.tolist())

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
            from_owner = df_inventory.loc[idx, "USER"]
            df_inventory.loc[idx, "Previous User"] = from_owner
            df_inventory.loc[idx, "USER"] = new_owner
            df_inventory.loc[idx, "TO"] = new_owner

            # Append to transfer log sheet
            try:
                worksheet_log = client.open(SHEET_NAME).worksheet("TransferLog")
            except gspread.exceptions.WorksheetNotFound:
                worksheet_log = client.open(SHEET_NAME).add_worksheet(title="TransferLog", rows="1000", cols="10")
                worksheet_log.append_row(["Device Type", "Serial Number", "From owner", "To owner", "Date issued", "Registered by"])

            device_type = df_inventory.loc[idx, "Device Type"]
            worksheet_log.append_row([
                device_type,
                serial_number,
                from_owner,
                new_owner,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                registered_by
            ])

            # Save updated inventory
            save_data(df_inventory)

            st.success(f"✅ Transfer Successful from {from_owner} to {new_owner}")

