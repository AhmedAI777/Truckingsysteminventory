# # ============================ SHEETS (gspread) ============================
# from io import BytesIO
# from datetime import datetime

# import numpy as np
# import pandas as pd
# import streamlit as st

# import gspread
# from google.oauth2.service_account import Credentials
# from gspread_dataframe import set_with_dataframe

# # ------------------------------ Config -----------------------------------
# APP_TITLE = "Tracking Inventory Management System"
# SUBTITLE = "AdvancedConstruction"
# DATE_FMT = "%Y-%m-%d %H:%M:%S"

# # Tab names from secrets (defaults if missing)
# INVENTORY_WS   = (st.secrets.get("inventory_tab", "truckingsysteminventory") or "").strip()
# TRANSFERLOG_WS = (st.secrets.get("transferlog_tab", "transfer_log") or "").strip()

# st.set_page_config(page_title=APP_TITLE, layout="wide")
# st.markdown(f"## {APP_TITLE}\n**{SUBTITLE}**")

# # ------------------------------ Auth -------------------------------------
# SCOPES = [
#     "https://www.googleapis.com/auth/spreadsheets",
#     "https://www.googleapis.com/auth/drive",
# ]
# creds = Credentials.from_service_account_info(dict(st.secrets["gcp_service_account"]), scopes=SCOPES)
# gc = gspread.authorize(creds)
# SHEET_URL = st.secrets["sheets"]["url"]
# sh = gc.open_by_url(SHEET_URL)

# def get_or_create_ws(title: str, rows: int = 100, cols: int = 26):
#     try:
#         return sh.worksheet(title)
#     except gspread.exceptions.WorksheetNotFound:
#         return sh.add_worksheet(title=title, rows=rows, cols=cols)

# # ------------------------------ Helpers ----------------------------------
# ALL_COLS = [
#     "Serial Number","Device Type","Brand","Model","CPU",
#     "Hard Drive 1","Hard Drive 2","Memory","GPU","Screen Size",
#     "USER","Previous User","TO","Department","Email Address",
#     "Contact Number","Location","Office","Notes","Date issued","Registered by"
# ]

# def _ensure_cols(df: pd.DataFrame, cols: list[str]) -> pd.DataFrame:
#     pass


# tracking_inventory_app.py

from datetime import datetime
from io import BytesIO
import numpy as np
import pandas as pd
import streamlit as st
import gspread
from google.oauth2.service_account import Credentials
from gspread_dataframe import set_with_dataframe

# ---------------------- Config & UI Header ----------------------
APP_TITLE = "Tracking Inventory Management System"
SUBTITLE = "AdvancedConstruction"
DATE_FMT = "%Y-%m-%d %H:%M:%S"

INVENTORY_WS = (st.secrets.get("inventory_tab", "truckingsysteminventory") or "").strip()
TRANSFERLOG_WS = (st.secrets.get("transferlog_tab", "transfer_log") or "").strip()

st.set_page_config(page_title=APP_TITLE, layout="wide")
st.markdown(f"## {APP_TITLE}\n**{SUBTITLE}**")

# ---------------------- Google Sheets Auth ----------------------
SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive",
]

creds = Credentials.from_service_account_info(
    dict(st.secrets["gcp_service_account"]),
    scopes=SCOPES
)
gc = gspread.authorize(creds)
SHEET_URL = st.secrets["sheets"]["url"]
sh = gc.open_by_url(SHEET_URL)

# ---------------------- Sheet Utilities ----------------------
def get_or_create_ws(title: str, rows: int = 100, cols: int = 26):
    try:
        return sh.worksheet(title)
    except gspread.exceptions.WorksheetNotFound:
        return sh.add_worksheet(title=title, rows=rows, cols=cols)

def read_worksheet(ws_title: str) -> pd.DataFrame:
    ws = get_or_create_ws(ws_title)
    records = ws.get_all_records()
    return pd.DataFrame(records)

def write_worksheet(ws_title: str, df: pd.DataFrame):
    ws = get_or_create_ws(ws_title)
    ws.clear()
    set_with_dataframe(ws, df)

def append_to_worksheet(ws_title: str, new_data: pd.DataFrame):
    ws = get_or_create_ws(ws_title)
    existing = pd.DataFrame(ws.get_all_records())
    combined = pd.concat([existing, new_data], ignore_index=True)
    set_with_dataframe(ws, combined)

# ---------------------- Register Device ----------------------
st.subheader("📦 Register New Device")
with st.form("register_device"):
    col1, col2, col3 = st.columns(3)
    with col1:
        serial = st.text_input("Serial Number")
        device_type = st.selectbox("Device Type", ["Desktop", "Printer", "Monitor", "Other"])
        brand = st.text_input("Brand")
    with col2:
        model = st.text_input("Model")
        user = st.text_input("Current User")
        department = st.text_input("Department")
    with col3:
        location = st.text_input("Location")
        registered_by = st.text_input("Registered By")
        date_issued = st.date_input("Date Issued", value=datetime.now())

    register_submit = st.form_submit_button("Register Device")

    if register_submit:
        new_device = pd.DataFrame([{
            "Serial Number": serial,
            "Device Type": device_type,
            "Brand": brand,
            "Model": model,
            "USER": user,
            "Department": department,
            "Location": location,
            "Registered by": registered_by,
            "Date issued": date_issued.strftime(DATE_FMT)
        }])
        append_to_worksheet(INVENTORY_WS, new_device)
        st.success(f"✅ Device {serial} registered successfully.")

# ---------------------- Transfer Device ----------------------
st.subheader("🔁 Transfer Device")
with st.form("transfer_device"):
    col1, col2, col3 = st.columns(3)
    with col1:
        transfer_serial = st.text_input("Serial Number (to transfer)")
        from_user = st.text_input("From User")
    with col2:
        to_user = st.text_input("To User")
        department = st.text_input("New Department")
    with col3:
        transfer_by = st.text_input("Transfer By")
        transfer_date = st.date_input("Transfer Date", value=datetime.now())
        transfer_time = st.time_input("Transfer Time", value=datetime.now().time())

    transfer_submit = st.form_submit_button("Transfer Device")

    if transfer_submit:
        timestamp = f"{transfer_date} {transfer_time.strftime('%H:%M')}"
        transfer_log = pd.DataFrame([{
            "Serial Number": transfer_serial,
            "From": from_user,
            "To": to_user,
            "Department": department,
            "Transfer By": transfer_by,
            "Timestamp": timestamp
        }])
        append_to_worksheet(TRANSFERLOG_WS, transfer_log)

        # Update current user in inventory
        inventory_df = read_worksheet(INVENTORY_WS)
        idx = inventory_df[inventory_df["Serial Number"] == transfer_serial].index
        if not idx.empty:
            inventory_df.at[idx[0], "USER"] = to_user
            inventory_df.at[idx[0], "Department"] = department
            inventory_df.at[idx[0], "Date issued"] = timestamp
            write_worksheet(INVENTORY_WS, inventory_df)
            st.success(f"✅ Device {transfer_serial} transferred successfully.")
        else:
            st.warning("⚠️ Serial number not found in inventory!")

# ---------------------- View Sheets ----------------------
st.subheader("📋 Current Inventory")
st.dataframe(read_worksheet(INVENTORY_WS))

st.subheader("📝 Transfer Log")
st.dataframe(read_worksheet(TRANSFERLOG_WS))
