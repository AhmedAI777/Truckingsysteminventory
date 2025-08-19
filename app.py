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

from datetime import datetime
import pandas as pd
import streamlit as st
import gspread
from google.oauth2.service_account import Credentials
from gspread_dataframe import set_with_dataframe

# -------------------- Config --------------------
APP_TITLE = "Tracking Inventory Management System"
SUBTITLE = "AdvancedConstruction"
DATE_FMT = "%Y-%m-%d %H:%M:%S"

INVENTORY_WS = st.secrets.get("inventory_tab", "truckinventory").strip()
TRANSFERLOG_WS = st.secrets.get("transferlog_tab", "transfer_log").strip()

st.set_page_config(page_title=APP_TITLE, layout="wide")

# -------------------- Google Sheets --------------------
SCOPES = ["https://www.googleapis.com/auth/spreadsheets", "https://www.googleapis.com/auth/drive"]
creds = Credentials.from_service_account_info(dict(st.secrets["gcp_service_account"]), scopes=SCOPES)
gc = gspread.authorize(creds)
sh = gc.open_by_url(st.secrets["sheets"]["url"])

# -------------------- Session --------------------
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
    st.session_state.role = None

# -------------------- Helpers --------------------
def get_or_create_ws(title: str, rows: int = 100, cols: int = 26):
    try:
        return sh.worksheet(title)
    except gspread.exceptions.WorksheetNotFound:
        return sh.add_worksheet(title=title, rows=rows, cols=cols)

def read_worksheet(ws_title: str) -> pd.DataFrame:
    try:
        ws = get_or_create_ws(ws_title)
        return pd.DataFrame(ws.get_all_records())
    except Exception as e:
        st.error(f"❌ Failed to read from sheet '{ws_title}': {e}")
        return pd.DataFrame()

def write_worksheet(ws_title: str, df: pd.DataFrame):
    ws = get_or_create_ws(ws_title)
    ws.clear()
    set_with_dataframe(ws, df)

def append_to_worksheet(ws_title: str, new_data: pd.DataFrame):
    ws = get_or_create_ws(ws_title)
    existing = pd.DataFrame(ws.get_all_records())
    combined = pd.concat([existing, new_data], ignore_index=True)
    set_with_dataframe(ws, combined)

# -------------------- Auth --------------------
def show_login():
    st.subheader("🔐 Sign In")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    role = st.selectbox("Role", ["Admin", "Staff"])
    if st.button("Login"):
        if username and password:
            st.session_state.authenticated = True
            st.session_state.role = role
            st.experimental_rerun()
        else:
            st.error("❌ Invalid credentials")

def top_logout_button():
    if st.session_state.authenticated:
        if st.button("🚪 Logout", key="logout", help="Click to log out"):
            st.session_state.authenticated = False
            st.session_state.role = None
            st.experimental_rerun()

# -------------------- Tabs --------------------
def transfer_tab():
    st.subheader("🔁 Transfer Device")

    inventory_df = read_worksheet(INVENTORY_WS)
    if inventory_df.empty:
        st.warning("No inventory data available.")
        return

    serial_list = inventory_df["Serial Number"].dropna().unique().tolist()

    with st.form("transfer_device"):
        serial = st.selectbox("Select Serial Number", serial_list)
        new_owner = st.text_input("New Owner")

        submit = st.form_submit_button("Transfer Device")

        if submit:
            match = inventory_df[inventory_df["Serial Number"] == serial]
            if match.empty:
                st.warning("⚠️ Serial number not found.")
                return

            row = match.iloc[0].copy()
            row["From owner"] = row.get("USER", "")
            row["To owner"] = new_owner
            row["Date issued"] = datetime.now().strftime(DATE_FMT)
            row["Registered by"] = new_owner
            row["USER"] = new_owner

            idx = match.index[0]
            inventory_df.loc[idx, "USER"] = new_owner
            inventory_df.loc[idx, "Date issued"] = row["Date issued"]
            inventory_df.loc[idx, "Registered by"] = new_owner
            write_worksheet(INVENTORY_WS, inventory_df)

            transfer_row = row[[
                "Device Type", "Serial Number", "From owner", "To owner",
                "Date issued", "Registered by"
            ]]
            append_to_worksheet(TRANSFERLOG_WS, pd.DataFrame([transfer_row]))

            st.success(f"✅ Device {serial} transferred to {new_owner}")

def history_tab():
    st.subheader("📝 Transfer Log")
    df = read_worksheet(TRANSFERLOG_WS)
    st.dataframe(df if not df.empty else pd.DataFrame())

def inventory_tab():
    st.subheader("📋 Inventory")
    df = read_worksheet(INVENTORY_WS)
    if df.empty:
        st.warning("No inventory data found.")
    else:
        st.dataframe(df)

        if st.session_state.role == "Admin":
            csv = df.to_csv(index=False).encode("utf-8")
            st.download_button("⬇️ Download CSV", csv, "inventory.csv", "text/csv")

def register_tab():
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
            email = st.text_input("Email Address")
            phone = st.text_input("Contact Number")
            date_issued = st.date_input("Date Issued", value=datetime.now())

        if st.form_submit_button("Register Device"):
            new_device = pd.DataFrame([{
                "Serial Number": serial,
                "Device Type": device_type,
                "Brand": brand,
                "Model": model,
                "USER": user,
                "Department": department,
                "Location": location,
                "Email Address": email,
                "Contact Number": phone,
                "Date issued": date_issued.strftime(DATE_FMT),
                "Registered by": user
            }])
            append_to_worksheet(INVENTORY_WS, new_device)
            st.success(f"✅ Device {serial} registered.")

# -------------------- Main --------------------
if not st.session_state.authenticated:
    show_login()
else:
    top_logout_button()
    st.title(APP_TITLE)
    st.caption(SUBTITLE)
    st.success(f"👤 Logged in as: {st.session_state.role}")

    role = st.session_state.role
    if role == "Admin":
        tab_labels = ["Register", "Transfer", "History", "Export"]
    else:
        tab_labels = ["Transfer", "History", "Inventory"]

    tabs = st.tabs(tab_labels)
    tab_map = {label: i for i, label in enumerate(tab_labels)}

    if "Register" in tab_labels:
        with tabs[tab_map["Register"]]:
            register_tab()
    with tabs[tab_map["Transfer"]]:
        transfer_tab()
    with tabs[tab_map["History"]]:
        history_tab()
    if "Export" in tab_labels:
        with tabs[tab_map["Export"]]:
            inventory_tab()
    if "Inventory" in tab_labels:
        with tabs[tab_map["Inventory"]]:
            inventory_tab()
