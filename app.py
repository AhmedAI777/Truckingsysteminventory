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


import streamlit as st
import pandas as pd
from datetime import datetime
import gspread
from google.oauth2.service_account import Credentials
from gspread_dataframe import set_with_dataframe

# --------------------------- CONFIGURATION ---------------------------
APP_TITLE = "Tracking Inventory Management System"
SUBTITLE = "AdvancedConstruction"
DATE_FMT = "%Y-%m-%d %H:%M:%S"

INVENTORY_WS = "truckinventory"
TRANSFERLOG_WS = "transfer_log"

# --------------------------- PAGE CONFIG -----------------------------
st.set_page_config(page_title=APP_TITLE, layout="wide")
st.markdown(f"## {APP_TITLE}\n**{SUBTITLE}**")

# --------------------------- GOOGLE SHEETS ---------------------------
SCOPES = ["https://www.googleapis.com/auth/spreadsheets", "https://www.googleapis.com/auth/drive"]
creds = Credentials.from_service_account_info(st.secrets["gcp_service_account"], scopes=SCOPES)
gc = gspread.authorize(creds)
sh = gc.open_by_url(st.secrets["sheets"]["url"])

def get_or_create_ws(title, rows=100, cols=26):
    try:
        return sh.worksheet(title)
    except gspread.exceptions.WorksheetNotFound:
        return sh.add_worksheet(title=title, rows=rows, cols=cols)

def read_worksheet(ws_title):
    try:
        ws = get_or_create_ws(ws_title)
        data = ws.get_all_records()
        return pd.DataFrame(data)
    except Exception as e:
        st.error(f"❌ Error reading sheet '{ws_title}': {e}")
        return pd.DataFrame()

def write_worksheet(ws_title, df):
    ws = get_or_create_ws(ws_title)
    ws.clear()
    set_with_dataframe(ws, df)

def append_to_worksheet(ws_title, new_data):
    ws = get_or_create_ws(ws_title)
    df_existing = pd.DataFrame(ws.get_all_records())
    df_combined = pd.concat([df_existing, new_data], ignore_index=True)
    set_with_dataframe(ws, df_combined)

# --------------------------- AUTH & LOGIN ----------------------------
def show_login():
    st.subheader("🔐 Sign In")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        user = st.secrets["auth"]["admins"].get(username) if username in st.secrets["auth"]["admins"] else st.secrets["auth"]["staff"].get(username)
        if user and user == password:
            st.session_state.authenticated = True
            st.session_state.username = username
            st.session_state.name = username
            st.session_state.role = "Admin" if username in st.secrets["auth"]["admins"] else "Staff"
            st.experimental_rerun()
        else:
            st.error("❌ Invalid username or password.")

def top_logout_button():
    if st.session_state.get("authenticated"):
        st.markdown("""<div style='position:fixed; top:10px; right:20px;'>""",
                    unsafe_allow_html=True)
        if st.button("🚪 Logout", key="logout"):
            for key in ["authenticated", "role", "username", "name"]:
                st.session_state.pop(key, None)
            st.experimental_rerun()
        st.markdown("</div>", unsafe_allow_html=True)

# --------------------------- TABS ------------------------------------
def transfer_tab():
    st.subheader("🔁 Transfer Device")
    inventory_df = read_worksheet(INVENTORY_WS)
    if "Screen Size" in inventory_df.columns:
        inventory_df["Screen Size"] = inventory_df["Screen Size"].astype(str)

    if inventory_df.empty:
        st.warning("Inventory is empty. Cannot proceed.")
        return

    serial_list = inventory_df["Serial Number"].dropna().unique().tolist()
    user_list = inventory_df["USER"].dropna().unique().tolist()

    with st.form("transfer_device"):
        serial = st.selectbox("Select Serial Number", serial_list)
        new_owner = st.selectbox("Select New Owner", user_list)
        submitted = st.form_submit_button("Transfer Device")

        if submitted:
            match = inventory_df[inventory_df["Serial Number"] == serial]
            if match.empty:
                st.warning("Serial number not found.")
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
    if df.empty:
        st.info("No transfer history found.")
    else:
        st.dataframe(df)

def inventory_tab():
    st.subheader("📋 Inventory")
    df = read_worksheet(INVENTORY_WS)
    if "Screen Size" in df.columns:
        df["Screen Size"] = df["Screen Size"].astype(str)
    if df.empty:
        st.warning("Inventory is empty.")
    else:
        st.dataframe(df)
        if st.session_state.role == "Admin":
            csv = df.to_csv(index=False).encode("utf-8")
            st.download_button("⬇️ Download CSV", csv, "inventory.csv", "text/csv")

# --------------------------- MAIN APP -------------------------------
def run_app():
    top_logout_button()
    st.success(f"👋 Welcome, {st.session_state.name} — {st.session_state.role}")

    if st.session_state.role == "Admin":
        tabs = st.tabs(["Register", "Transfer", "History", "Inventory"])
    else:
        tabs = st.tabs(["Transfer", "History", "Inventory"])

    if st.session_state.role == "Admin":
        with tabs[0]:
            st.subheader("📦 Register New Device (Admin only)")
            st.info("Registration functionality goes here.")
        with tabs[1]: transfer_tab()
        with tabs[2]: history_tab()
        with tabs[3]: inventory_tab()
    else:
        with tabs[0]: transfer_tab()
        with tabs[1]: history_tab()
        with tabs[2]: inventory_tab()

# --------------------------- ENTRY POINT -----------------------------
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

if st.session_state.authenticated:
    run_app()
else:
    show_login()
