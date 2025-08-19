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

# app.py
import os
import base64
from datetime import datetime

import streamlit as st
import pandas as pd
import gspread
from google.oauth2.service_account import Credentials
from gspread_dataframe import set_with_dataframe

# =============================================================================
# CONFIG
# =============================================================================
APP_TITLE = "Tracking Inventory Management System"
SUBTITLE  = "AdvancedConstruction"
DATE_FMT  = "%Y-%m-%d %H:%M:%S"

# Default to your sheet URL; can be overridden in secrets
SHEET_URL_DEFAULT = "https://docs.google.com/spreadsheets/d/1SHp6gOW4ltsyOT41rwo85e_LELrHkwSwKN33K6XNHFI/edit"

# Worksheet titles (created if missing)
INVENTORY_WS   = "truckinventory"
TRANSFERLOG_WS = "transfer_log"

st.set_page_config(page_title=APP_TITLE, layout="wide")

# =============================================================================
# STYLE (font + header + optional toolbar hide)
# =============================================================================
def _inject_font_css(font_path: str, family: str = "FounderGroteskCondensed"):
    """Embed local OTF if present; otherwise skip silently."""
    if not os.path.exists(font_path):
        return
    with open(font_path, "rb") as f:
        b64 = base64.b64encode(f.read()).decode("utf-8")
    st.markdown(
        f"""
        <style>
          @font-face {{
            font-family: '{family}';
            src: url(data:font/otf;base64,{b64}) format('opentype');
            font-weight: normal;
            font-style: normal;
            font-display: swap;
          }}
          html, body, [class*="css"] {{
            font-family: '{family}', -apple-system, BlinkMacSystemFont, "Segoe UI",
                         Roboto, "Helvetica Neue", Arial, "Noto Sans", sans-serif !important;
          }}
          h1,h2,h3,h4,h5,h6, .stTabs [role="tab"] {{
            font-family: '{family}', sans-serif !important;
          }}
          section.main > div {{ padding-top: 0.6rem; }}
        </style>
        """,
        unsafe_allow_html=True,
    )

def render_header():
    _inject_font_css("FounderGroteskCondensed-Regular.otf")

    c_logo, c_title, c_user = st.columns([1.2, 6, 3], gap="small")

    with c_logo:
        if os.path.exists("company_logo.jpeg"):
            # Streamlit compatibility: some versions use use_column_width, newer use use_container_width
            try:
                st.image("company_logo.jpeg", use_container_width=True)
            except TypeError:
                st.image("company_logo.jpeg", use_column_width=True)

    with c_title:
        st.markdown(f"### {APP_TITLE}")
        st.caption(SUBTITLE)

    with c_user:
        username = st.session_state.get("username", "")
        role = st.session_state.get("role", "")
        st.markdown(
            f"""<div style="display:flex; align-items:center; justify-content:flex-end; gap:1rem;">
                   <div>
                     <div style="font-weight:600;">Welcome, {username}</div>
                     <div>Role: <b>{role}</b></div>
                   </div>
                 </div>""",
            unsafe_allow_html=True,
        )
        if st.button("Logout"):
            for key in ["authenticated", "role", "username", "name"]:
                st.session_state.pop(key, None)
            st.rerun()

    st.markdown("<hr style='margin-top:0.8rem;'>", unsafe_allow_html=True)


def hide_table_toolbar_for_non_admin():
    if st.session_state.get("role") != "Admin":
        st.markdown(
            """
            <style>
              div[data-testid="stDataFrame"] div[data-testid="stElementToolbar"] { display:none !important; }
              div[data-testid="stDataEditor"]  div[data-testid="stElementToolbar"] { display:none !important; }
              div[data-testid="stElementToolbar"] { display:none !important; }
            </style>
            """,
            unsafe_allow_html=True
        )

# =============================================================================
# GOOGLE SHEETS (gspread)
# =============================================================================
SCOPES = ["https://www.googleapis.com/auth/spreadsheets", "https://www.googleapis.com/auth/drive"]

# Service account from secrets
creds = Credentials.from_service_account_info(st.secrets["gcp_service_account"], scopes=SCOPES)
gc = gspread.authorize(creds)

# Sheet URL from secrets OR default to your URL
SHEET_URL = st.secrets.get("sheets", {}).get("url", SHEET_URL_DEFAULT)
sh = gc.open_by_url(SHEET_URL)

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
        st.error(f"Error reading sheet '{ws_title}': {e}")
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

# =============================================================================
# AUTH (simple, from secrets)
# =============================================================================
def load_users():
    admins = st.secrets["auth"]["admins"]
    staff = st.secrets["auth"]["staff"]
    users = {}
    for user, pw in admins.items():
        if user != "type":
            users[user] = {"password": pw, "role": "Admin", "name": user}
    for user, pw in staff.items():
        users[user] = {"password": pw, "role": "Staff", "name": user}
    return users

USERS = load_users()

def show_login():
    st.subheader("🔐 Sign In")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login", type="primary"):
        user = USERS.get(username)
        if user and user["password"] == password:
            st.session_state.authenticated = True
            st.session_state.username = username
            st.session_state.name = user["name"]
            st.session_state.role = user["role"]
            st.rerun()
        else:
            st.error("❌ Invalid username or password.")

# =============================================================================
# TABS
# =============================================================================
def inventory_tab():
    st.subheader("📋 Inventory")
    df = read_worksheet(INVENTORY_WS)
    if df.empty:
        st.warning("Inventory is empty.")
    else:
        if st.session_state.role == "Admin":
            st.dataframe(df, use_container_width=True)
        else:
            st.dataframe(df, use_container_width=True, hide_index=True)

def transfer_tab():
    st.subheader("🔁 Transfer Device")
    inventory_df = read_worksheet(INVENTORY_WS)
    if inventory_df.empty:
        st.warning("Inventory is empty.")
        return

    if "Screen Size" in inventory_df.columns:
        inventory_df["Screen Size"] = inventory_df["Screen Size"].astype(str)

    serial_list = inventory_df["Serial Number"].dropna().unique().tolist()
    user_list = inventory_df["USER"].dropna().unique().tolist()

    with st.form("transfer_device"):
        serial = st.selectbox("Serial Number", serial_list)
        new_owner = st.selectbox("New Owner", user_list)
        submitted = st.form_submit_button("Transfer Now")

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
            for col in ["USER", "Date issued", "Registered by"]:
                inventory_df.loc[idx, col] = row[col]

            write_worksheet(INVENTORY_WS, inventory_df)

            transfer_row = row[["Device Type","Serial Number","From owner","To owner","Date issued","Registered by"]]
            append_to_worksheet(TRANSFERLOG_WS, pd.DataFrame([transfer_row]))

            st.success(f"✅ Device {serial} transferred to {new_owner}")

def history_tab():
    st.subheader("📜 Transfer Log")
    df = read_worksheet(TRANSFERLOG_WS)
    if df.empty:
        st.info("No transfer history found.")
    else:
        st.dataframe(df, use_container_width=True)

def export_tab():
    st.subheader("⬇️ Export Inventory")
    df = read_worksheet(INVENTORY_WS)
    if df.empty:
        st.warning("Nothing to export.")
        return
    csv = df.to_csv(index=False).encode("utf-8")
    st.download_button("Download CSV", csv, "inventory.csv", "text/csv")

# =============================================================================
# MAIN
# =============================================================================
def run_app():
    render_header()
    hide_table_toolbar_for_non_admin()

    if st.session_state.role == "Admin":
        tabs = st.tabs(["📋 View Inventory", "🔁 Transfer Device", "📜 Transfer Log", "⬇️ Export"])
        with tabs[0]: inventory_tab()
        with tabs[1]: transfer_tab()
        with tabs[2]: history_tab()
        with tabs[3]: export_tab()
    else:
        tabs = st.tabs(["📋 View Inventory", "🔁 Transfer Device", "📜 Transfer Log"])
        with tabs[0]: inventory_tab()
        with tabs[1]: transfer_tab()
        with tabs[2]: history_tab()

# =============================================================================
# ENTRY
# =============================================================================
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

if st.session_state.authenticated:
    run_app()
else:
    show_login()





