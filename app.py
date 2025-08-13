# app.py — Tracking Inventory System (Streamlit)
# ✅ Clean header + easy knobs (logo size/placement, fonts, spacing)
# ✅ Logout row UNDER the header (right-aligned)
# ✅ Persistent login across refresh (signed token using st.query_params)
# ✅ Arrow-safe display for mixed-type columns
# ✅ No deprecated API calls (no experimental_rerun, no use_column_width)

import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime
from io import BytesIO
import json
import os
import shutil
import base64
import hmac
import hashlib

# ============================
# 🔧 EASY CONTROLS — Tweak these
# ============================
APP_TITLE        = "AdvancedConstruction"                          # ← Title text
APP_TAGLINE      = "Tracking Inventory Management System"          # ← Subtitle text
FONT_FAMILY      = "Times New Roman"                               # ← Global font (system-safe)
TOP_PADDING_REM  = 2.5                                             # ← Space from very top of page
MAX_CONTENT_W    = 1250                                          # ← Page max width (px)

# --- Logo controls ---
LOGO_FILE        = "assets/company_logo.png"                       # ← Path to logo image
LOGO_WIDTH_PX    = 160                                              # ← Logo width in px (try 120–220)
LOGO_HEIGHT_PX   = None                                            # ← Set an int (e.g., 60/80) or None to auto
LOGO_ALT_EMOJI   = "🖥️"                                           # ← Fallback if file missing

# --- Title & tagline sizing ---
TITLE_SIZE_PX    = 46                                               # ← Title font-size (px)
TAGLINE_SIZE_PX  = 16                                               # ← Tagline font-size (px)

# --- Spacing around header ---
GAP_BELOW_HEADER_PX = 16                                            # ← Space below header divider
LOGOUT_ROW_TOP_MARG = 8                                             # ← Top margin (px) before Logout row

# --- Favicon (optional) ---
ICON_FILE        = "assets/favicon.png"                             # ← Path to favicon (or leave missing)

# --- Security / Login persistence ---
# Put these in .streamlit/secrets.toml for production:
# auth_secret = "a-very-long-random-string"
# users_json = '[{"username":"admin","password":"123","role":"admin"}]'
AUTH_SECRET      = st.secrets.get("auth_secret", "change-me")      # ← Replace in secrets for production

# ============================
# STREAMLIT PAGE CONFIG
# ============================
st.set_page_config(
    page_title="Tracking Inventory System",
    page_icon=ICON_FILE if os.path.exists(ICON_FILE) else LOGO_ALT_EMOJI,
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ============================
# GLOBAL CSS (uses the knobs above)
# ============================
st.markdown(f"""
<style>
/* Global font */
html, body, .stApp, .stApp * {{
  font-family: "{FONT_FAMILY}", Times, serif !important;
}}

/* Hide the sidebar completely */
[data-testid="stSidebar"] {{ display: none !important; }}

/* Page container padding & width */
.block-container {{
  padding-top: {TOP_PADDING_REM}rem;
  max-width: {MAX_CONTENT_W}px;
}}

.brand-title {{
  font-weight: 700;
  font-size: {TITLE_SIZE_PX}px;   /* ← change TITLE_SIZE_PX above */
  margin: 0;
  line-height: 1.1;
}}
.brand-tag {{
  margin: 2px 0 0;
  color: #64748b;
  font-weight: 400;
  font-size: {TAGLINE_SIZE_PX}px; /* ← change TAGLINE_SIZE_PX above */
}}

.header-divider {{
  height: 1px;
  background: #e5e7eb;
  margin: 10px 0 {GAP_BELOW_HEADER_PX}px;  /* ← change GAP_BELOW_HEADER_PX above */
}}

.logout-row {{ margin-top: {LOGOUT_ROW_TOP_MARG}px; }}  /* ← change LOGOUT_ROW_TOP_MARG above */

/* Button sizing/shape consistent with Streamlit toolbar */
.stButton > button {{
  height: 38px;
  padding: 0 .9rem;
  border-radius: 8px;
  font-weight: 600;
}}
.logout-col .stButton > button {{
  background: #f3f4f6;
  color: #111827;
  border: 1px solid #e5e7eb;
}}
.logout-col .stButton > button:hover {{ background: #e5e7eb; }}

/* Tiny breathing room for tabs & subheaders */
.stTabs {{ margin-top: 6px; }}
section[tabindex="0"] h2 {{ margin-top: 8px; }}

#MainMenu, footer {{ visibility: hidden; }}
</style>
""", unsafe_allow_html=True)

# ============================
# SESSION DEFAULTS
# ============================
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
if "role" not in st.session_state:
    st.session_state["role"] = None
if "username" not in st.session_state:
    st.session_state["username"] = ""

# ============================
# USERS (from secrets)
# ============================
try:
    USERS = json.loads(st.secrets["users_json"])
except Exception:
    st.error(
        "Missing `users_json` in secrets. Example: "
        '`[{"username":"admin","password":"123","role":"admin"}]`'
    )
    st.stop()

def get_user_role(username: str):
    for u in USERS:
        if u.get("username") == username:
            return u.get("role")
    return None

# ============================
# URL TOKEN (persistent login across refresh)
# ============================
def make_token(username: str) -> str:
    return hmac.new(
        AUTH_SECRET.encode("utf-8"),
        msg=username.encode("utf-8"),
        digestmod=hashlib.sha256
    ).hexdigest()

def set_auth_query_params(username: str):
    st.query_params.clear()
    st.query_params.update({"u": username, "t": make_token(username)})

def clear_auth_query_params():
    st.query_params.clear()

def try_auto_login_from_url():
    if st.session_state.get("authenticated"):
        return
    params = st.query_params
    u = params.get("u")
    t = params.get("t")
    if not u or not t:
        return
    if hmac.compare_digest(t, make_token(u)):
        role = get_user_role(u)
        if role:
            st.session_state["authenticated"] = True
            st.session_state["username"] = u
            st.session_state["role"] = role

try_auto_login_from_url()

# ============================
# SMALL UTILS
# ============================
def img_to_base64(path: str) -> str | None:
    if os.path.exists(path):
        with open(path, "rb") as f:
            return base64.b64encode(f.read()).decode("utf-8")
    return None

def logo_html(src_path: str, width_px: int, height_px: int | None, alt_emoji: str) -> str:
    """
    Renders logo with exact width/height via HTML (so you can control BOTH).
    - Set height_px to None to keep aspect ratio (auto height).
    """
    b64 = img_to_base64(src_path)
    if not b64:
        return f"<div style='font-size:{int(width_px*0.7)}px;line-height:1'>{alt_emoji}</div>"
    h_style = f"height:{height_px}px;" if height_px else ""
    return f"<img src='data:image/png;base64,{b64}' alt='logo' style='width:{width_px}px;{h_style}display:block;'/>"

# Arrow-safe display-only copy (keeps NaN empty, casts to str)
def for_display(df: pd.DataFrame) -> pd.DataFrame:
    if df is None or df.empty:
        return df
    out = df.copy()
    out = out.replace({np.nan: ""})
    for c in out.columns:
        out[c] = out[c].astype(str)
    return out

# ============================
# HEADER (row1: logo+title, row2: logout right)
# ============================
def show_header():
    # Row 1 — Logo + Text
    c_logo, c_text = st.columns([0.16, 0.84])
    with c_logo:
        st.markdown(logo_html(LOGO_FILE, LOGO_WIDTH_PX, LOGO_HEIGHT_PX, LOGO_ALT_EMOJI), unsafe_allow_html=True)
    with c_text:
        st.markdown(
            f"<h1 class='brand-title'>{APP_TITLE}</h1>"
            f"<div class='brand-tag'>{APP_TAGLINE}</div>",
            unsafe_allow_html=True
        )

    # Row 2 — Logout (right-aligned, below header)
    s, btn = st.columns([0.85, 0.15])
    with btn:
        st.markdown("<div class='logout-col logout-row'>", unsafe_allow_html=True)
        if st.session_state.get("authenticated"):
            if st.button("Logout", use_container_width=True, key="logout_btn"):
                st.session_state["authenticated"] = False
                st.session_state["role"] = None
                st.session_state["username"] = ""
                clear_auth_query_params()
                st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)

    # Divider under both rows
    st.markdown('<div class="header-divider"></div>', unsafe_allow_html=True)

show_header()

# ============================
# FILES & HELPERS
# ============================
INVENTORY_FILE         = "truckinventory.xlsx"
TRANSFER_LOG_PRIMARY   = "transferlog.xlsx"
TRANSFER_LOG_ALT       = "transferlogin.xlsx"
TRANSFER_LOG_FILE      = TRANSFER_LOG_PRIMARY if os.path.exists(TRANSFER_LOG_PRIMARY) else (
                         TRANSFER_LOG_ALT if os.path.exists(TRANSFER_LOG_ALT) else TRANSFER_LOG_PRIMARY)

BACKUP_FOLDER          = "backups"
os.makedirs(BACKUP_FOLDER, exist_ok=True)

def backup_file(file_path):
    if os.path.exists(file_path):
        base = os.path.basename(file_path).split(".")[0]
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        shutil.copy(file_path, f"{BACKUP_FOLDER}/{base}_{ts}.xlsx")

def ensure_inventory_file():
    if not os.path.exists(INVENTORY_FILE):
        cols = ["Device Type", "Serial Number", "USER", "Previous User", "TO", "Date issued", "Registered by"]
        pd.DataFrame(columns=cols).to_excel(INVENTORY_FILE, index=False)

def ensure_transfer_log_file():
    if not os.path.exists(TRANSFER_LOG_FILE):
        cols = ["Device Type", "Serial Number", "From owner", "To owner", "Date issued", "Registered by"]
        pd.DataFrame(columns=cols).to_excel(TRANSFER_LOG_FILE, index=False)

def load_inventory() -> pd.DataFrame:
    ensure_inventory_file()
    return pd.read_excel(INVENTORY_FILE)

def load_transfer_log() -> pd.DataFrame:
    ensure_transfer_log_file()
    return pd.read_excel(TRANSFER_LOG_FILE)

def save_inventory(df: pd.DataFrame):
    backup_file(INVENTORY_FILE)
    df.to_excel(INVENTORY_FILE, index=False)

def save_transfer_log(df: pd.DataFrame):
    backup_file(TRANSFER_LOG_FILE)
    df.to_excel(TRANSFER_LOG_FILE, index=False)

# ============================
# AUTH (login card)
# ============================
if not st.session_state.get("authenticated", False):
    st.subheader("Sign in")
    in_user = st.text_input("Username", placeholder="your.username")
    in_pass = st.text_input("Password", type="password", placeholder="••••••••")
    if st.button("Login", type="primary"):
        role = None
        for u in USERS:
            if u.get("username") == in_user and u.get("password") == in_pass:
                role = u.get("role")
                break
        if role:
            st.session_state["authenticated"] = True
            st.session_state["role"] = role
            st.session_state["username"] = in_user
            set_auth_query_params(in_user)  # persist via URL
            st.success(f"✅ Logged in as {in_user} ({role})")
            st.rerun()
        else:
            st.error("❌ Invalid username or password")
    st.stop()

# ============================
# TABS (main app)
# ============================
tabs = ["📦 View Inventory", "🔄 Transfer Device", "📜 View Transfer Log"]
if st.session_state.get("role") == "admin":
    tabs.append("⬇ Export Files")
tab_objects = st.tabs(tabs)

# TAB 1 – View Inventory
with tab_objects[0]:
    st.subheader("Current Inventory")
    df_inventory = load_inventory()
    if st.session_state.get("role") == "admin":
        st.dataframe(for_display(df_inventory), use_container_width=True)
    else:
        st.table(for_display(df_inventory))

# TAB 2 – Transfer Device
with tab_objects[1]:
    st.subheader("Register Ownership Transfer")
    serial_number  = st.text_input("Enter Serial Number")
    new_owner      = st.text_input("Enter NEW Owner's Name")
    registered_by  = st.session_state.get("username", "")
    if st.button("Transfer Now", type="primary"):
        if not serial_number.strip() or not new_owner.strip():
            st.error("⚠ All fields are required.")
            st.stop()

        df_inventory = load_inventory()
        df_log       = load_transfer_log()

        if "Serial Number" not in df_inventory.columns:
            st.error("Inventory file is missing 'Serial Number' column.")
            st.stop()

        if serial_number not in df_inventory["Serial Number"].values:
            st.error(f"Device with Serial Number {serial_number} not found!")
        else:
            idx         = df_inventory[df_inventory["Serial Number"] == serial_number].index[0]
            from_owner  = df_inventory.loc[idx, "USER"] if "USER" in df_inventory.columns else ""
            device_type = df_inventory.loc[idx, "Device Type"] if "Device Type" in df_inventory.columns else ""

            if "Previous User" in df_inventory.columns:
                df_inventory.loc[idx, "Previous User"] = from_owner
            if "USER" in df_inventory.columns:
                df_inventory.loc[idx, "USER"] = new_owner
            if "TO" in df_inventory.columns:
                df_inventory.loc[idx, "TO"]  = new_owner
            if "Date issued" in df_inventory.columns:
                df_inventory.loc[idx, "Date issued"] = datetime.now().strftime("%m/%d/%Y %H:%M:%S")
            if "Registered by" in df_inventory.columns:
                df_inventory.loc[idx, "Registered by"] = registered_by

            log_entry = {
                "Device Type": device_type,
                "Serial Number": serial_number,
                "From owner": from_owner,
                "To owner": new_owner,
                "Date issued": datetime.now().strftime("%m/%d/%Y %H:%M:%S"),
                "Registered by": registered_by
            }
            df_log = pd.concat([df_log, pd.DataFrame([log_entry])], ignore_index=True)

            save_inventory(df_inventory)
            save_transfer_log(df_log)
            st.success(f"✅ Transfer logged: {from_owner} → {new_owner}")

# TAB 3 – View Transfer Log
with tab_objects[2]:
    st.subheader("Transfer Log History")
    df_log = load_transfer_log()
    if st.session_state.get("role") == "admin":
        st.dataframe(for_display(df_log), use_container_width=True)
    else:
        st.table(for_display(df_log))

# TAB 4 – Export Files (Admins Only)
if st.session_state.get("role") == "admin" and len(tab_objects) > 3:
    with tab_objects[3]:
        st.subheader("Download Updated Files")

        # Inventory export
        df_inventory = load_inventory()
        out_inv = BytesIO()
        with pd.ExcelWriter(out_inv, engine="openpyxl") as writer:
            df_inventory.to_excel(writer, index=False)
        out_inv.seek(0)
        st.download_button(
            label="⬇ Download Inventory",
            data=out_inv.getvalue(),
            file_name="truckinventory_updated.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )

        # Transfer log export
        df_log = load_transfer_log()
        out_log = BytesIO()
        with pd.ExcelWriter(out_log, engine="openpyxl") as writer:
            df_log.to_excel(writer, index=False)
        out_log.seek(0)
        st.download_button(
            label="⬇ Download Transfer Log",
            data=out_log.getvalue(),
            file_name="transferlog_updated.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
