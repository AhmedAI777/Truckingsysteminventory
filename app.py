import pandas as pd
import numpy as np
from io import BytesIO
from datetime import datetime
import streamlit as st
from streamlit_gsheets import GSheetsConnection

# =============================
# BASIC SETTINGS
# =============================
APP_TITLE = "Tracking Inventory Management System"
SUBTITLE  = "AdvancedConstruction"
DATE_FMT  = "%Y-%m-%d %H:%M:%S"

st.set_page_config(page_title=APP_TITLE, layout="wide")
st.markdown(f"## {APP_TITLE}\n**{SUBTITLE}**")

# =============================
# CONNECTION (public read-only or gspread write)
# .streamlit/secrets.toml example:
# [connections.gsheets]
# type = "gspread"  # or "public" for read-only
# spreadsheet = "https://docs.google.com/spreadsheets/d/<ID>/edit"
#
# inventory_tab   = "0"          # gid or sheet name
# transferlog_tab = "405007082"  # gid or sheet name
#
# admin_pin = "YOUR-STRONG-PIN"
# =============================
GS = st.secrets.get("connections", {}).get("gsheets", {})
SPREADSHEET   = GS.get("spreadsheet", "")
MODE          = GS.get("type", "public").lower()
CAN_WRITE     = MODE == "gspread"

INVENTORY_WS  = st.secrets.get("inventory_tab", "0")
TRANSFER_WS   = st.secrets.get("transferlog_tab", "405007082")

ADMIN_PIN     = str(st.secrets.get("admin_pin", "")).strip()

conn = st.connection("gsheets", type=GSheetsConnection)

# =============================
# SIDEBAR: SIMPLE ROLE CONTROL
# =============================
if "is_admin" not in st.session_state:
    st.session_state.is_admin = False

with st.sidebar:
    st.markdown("### 🔐 Access")
    if st.session_state.is_admin:
        st.success("Role: Admin")
        if st.button("Lock to Staff"):
            st.session_state.is_admin = False
            st.rerun()
    else:
        st.info("Role: Staff")
        pin = st.text_input("Admin PIN", type="password", placeholder="Enter PIN")
        if st.button("Unlock Admin"):
            if ADMIN_PIN and pin == ADMIN_PIN:
                st.session_state.is_admin = True
                st.rerun()
            else:
                st.error("Invalid PIN")

IS_ADMIN = st.session_state.is_admin

# Policy: admins control everything, staff can only transfer + view
ALLOW_REGISTER = IS_ADMIN
ALLOW_TRANSFER = True
ALLOW_EXPORT   = IS_ADMIN

# =============================
# HELPERS
# =============================
def _ws_arg(x):
    """Support both gid (int) and sheet name (str)."""
    s = str(x).strip()
    try:
        return int(s)
    except Exception:
        return s

def _ensure_cols(df: pd.DataFrame, cols: list[str]) -> pd.DataFrame:
    if df is None or df.empty:
        return pd.DataFrame(columns=cols)
    df = df.fillna("")
    for c in cols:
        if c not in df.columns:
            df[c] = ""
    return df[cols + [c for c in df.columns if c not in cols]]

def nice_display(df: pd.DataFrame) -> pd.DataFrame:
    if df is None or df.empty:
        return df
    out = df.copy()
    for col in out.columns:
        try:
            if np.issubdtype(out[col].dtype, np.datetime64) or "date" in col.lower():
                s = pd.to_datetime(out[col], errors="ignore")
                if hasattr(s, "dt"):
                    out[col] = s.dt.strftime(DATE_FMT)
        except Exception:
            pass
    out = out.replace({np.nan: ""})
    for c in out.columns:
        out[c] = out[c].astype(str).replace({"NaT": "", "nan": "", "NaN": ""})
    return out

def load_ws(worksheet, cols):
    try:
        df = conn.read(spreadsheet=SPREADSHEET, worksheet=_ws_arg(worksheet), ttl=0)
        return _ensure_cols(df, cols)
    except Exception as e:
        st.warning(
            f"Couldn’t read data from Google Sheets (worksheet={worksheet}). "
            f"Check sharing/GID. Error: {type(e).__name__}"
        )
        return _ensure_cols(None, cols)

def save_ws(worksheet, df):
    if not CAN_WRITE:
        st.error("App is in public (read-only) mode. Switch connection type to 'gspread' to enable writes.")
        return False
    try:
        conn.update(spreadsheet=SPREADSHEET, worksheet=_ws_arg(worksheet), data=df)
        return True
    except Exception as e:
        st.error(f"Write failed: {type(e).__name__}")
        return False

# =============================
# COLUMNS
# =============================
ALL_COLS = [
    "Serial Number","Device Type","Brand","Model","CPU",
    "Hard Drive 1","Hard Drive 2","Memory","GPU","Screen Size",
    "USER","Previous User","TO","Department","Email Address",
    "Contact Number","Location","Office","Notes","Date issued","Registered by"
]
LOG_COLS = ["Device Type","Serial Number","From owner","To owner","Date issued","Registered by"]

# =============================
# TABS
# =============================
tab_reg, tab_inv, tab_xfer, tab_log, tab_export = st.tabs(
    ["📝 Register", "📦 View Inventory", "🔄 Transfer Device", "📜 Transfer Log", "⬇ Export"]
)

# -----------------------------
# 1) REGISTER (Admin only)
# -----------------------------
with tab_reg:
    st.subheader("Register New Inventory Item")
    if not ALLOW_REGISTER:
        st.info("Registration is disabled for staff. (Read-only mode)")
        disabled = True
    else:
        disabled = False

    with st.form("reg_form", clear_on_submit=False):
        c1, c2 = st.columns(2)
        with c1:
            serial = st.text_input("Serial Number *", disabled=disabled)
            device = st.text_input("Device Type *", disabled=disabled)
            brand  = st.text_input("Brand", disabled=disabled)
            model  = st.text_input("Model", disabled=disabled)
            cpu    = st.text_input("CPU", disabled=disabled)
        with c2:
            hdd1   = st.text_input("Hard Drive 1", disabled=disabled)
            hdd2   = st.text_input("Hard Drive 2", disabled=disabled)
            mem    = st.text_input("Memory", disabled=disabled)
            gpu    = st.text_input("GPU", disabled=disabled)
            screen = st.text_input("Screen Size", disabled=disabled)
        submitted = st.form_submit_button("Save Item", disabled=disabled)

    if submitted and ALLOW_REGISTER:
        if not serial.strip() or not device.strip():
            st.error("Serial Number and Device Type are required.")
        else:
            inv = load_ws(INVENTORY_WS, ALL_COLS)
            if serial.strip() in inv["Serial Number"].astype(str).values:
                st.error(f"Serial Number '{serial}' already exists.")
            else:
                row = {
                    "Serial Number": serial.strip(),
                    "Device Type": device.strip(),
                    "Brand": brand.strip(),
                    "Model": model.strip(),
                    "CPU": cpu.strip(),
                    "Hard Drive 1": hdd1.strip(),
                    "Hard Drive 2": hdd2.strip(),
                    "Memory": mem.strip(),
                    "GPU": gpu.strip(),
                    "Screen Size": screen.strip(),
                    "USER": "", "Previous User": "", "TO": "",
                    "Department": "", "Email Address": "", "Contact Number": "",
                    "Location": "", "Office": "", "Notes": "",
                    "Date issued": datetime.now().strftime(DATE_FMT),
                    "Registered by": "admin",
                }
                inv = pd.concat([inv, pd.DataFrame([row])], ignore_index=True)
                if save_ws(INVENTORY_WS, inv):
                    st.success("✅ Saved to Google Sheets.")

# -----------------------------
# 2) VIEW INVENTORY (single full table)
# -----------------------------
with tab_inv:
    st.subheader("Current Inventory")
    inv = load_ws(INVENTORY_WS, ALL_COLS)
    st.dataframe(nice_display(inv), use_container_width=True, hide_index=True)

# -----------------------------
# 3) TRANSFER DEVICE (staff & admin)
# -----------------------------
with tab_xfer:
    st.subheader("Register Ownership Transfer")
    inv = load_ws(INVENTORY_WS, ALL_COLS)

    serials = sorted(inv["Serial Number"].astype(str).dropna().unique().tolist())
    pick = st.selectbox("Serial Number", ["— Select —"] + serials)
    chosen_serial = None if pick == "— Select —" else pick

    if chosen_serial:
        row = inv[inv["Serial Number"].astype(str) == chosen_serial]
        if not row.empty:
            r = row.iloc[0]
            st.caption(f"Device: {r.get('Device Type','')} • Brand: {r.get('Brand','')} • "
                       f"Model: {r.get('Model','')} • CPU: {r.get('CPU','')}")
        else:
            st.warning("Serial not found in inventory.")

    new_owner = st.text_input("New Owner (required)")
    do_transfer = st.button(
        "Transfer Now",
        type="primary",
        disabled=not (ALLOW_TRANSFER and CAN_WRITE and chosen_serial and new_owner.strip())
    )

    if do_transfer:
        idx_list = inv.index[inv["Serial Number"].astype(str) == chosen_serial].tolist()
        if not idx_list:
            st.error(f"Device with Serial Number {chosen_serial} not found!")
        else:
            idx = idx_list[0]
            prev_user = inv.loc[idx, "USER"]
            # update inventory
            inv.loc[idx, "Previous User"] = str(prev_user or "")
            inv.loc[idx, "USER"] = new_owner.strip()
            inv.loc[idx, "TO"] = new_owner.strip()
            inv.loc[idx, "Date issued"] = datetime.now().strftime(DATE_FMT)
            inv.loc[idx, "Registered by"] = "admin" if IS_ADMIN else "staff"

            # append to log
            log = load_ws(TRANSFER_WS, LOG_COLS)
            log_row = {
                "Device Type": inv.loc[idx, "Device Type"],
                "Serial Number": chosen_serial,
                "From owner": str(prev_user or ""),
                "To owner": new_owner.strip(),
                "Date issued": datetime.now().strftime(DATE_FMT),
                "Registered by": "admin" if IS_ADMIN else "staff",
            }
            log = pd.concat([log, pd.DataFrame([log_row])], ignore_index=True)

            ok1 = save_ws(INVENTORY_WS, inv)
            ok2 = save_ws(TRANSFER_WS, log)
            if ok1 and ok2:
                st.success(f"✅ Transfer saved: {prev_user or '(blank)'} → {new_owner.strip()}")

# -----------------------------
# 4) TRANSFER LOG (sorted, clean index)
# -----------------------------
with tab_log:
    st.subheader("Transfer Log")
    log = load_ws(TRANSFER_WS, LOG_COLS)
    if not log.empty and "Date issued" in log.columns:
        log["Date issued"] = pd.to_datetime(log["Date issued"], errors="coerce")
        log = log.sort_values("Date issued", ascending=False, na_position="last").reset_index(drop=True)
    if not log.empty:
        log.insert(0, "#", range(1, len(log) + 1))
    st.dataframe(nice_display(log), use_container_width=True, hide_index=True)

# -----------------------------
# 5) EXPORT (Admin only)
# -----------------------------
with tab_export:
    st.subheader("Download Exports")
    if not ALLOW_EXPORT:
        st.info("Export is restricted to admins.")
    else:
        inv = load_ws(INVENTORY_WS, ALL_COLS)
        inv_x = BytesIO()
        with pd.ExcelWriter(inv_x, engine="openpyxl") as w:
            inv.to_excel(w, index=False)
        inv_x.seek(0)
        st.download_button("⬇ Download Inventory", inv_x.getvalue(),
                           file_name="inventory.xlsx",
                           mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

        log = load_ws(TRANSFER_WS, LOG_COLS)
        log_x = BytesIO()
        with pd.ExcelWriter(log_x, engine="openpyxl") as w:
            log.to_excel(w, index=False)
        log_x.seek(0)
        st.download_button("⬇ Download Transfer Log", log_x.getvalue(),
                           file_name="transfer_log.xlsx",
                           mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
