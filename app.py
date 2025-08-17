

----------------------------------------------------------------------------------------
import os
from io import BytesIO
from datetime import datetime

import numpy as np
import pandas as pd
import streamlit as st
from streamlit_gsheets import GSheetsConnection

# -----------------------------
# EASY KNOBS
# -----------------------------
APP_TITLE   = "Tracking Inventory Management System"
SUBTITLE    = "AdvancedConstruction"
DATE_FMT    = "%Y-%m-%d %H:%M:%S"



import pandas as pd
import numpy as np
from datetime import datetime
import streamlit as st
from io import BytesIO
from streamlit_gsheets import GSheetsConnection

DATE_FMT = "%Y-%m-%d %H:%M:%S"

# worksheet names (or read from secrets like you did)
INVENTORY_WS   = st.secrets.get("inventory_tab", "truckinventory")
TRANSFERLOG_WS = st.secrets.get("transferlog_tab", "transferlog")

conn = st.connection("gsheets", type=GSheetsConnection)

def _ensure_cols(df: pd.DataFrame, cols: list[str]) -> pd.DataFrame:
    if df is None or df.empty:
        return pd.DataFrame(columns=cols)
    df = df.fillna("")
    for c in cols:
        if c not in df.columns:
            df[c] = ""
    return df[cols + [c for c in df.columns if c not in cols]]

def load_ws(worksheet: str, cols: list[str]) -> pd.DataFrame:
    return _ensure_cols(conn.read(worksheet=worksheet, ttl=0), cols)

def save_ws(worksheet: str, df: pd.DataFrame) -> None:
    conn.update(worksheet=worksheet, data=df)

# Example: read inventory
ALL_COLS = ["Serial Number","Device Type","Brand","Model","CPU",
            "Hard Drive 1","Hard Drive 2","Memory","GPU","Screen Size",
            "USER","Previous User","TO","Department","Email Address",
            "Contact Number","Location","Office","Notes","Date issued","Registered by"]

inv = load_ws(INVENTORY_WS, ALL_COLS)
st.dataframe(inv)

# Example: append one new row
if st.button("Add sample row"):
    row = {c:"" for c in ALL_COLS}
    row["Serial Number"] = "TEST-123"
    row["Device Type"]   = "Desktop"
    row["Date issued"]   = datetime.now().strftime(DATE_FMT)
    inv = pd.concat([inv, pd.DataFrame([row])], ignore_index=True)
    save_ws(INVENTORY_WS, inv)
    st.success("Added.")







# # Read spreadsheet url and tab names (worksheets) from secrets (with fallbacks)
# SPREADSHEET_URL = st.secrets.get(
#     "connections", {}
# ).get("gsheets", {}).get(
#     "spreadsheet",
#     "https://docs.google.com/spreadsheets/d/1SHp6gOW4ltsyOT41rwo85e_LELrHkwSwKN33K6XNHFI/edit"
# )

# INVENTORY_WS   = st.secrets.get("inventory_tab", "truckinventory")
# TRANSFERLOG_WS = st.secrets.get("transferlog_tab", "transferlog")

# # Inventory columns (hardware + meta)
# HW_COLS = [
#     "Serial Number", "Device Type", "Brand", "Model", "CPU",
#     "Hard Drive 1", "Hard Drive 2", "Memory", "GPU", "Screen Size",
# ]
# META_COLS = [
#     "USER", "Previous User", "TO",
#     "Department", "Email Address", "Contact Number", "Location", "Office", "Notes",
#     "Date issued", "Registered by",
# ]
# ALL_COLS = HW_COLS + META_COLS

# -----------------------------
# PAGE / HEADER
# -----------------------------
st.set_page_config(page_title=APP_TITLE, layout="wide")
st.markdown(f"## {APP_TITLE}\n**{SUBTITLE}**")

# Make the connection once
conn = st.connection("gsheets", type=GSheetsConnection)

# -----------------------------
# Small helpers
# -----------------------------
def _ensure_cols(df: pd.DataFrame, cols: list[str]) -> pd.DataFrame:
    if df is None or df.empty:
        return pd.DataFrame(columns=cols)
    df = df.fillna("")
    for c in cols:
        if c not in df.columns:
            df[c] = ""
    # nice order: expected first, any extra columns after
    df = df[cols + [c for c in df.columns if c not in cols]]
    return df

def load_ws(worksheet: str, cols: list[str]) -> pd.DataFrame:
    """Read a worksheet as DataFrame (adds missing columns, keeps blanks)."""
    df = conn.read(
        spreadsheet=SPREADSHEET_URL,  # you can omit this if set in secrets
        worksheet=worksheet,
        ttl=0,                         # always read fresh
    )
    return _ensure_cols(df, cols)

def save_ws(worksheet: str, df: pd.DataFrame) -> None:
    """Write a DataFrame back to the worksheet."""
    conn.update(
        spreadsheet=SPREADSHEET_URL,  # you can omit this if set in secrets
        worksheet=worksheet,
        data=df
    )

def nice_display(df: pd.DataFrame) -> pd.DataFrame:
    """Arrow-friendly display and nice date formatting."""
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

# -----------------------------
# TABS
# -----------------------------
tabs = st.tabs(["📝 Register", "📦 View Inventory", "🔄 Transfer Device", "📜 Transfer Log", "⬇ Export"])

# 1) Register
with tabs[0]:
    st.subheader("Register New Inventory Item")
    with st.form("reg_form", clear_on_submit=False):
        c1, c2 = st.columns(2)
        with c1:
            serial = st.text_input("Serial Number *")
            device = st.text_input("Device Type *")
            brand  = st.text_input("Brand")
            model  = st.text_input("Model")
            cpu    = st.text_input("CPU")
        with c2:
            hdd1   = st.text_input("Hard Drive 1")
            hdd2   = st.text_input("Hard Drive 2")
            mem    = st.text_input("Memory")
            gpu    = st.text_input("GPU")
            screen = st.text_input("Screen Size")
        submitted = st.form_submit_button("Save Item")

    if submitted:
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
                    # meta defaults
                    "USER": "", "Previous User": "", "TO": "",
                    "Department": "", "Email Address": "", "Contact Number": "",
                    "Location": "", "Office": "", "Notes": "",
                    "Date issued": datetime.now().strftime(DATE_FMT),
                    "Registered by": "system",
                }
                inv = pd.concat([inv, pd.DataFrame([row])], ignore_index=True)
                save_ws(INVENTORY_WS, inv)
                st.success("✅ Saved to Google Sheets.")

# 2) View inventory
with tabs[1]:
    st.subheader("Current Inventory")
    inv = load_ws(INVENTORY_WS, ALL_COLS)
    if "Date issued" in inv.columns:
        _ts = pd.to_datetime(inv["Date issued"], errors="coerce")
        inv = inv.assign(_ts=_ts).sort_values("_ts", ascending=False, na_position="last").drop(columns="_ts")
    st.dataframe(nice_display(inv), use_container_width=True)

# 3) Transfer device (just Serial + New Owner; the rest auto)
with tabs[2]:
    st.subheader("Register Ownership Transfer")

    inv = load_ws(INVENTORY_WS, ALL_COLS)
    serials = sorted(inv["Serial Number"].astype(str).dropna().unique().tolist())
    pick = st.selectbox("Serial Number", ["— Select —"] + serials)
    chosen_serial = None if pick == "— Select —" else pick

    if chosen_serial:
        row = inv[inv["Serial Number"].astype(str) == chosen_serial]
        if not row.empty:
            r = row.iloc[0]
            st.caption(f"Device: {r.get('Device Type','')} • Brand: {r.get('Brand','')} • Model: {r.get('Model','')} • CPU: {r.get('CPU','')}")
        else:
            st.warning("Serial not found in inventory.")

    new_owner = st.text_input("New Owner (required)")
    do_transfer = st.button("Transfer Now", type="primary", disabled=not (chosen_serial and new_owner.strip()))

    if do_transfer:
        idx_list = inv.index[inv["Serial Number"].astype(str) == chosen_serial].tolist()
        if not idx_list:
            st.error(f"Device with Serial Number {chosen_serial} not found!")
        else:
            idx = idx_list[0]
            prev_user = inv.loc[idx, "USER"]

            inv.loc[idx, "Previous User"] = str(prev_user or "")
            inv.loc[idx, "USER"] = new_owner.strip()
            inv.loc[idx, "TO"] = new_owner.strip()
            inv.loc[idx, "Date issued"] = datetime.now().strftime(DATE_FMT)
            inv.loc[idx, "Registered by"] = "system"

            # Log the transfer
            log = load_ws(TRANSFERLOG_WS, ["Device Type","Serial Number","From owner","To owner","Date issued","Registered by"])
            log_row = {
                "Device Type": inv.loc[idx, "Device Type"],
                "Serial Number": chosen_serial,
                "From owner": str(prev_user or ""),
                "To owner": new_owner.strip(),
                "Date issued": datetime.now().strftime(DATE_FMT),
                "Registered by": "system",
            }
            log = pd.concat([log, pd.DataFrame([log_row])], ignore_index=True)

            save_ws(INVENTORY_WS, inv)
            save_ws(TRANSFERLOG_WS, log)
            st.success(f"✅ Transfer saved: {prev_user or '(blank)'} → {new_owner.strip()}")

# 4) View transfer log
with tabs[3]:
    st.subheader("Transfer Log")
    log = load_ws(TRANSFERLOG_WS, ["Device Type","Serial Number","From owner","To owner","Date issued","Registered by"])
    if "Date issued" in log.columns:
        _ts = pd.to_datetime(log["Date issued"], errors="coerce")
        log = log.assign(_ts=_ts).sort_values("_ts", ascending=False, na_position="last").drop(columns="_ts")
    st.dataframe(nice_display(log), use_container_width=True)

# 5) Export
with tabs[4]:
    st.subheader("Download Exports")
    # Inventory
    inv = load_ws(INVENTORY_WS, ALL_COLS)
    inv_x = BytesIO()
    with pd.ExcelWriter(inv_x, engine="openpyxl") as w:
        inv.to_excel(w, index=False)
    inv_x.seek(0)
    st.download_button("⬇ Download Inventory", inv_x.getvalue(),
                       file_name="inventory.xlsx",
                       mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

    # Log
    log = load_ws(TRANSFERLOG_WS, ["Device Type","Serial Number","From owner","To owner","Date issued","Registered by"])
    log_x = BytesIO()
    with pd.ExcelWriter(log_x, engine="openpyxl") as w:
        log.to_excel(w, index=False)
    log_x.seek(0)
    st.download_button("⬇ Download Transfer Log", log_x.getvalue(),
                       file_name="transfer_log.xlsx",
                       mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
