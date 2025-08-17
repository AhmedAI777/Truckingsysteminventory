import os
from io import BytesIO
from datetime import datetime
import numpy as np
import pandas as pd
import streamlit as st
from streamlit_gsheets import GSheetsConnection

# ==============================
# BASICS
# ==============================
APP_TITLE = "Tracking Inventory Management System"
SUBTITLE  = "AdvancedConstruction"
DATE_FMT  = "%Y-%m-%d %H:%M:%S"

st.set_page_config(page_title=APP_TITLE, layout="wide")
st.markdown(f"## {APP_TITLE}\n**{SUBTITLE}**")

# ==============================
# CONNECTION / CONFIG
# ==============================
# Your working browser URL (no gid). You can also put this in secrets.
DEFAULT_SHEET_URL = "https://docs.google.com/spreadsheets/d/1SHp6gOW4ltsyOT41rwo85e_LELrHkwSwKN33K6XNHFI/edit"

# allow override via secrets -> [connections.gsheets].spreadsheet
SPREADSHEET = (
    st.secrets.get("connections", {})
    .get("gsheets", {})
    .get("spreadsheet", DEFAULT_SHEET_URL)
).strip()

# exact tab names from the bottom of your sheet
INVENTORY_WS   = (st.secrets.get("inventory_tab", "0") or "").strip()
TRANSFERLOG_WS = (st.secrets.get("transferlog_tab", "405007082") or "").strip()

# Streamlit connection (keep this exact)
conn = st.connection("gsheets", type=GSheetsConnection)

def _ws_arg(x):
    try:
        return int(str(x).strip())  # gid
    except Exception:
        return str(x).strip()       # fallback name

# examples
# probe = conn.read(spreadsheet=SPREADSHEET, worksheet=_ws_arg(INVENTORY_WS), nrows=3, ttl=0)
# inv   = conn.read(spreadsheet=SPREADSHEET, worksheet=_ws_arg(INVENTORY_WS), ttl=0)
# log   = conn.read(spreadsheet=SPREADSHEET, worksheet=_ws_arg(TRANSFERLOG_WS), ttl=0)

# ==============================
# HELPERS
# ==============================
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

def load_ws(worksheet: str, cols: list[str]) -> pd.DataFrame:
    """Strict read with spreadsheet URL/ID passed every time."""
    df = conn.read(spreadsheet=SPREADSHEET, worksheet=worksheet, ttl=0)
    return _ensure_cols(df, cols)

def safe_load_ws(worksheet: str, cols: list[str], label: str) -> pd.DataFrame:
    """Safe read with friendly message instead of crash."""
    try:
        return load_ws(worksheet, cols)
    except Exception as e:
        st.warning(
            f"Couldn’t read **{label}** from Google Sheets. "
            f"Check sharing/publishing and tab name. Error: {type(e).__name__}"
        )
        st.caption(f"(worksheet requested = '{worksheet}')")
        return _ensure_cols(None, cols)

def save_ws(worksheet: str, df: pd.DataFrame) -> None:
    conn.update(spreadsheet=SPREADSHEET, worksheet=worksheet, data=df)

# columns we maintain in the inventory sheet
ALL_COLS = [
    "Serial Number","Device Type","Brand","Model","CPU",
    "Hard Drive 1","Hard Drive 2","Memory","GPU","Screen Size",
    "USER","Previous User","TO","Department","Email Address",
    "Contact Number","Location","Office","Notes","Date issued","Registered by",
]

# ==============================
# OPTIONAL DIAGNOSTICS
# ==============================
with st.expander("🔍 Connection diagnostics", expanded=False):
    st.write({"spreadsheet": SPREADSHEET})
    st.write({"INVENTORY_WS": INVENTORY_WS, "TRANSFERLOG_WS": TRANSFERLOG_WS})
    try:
        probe = conn.read(spreadsheet=SPREADSHEET, worksheet=INVENTORY_WS, nrows=3, ttl=0)
        st.write("Inventory probe:", getattr(probe, "shape", None))
        st.dataframe(probe)
    except Exception as e:
        st.info("Inventory probe failed:")
        st.exception(e)
    try:
        probe2 = conn.read(spreadsheet=SPREADSHEET, worksheet=TRANSFERLOG_WS, nrows=3, ttl=0)
        st.write("Transfer log probe:", getattr(probe2, "shape", None))
        st.dataframe(probe2)
    except Exception as e:
        st.info("Transfer log probe failed:")
        st.exception(e)

# ==============================
# UI TABS
# ==============================
tab_reg, tab_inv, tab_transfer, tab_log, tab_export = st.tabs(
    ["📝 Register", "📦 View Inventory", "🔄 Transfer Device", "📜 Transfer Log", "⬇ Export"]
)

# ------------------------------
# 1) REGISTER
# ------------------------------
with tab_reg:
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
            inv = safe_load_ws(INVENTORY_WS, ALL_COLS, "inventory")
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
                    "Registered by": "system",
                }
                inv = pd.concat([inv, pd.DataFrame([row])], ignore_index=True)
                save_ws(INVENTORY_WS, inv)
                st.success("✅ Saved to Google Sheets.")

# ------------------------------
# 2) VIEW INVENTORY
# ------------------------------
with tab_inv:
    st.subheader("Current Inventory")

    # Your working pattern: read with spreadsheet + usecols
    try:
        # safer by column names; if you prefer indices: usecols=[0, 10]
        preview = conn.read(
            spreadsheet=SPREADSHEET,
            worksheet=INVENTORY_WS,
            usecols=["Serial Number", "USER"],
            ttl=0,
        )
        preview = preview.dropna(how="all")
        st.caption("Quick preview (Serial Number & USER)")
        st.dataframe(preview, use_container_width=True)
    except Exception as e:
        st.info("Quick preview unavailable.")
        st.exception(e)

    inv = safe_load_ws(INVENTORY_WS, ALL_COLS, "inventory")
    if not inv.empty and "Date issued" in inv.columns:
        _ts = pd.to_datetime(inv["Date issued"], errors="coerce")
        inv = inv.assign(_ts=_ts).sort_values("_ts", ascending=False, na_position="last").drop(columns="_ts")
    st.dataframe(nice_display(inv), use_container_width=True)

# ------------------------------
# 3) TRANSFER DEVICE
# ------------------------------
with tab_transfer:
    st.subheader("Register Ownership Transfer")
    inv = safe_load_ws(INVENTORY_WS, ALL_COLS, "inventory")
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

            log_cols = ["Device Type","Serial Number","From owner","To owner","Date issued","Registered by"]
            log = safe_load_ws(TRANSFERLOG_WS, log_cols, "transfer log")
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

# ------------------------------
# 4) TRANSFER LOG
# ------------------------------
with tab_log:
    st.subheader("Transfer Log")
    log_cols = ["Device Type","Serial Number","From owner","To owner","Date issued","Registered by"]
    log = safe_load_ws(TRANSFERLOG_WS, log_cols, "transfer log")
    if not log.empty and "Date issued" in log.columns:
        _ts = pd.to_datetime(log["Date issued"], errors="coerce")
        log = log.assign(_ts=_ts).sort_values("_ts", ascending=False, na_position="last").drop(columns="_ts")
    st.dataframe(nice_display(log), use_container_width=True)

# ------------------------------
# 5) EXPORT
# ------------------------------
with tab_export:
    st.subheader("Download Exports")

    inv = safe_load_ws(INVENTORY_WS, ALL_COLS, "inventory")
    inv_x = BytesIO()
    with pd.ExcelWriter(inv_x, engine="openpyxl") as w:
        inv.to_excel(w, index=False)
    inv_x.seek(0)
    st.download_button("⬇ Download Inventory", inv_x.getvalue(),
                       file_name="inventory.xlsx",
                       mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

    log_cols = ["Device Type","Serial Number","From owner","To owner","Date issued","Registered by"]
    log = safe_load_ws(TRANSFERLOG_WS, log_cols, "transfer log")
    log_x = BytesIO()
    with pd.ExcelWriter(log_x, engine="openpyxl") as w:
        log.to_excel(w, index=False)
    log_x.seek(0)
    st.download_button("⬇ Download Transfer Log", log_x.getvalue(),
                       file_name="transfer_log.xlsx",
                       mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
