# ============================ SHEETS (gspread) ============================
from io import BytesIO
from datetime import datetime

import numpy as np
import pandas as pd
import streamlit as st

import gspread
from google.oauth2.service_account import Credentials
from gspread_dataframe import set_with_dataframe

# ------------------------------ Config -----------------------------------
APP_TITLE = "Tracking Inventory Management System"
SUBTITLE = "AdvancedConstruction"
DATE_FMT = "%Y-%m-%d %H:%M:%S"

# Tab names from secrets (defaults if missing)
INVENTORY_WS   = (st.secrets.get("inventory_tab", "truckingsysteminventory") or "").strip()
TRANSFERLOG_WS = (st.secrets.get("transferlog_tab", "transfer_log") or "").strip()

st.set_page_config(page_title=APP_TITLE, layout="wide")
st.markdown(f"## {APP_TITLE}\n**{SUBTITLE}**")

# ------------------------------ Auth -------------------------------------
SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive",
]
creds = Credentials.from_service_account_info(dict(st.secrets["gcp_service_account"]), scopes=SCOPES)
gc = gspread.authorize(creds)
SHEET_URL = st.secrets["sheets"]["url"]
sh = gc.open_by_url(SHEET_URL)

def get_or_create_ws(title: str, rows: int = 100, cols: int = 26):
    try:
        return sh.worksheet(title)
    except gspread.exceptions.WorksheetNotFound:
        return sh.add_worksheet(title=title, rows=rows, cols=cols)

# ------------------------------ Helpers ----------------------------------
ALL_COLS = [
    "Serial Number","Device Type","Brand","Model","CPU",
    "Hard Drive 1","Hard Drive 2","Memory","GPU","Screen Size",
    "USER","Previous User","TO","Department","Email Address",
    "Contact Number","Location","Office","Notes","Date issued","Registered by"
]

def _ensure_cols(df: pd.DataFrame, cols: list[str]) -> pd.DataFrame:



# # ============================ SHEETS (gspread) ============================
# from io import BytesIO
# from datetime import datetime

# import numpy as np
# import pandas as pd
# import streamlit as st

# import gspread
# from google.oauth2.service_account import Credentials
# from gspread_dataframe import set_with_dataframe

# # ------------------------------ App Config --------------------------------
# APP_TITLE = "Tracking Inventory Management System"
# SUBTITLE = "AdvancedConstruction"
# DATE_FMT = "%Y-%m-%d %H:%M:%S"

# # Tab names (can be overridden in secrets)
# INVENTORY_WS   = (st.secrets.get("inventory_tab", "truckingsysteminventory") or "").strip()
# TRANSFERLOG_WS = (st.secrets.get("transferlog_tab", "transfer_log") or "").strip()

# st.set_page_config(page_title=APP_TITLE, layout="wide")
# st.markdown(f"## {APP_TITLE}\n**{SUBTITLE}**")

# # ------------------------------ Secrets / Auth ----------------------------
# SCOPES = [
#     "https://www.googleapis.com/auth/spreadsheets",
#     "https://www.googleapis.com/auth/drive",
# ]
# REQUIRED_KEYS = [
#     "type","project_id","private_key_id","private_key",
#     "client_email","client_id","token_uri"
# ]

# def _pick_service_account_and_url():
#     sa, sheet_url = None, None

#     # Preferred layout
#     if "gcp_service_account" in st.secrets:
#         sa = dict(st.secrets["gcp_service_account"])
#     if "sheets" in st.secrets and "url" in st.secrets["sheets"]:
#         sheet_url = st.secrets["sheets"]["url"]

#     # Fallback: older "connections" layouts
#     if "connections" in st.secrets and (sa is None or sheet_url is None):
#         for name in ("gsheets", "truckingsysteminventory"):
#             sect = st.secrets["connections"].get(name, {})
#             if sa is None and any(k in sect for k in REQUIRED_KEYS):
#                 sa = {k: sect.get(k) for k in REQUIRED_KEYS if k in sect}
#             if sheet_url is None and "spreadsheet" in sect:
#                 sheet_url = sect["spreadsheet"]

#     # Validate
#     if sa is None or any(k not in sa or not sa[k] for k in REQUIRED_KEYS):
#         st.error(
#             "Service account secrets not found. Add them in **Manage app → Settings → Secrets**.\n"
#             "Expected either:\n"
#             "  • [gcp_service_account] + [sheets]\n"
#             "  • or [connections.gsheets] / [connections.truckingsysteminventory]\n"
#         )
#         st.stop()
#     if not sheet_url:
#         st.error("Spreadsheet URL not found in secrets (need [sheets].url or connections.*.spreadsheet).")
#         st.stop()

#     return sa, sheet_url

# sa_info, SHEET_URL = _pick_service_account_and_url()
# creds = Credentials.from_service_account_info(sa_info, scopes=SCOPES)
# gc = gspread.authorize(creds)
# sh = gc.open_by_url(SHEET_URL)

# def get_or_create_ws(title: str, rows: int = 100, cols: int = 26):
#     """Return worksheet by title. Create it if missing."""
#     try:
#         return sh.worksheet(title)
#     except gspread.exceptions.WorksheetNotFound:
#         return sh.add_worksheet(title=title, rows=rows, cols=cols)

# # ------------------------------ Helpers -----------------------------------
# ALL_COLS = [
#     "Serial Number","Device Type","Brand","Model","CPU",
#     "Hard Drive 1","Hard Drive 2","Memory","GPU","Screen Size",
#     "USER","Previous User","TO","Department","Email Address",
#     "Contact Number","Location","Office","Notes","Date issued","Registered by"
# ]

# def _ensure_cols(df: pd.DataFrame, cols: list[str]) -> pd.DataFrame:
#     if df is None or df.empty:
#         return pd.DataFrame(columns=cols)
#     df = df.fillna("")
#     for c in cols:
#         if c not in df.columns:
#             df[c] = ""
#     extra = [c for c in df.columns if c not in cols]
#     return df[cols + extra]

# def read_ws(title: str, required_cols: list[str] | None = None) -> pd.DataFrame:
#     ws = get_or_create_ws(title)
#     rows = ws.get_all_records()  # first row is header
#     df = pd.DataFrame(rows)
#     if required_cols:
#         df = _ensure_cols(df, required_cols)
#     return df

# def write_ws(title: str, df: pd.DataFrame):
#     ws = get_or_create_ws(title)
#     set_with_dataframe(ws, df, include_index=False, include_column_header=True, resize=True)

# def nice_display(df: pd.DataFrame) -> pd.DataFrame:
#     if df is None or df.empty:
#         return df
#     out = df.copy()
#     for col in out.columns:
#         try:
#             if np.issubdtype(out[col].dtype, np.datetime64) or "date" in col.lower():
#                 s = pd.to_datetime(out[col], errors="ignore")
#                 if hasattr(s, "dt"):
#                     out[col] = s.dt.strftime(DATE_FMT)
#         except Exception:
#             pass
#     out = out.replace({np.nan: ""})
#     for c in out.columns:
#         out[c] = out[c].astype(str).replace({"NaT": "", "nan": "", "NaN": ""})
#     return out

# # ------------------------------ UI Tabs -----------------------------------
# tab_reg, tab_inv, tab_transfer, tab_log, tab_export = st.tabs(
#     ["📝 Register", "📦 View Inventory", "🔄 Transfer Device", "📜 Transfer Log", "⬇ Export"]
# )

# # Diagnostics (optional)
# with st.expander("🔍 Diagnostics", expanded=False):
#     st.write({"Spreadsheet URL": SHEET_URL})
#     st.write({"INVENTORY_WS": INVENTORY_WS, "TRANSFERLOG_WS": TRANSFERLOG_WS})
#     try:
#         probe = read_ws(INVENTORY_WS)
#         st.write("Probe shape:", getattr(probe, "shape", None))
#         st.dataframe(probe.head())
#     except Exception as e:
#         st.error(f"Probe failed: {type(e).__name__}")
#         st.exception(e)

# # ------------------------------ 1) REGISTER -------------------------------
# with tab_reg:
#     st.subheader("Register New Inventory Item")
#     with st.form("reg_form", clear_on_submit=False):
#         c1, c2 = st.columns(2)
#         with c1:
#             serial = st.text_input("Serial Number *")
#             device = st.text_input("Device Type *")
#             brand  = st.text_input("Brand")
#             model  = st.text_input("Model")
#             cpu    = st.text_input("CPU")
#         with c2:
#             hdd1   = st.text_input("Hard Drive 1")
#             hdd2   = st.text_input("Hard Drive 2")
#             mem    = st.text_input("Memory")
#             gpu    = st.text_input("GPU")
#             screen = st.text_input("Screen Size")
#         submitted = st.form_submit_button("Save Item")

#     if submitted:
#         if not serial.strip() or not device.strip():
#             st.error("Serial Number and Device Type are required.")
#         else:
#             inv = read_ws(INVENTORY_WS, ALL_COLS)
#             if serial.strip() in inv["Serial Number"].astype(str).values:
#                 st.error(f"Serial Number '{serial}' already exists.")
#             else:
#                 row = {
#                     "Serial Number": serial.strip(),
#                     "Device Type": device.strip(),
#                     "Brand": brand.strip(),
#                     "Model": model.strip(),
#                     "CPU": cpu.strip(),
#                     "Hard Drive 1": hdd1.strip(),
#                     "Hard Drive 2": hdd2.strip(),
#                     "Memory": mem.strip(),
#                     "GPU": gpu.strip(),
#                     "Screen Size": screen.strip(),
#                     "USER": "", "Previous User": "", "TO": "",
#                     "Department": "", "Email Address": "", "Contact Number": "",
#                     "Location": "", "Office": "", "Notes": "",
#                     "Date issued": datetime.now().strftime(DATE_FMT),
#                     "Registered by": "system",
#                 }
#                 inv = pd.concat([inv, pd.DataFrame([row])], ignore_index=True)
#                 try:
#                     write_ws(INVENTORY_WS, inv)
#                     st.success("✅ Saved to Google Sheets.")
#                 except Exception as e:
#                     st.error("Could not write to Google Sheets (service account + sharing required).")
#                     st.exception(e)

# # ------------------------------ 2) VIEW INVENTORY -------------------------
# with tab_inv:
#     st.subheader("Current Inventory")
#     inv = read_ws(INVENTORY_WS, ALL_COLS)
#     if not inv.empty and "Date issued" in inv.columns:
#         _ts = pd.to_datetime(inv["Date issued"], errors="coerce")
#         inv = inv.assign(_ts=_ts).sort_values("_ts", ascending=False, na_position="last").drop(columns="_ts")
#     st.dataframe(nice_display(inv), use_container_width=True)

# # ------------------------------ 3) TRANSFER DEVICE ------------------------
# with tab_transfer:
#     st.subheader("Register Ownership Transfer")
#     inv = read_ws(INVENTORY_WS, ALL_COLS)
#     serials = sorted(inv["Serial Number"].astype(str).dropna().unique().tolist())
#     pick = st.selectbox("Serial Number", ["— Select —"] + serials)
#     chosen_serial = None if pick == "— Select —" else pick

#     if chosen_serial:
#         row = inv[inv["Serial Number"].astype(str) == chosen_serial]
#         if not row.empty:
#             r = row.iloc[0]
#             st.caption(
#                 f"Device: {r.get('Device Type','')} • Brand: {r.get('Brand','')} • "
#                 f"Model: {r.get('Model','')} • CPU: {r.get('CPU','')}"
#             )
#         else:
#             st.warning("Serial not found in inventory.")

#     new_owner = st.text_input("New Owner (required)")
#     do_transfer = st.button("Transfer Now", type="primary", disabled=not (chosen_serial and new_owner.strip()))

#     if do_transfer:
#         idx_list = inv.index[inv["Serial Number"].astype(str) == chosen_serial].tolist()
#         if not idx_list:
#             st.error(f"Device with Serial Number {chosen_serial} not found!")
#         else:
#             idx = idx_list[0]
#             prev_user = inv.loc[idx, "USER"]
#             inv.loc[idx, "Previous User"] = str(prev_user or "")
#             inv.loc[idx, "USER"] = new_owner.strip()
#             inv.loc[idx, "TO"] = new_owner.strip()
#             inv.loc[idx, "Date issued"] = datetime.now().strftime(DATE_FMT)
#             inv.loc[idx, "Registered by"] = "system"

#             log_cols = ["Device Type","Serial Number","From owner","To owner","Date issued","Registered by"]
#             log = read_ws(TRANSFERLOG_WS, log_cols)
#             log_row = {
#                 "Device Type": inv.loc[idx, "Device Type"],
#                 "Serial Number": chosen_serial,
#                 "From owner": str(prev_user or ""),
#                 "To owner": new_owner.strip(),
#                 "Date issued": datetime.now().strftime(DATE_FMT),
#                 "Registered by": "system",
#             }
#             log = pd.concat([log, pd.DataFrame([log_row])], ignore_index=True)

#             try:
#                 write_ws(INVENTORY_WS, inv)
#                 write_ws(TRANSFERLOG_WS, log)
#                 st.success(f"✅ Transfer saved: {prev_user or '(blank)'} → {new_owner.strip()}")
#             except Exception as e:
#                 st.error("Could not write transfer to Google Sheets (service account + sharing required).")
#                 st.exception(e)

# # ------------------------------ 4) TRANSFER LOG ---------------------------
# with tab_log:
#     st.subheader("Transfer Log")
#     log_cols = ["Device Type","Serial Number","From owner","To owner","Date issued","Registered by"]
#     log = read_ws(TRANSFERLOG_WS, log_cols)
#     if not log.empty and "Date issued" in log.columns:
#         _ts = pd.to_datetime(log["Date issued"], errors="coerce")
#         log = log.assign(_ts=_ts).sort_values("_ts", ascending=False, na_position="last").drop(columns="_ts")
#     st.dataframe(nice_display(log), use_container_width=True)

# # ------------------------------ 5) EXPORT --------------------------------
# with tab_export:
#     st.subheader("Download Exports")
#     inv = read_ws(INVENTORY_WS, ALL_COLS)
#     inv_x = BytesIO()
#     with pd.ExcelWriter(inv_x, engine="openpyxl") as w:
#         inv.to_excel(w, index=False)
#     inv_x.seek(0)
#     st.download_button(
#         "⬇ Download Inventory", inv_x.getvalue(),
#         file_name="inventory.xlsx",
#         mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
#     )

#     log_cols = ["Device Type","Serial Number","From owner","To owner","Date issued","Registered by"]
#     log = read_ws(TRANSFERLOG_WS, log_cols)
#     log_x = BytesIO()
#     with pd.ExcelWriter(log_x, engine="openpyxl") as w:
#         log.to_excel(w, index=False)
#     log_x.seek(0)
#     st.download_button(
#         "⬇ Download Transfer Log", log_x.getvalue(),
#         file_name="transfer_log.xlsx",
#         mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
#     )

