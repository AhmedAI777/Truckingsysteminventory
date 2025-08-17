# import os
# from io import BytesIO
# from datetime import datetime
# import numpy as np
# import pandas as pd
# import streamlit as st
# from streamlit_gsheets import GSheetsConnection

# # ==============================
# # BASIC SETTINGS
# # ==============================
# APP_TITLE   = "Tracking Inventory Management System"
# SUBTITLE    = "AdvancedConstruction"
# DATE_FMT    = "%Y-%m-%d %H:%M:%S"

# # Worksheet (tab) names — override via secrets if you want
# INVENTORY_WS   = (st.secrets.get("inventory_tab", "truckinventory") or "").strip()
# TRANSFERLOG_WS = (st.secrets.get("transferlog_tab", "transferlog") or "").strip()

# # ==============================
# # PAGE HEADER
# # ==============================
# st.set_page_config(page_title=APP_TITLE, layout="wide")
# st.markdown(f"## {APP_TITLE}\n**{SUBTITLE}**")


# url = https://docs.google.com/spreadsheets/d/1SHp6gOW4ltsyOT41rwo85e_LELrHkwSwKN33K6XNHFI/edit?gid=405007082#gid=405007082
# conn = st.connection("gsheets", type=GSheetsConnection)
# data = conn.read(inventory_tab, usecols=[0, 5])
# st.dataframe(data)

# # (Optional) quick diagnostics
# with st.expander("🔍 Diagnostics", expanded=False):
#     cfg = st.secrets.get("connections", {}).get("gsheets", {})
#     st.write({"type": cfg.get("type"), "spreadsheet": cfg.get("spreadsheet")})
#     st.write({"INVENTORY_WS": INVENTORY_WS, "TRANSFERLOG_WS": TRANSFERLOG_WS})
#     try:
#         probe = conn.read(worksheet=INVENTORY_WS, nrows=3, ttl=0)
#         st.write("Probe shape:", getattr(probe, "shape", None))
#         st.dataframe(probe)
#     except Exception as e:
#         st.error(f"Probe failed: {type(e).__name__}")
#         st.exception(e)

# # ==============================
# # HELPERS
# # ==============================
# def _ensure_cols(df: pd.DataFrame, cols: list[str]) -> pd.DataFrame:
#     if df is None or df.empty:
#         return pd.DataFrame(columns=cols)
#     df = df.fillna("")
#     for c in cols:
#         if c not in df.columns:
#             df[c] = ""
#     return df[cols] + [df[c] for c in df.columns if c not in cols]

# def load_ws(worksheet: str, cols: list[str]) -> pd.DataFrame:
#     df = conn.read(worksheet=worksheet, ttl=0)
#     return _ensure_cols(df, cols)

# def safe_load_ws(worksheet: str, cols: list[str], label: str) -> pd.DataFrame:
#     try:
#         return load_ws(worksheet, cols)
#     except Exception as e:
#         st.warning(
#             f"Couldn’t read **{label}** from Google Sheets. "
#             f"Check secrets (spreadsheet URL), access, and tab name. Error: {type(e).__name__}"
#         )
#         st.caption(f"(worksheet requested = '{worksheet}')")
#         return _ensure_cols(None, cols)

# def save_ws(worksheet: str, df: pd.DataFrame) -> None:
#     conn.update(worksheet=worksheet, data=df)

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

# # ==============================
# # COLUMNS & TABS
# # ==============================
# ALL_COLS = [
#     "Serial Number","Device Type","Brand","Model","CPU",
#     "Hard Drive 1","Hard Drive 2","Memory","GPU","Screen Size",
#     "USER","Previous User","TO","Department","Email Address",
#     "Contact Number","Location","Office","Notes","Date issued","Registered by"
# ]

# tab_reg, tab_inv, tab_transfer, tab_log, tab_export = st.tabs(
#     ["📝 Register", "📦 View Inventory", "🔄 Transfer Device", "📜 Transfer Log", "⬇ Export"]
# )

# # ==============================
# # 1) REGISTER
# # ==============================
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
#             inv = safe_load_ws(INVENTORY_WS, ALL_COLS, "inventory")
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
#                 save_ws(INVENTORY_WS, inv)
#                 st.success("✅ Saved to Google Sheets.")

# # ==============================
# # 2) VIEW INVENTORY
# # ==============================
# with tab_inv:
#     st.subheader("Current Inventory")

#     # Quick preview: first 6 columns (A–F)
#     try:
#         preview = conn.read(worksheet=INVENTORY_WS, usecols=list(range(6)), ttl=5)
#         preview = preview.dropna(how="all")
#         st.caption("Quick preview (first 6 columns):")
#         st.dataframe(preview, use_container_width=True)
#     except Exception as e:
#         st.info("Quick preview unavailable.")
#         st.exception(e)

#     # Full table
#     inv = safe_load_ws(INVENTORY_WS, ALL_COLS, "inventory")
#     if not inv.empty and "Date issued" in inv.columns:
#         _ts = pd.to_datetime(inv["Date issued"], errors="coerce")
#         inv = inv.assign(_ts=_ts).sort_values("_ts", ascending=False, na_position="last").drop(columns="_ts")
#     st.dataframe(nice_display(inv), use_container_width=True)

# # ==============================
# # 3) TRANSFER DEVICE
# # ==============================
# with tab_transfer:
#     st.subheader("Register Ownership Transfer")
#     inv = safe_load_ws(INVENTORY_WS, ALL_COLS, "inventory")
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
#             log = safe_load_ws(TRANSFERLOG_WS, log_cols, "transfer log")
#             log_row = {
#                 "Device Type": inv.loc[idx, "Device Type"],
#                 "Serial Number": chosen_serial,
#                 "From owner": str(prev_user or ""),
#                 "To owner": new_owner.strip(),
#                 "Date issued": datetime.now().strftime(DATE_FMT),
#                 "Registered by": "system",
#             }
#             log = pd.concat([log, pd.DataFrame([log_row])], ignore_index=True)

#             save_ws(INVENTORY_WS, inv)
#             save_ws(TRANSFERLOG_WS, log)
#             st.success(f"✅ Transfer saved: {prev_user or '(blank)'} → {new_owner.strip()}")

# # ==============================
# # 4) TRANSFER LOG
# # ==============================
# with tab_log:
#     st.subheader("Transfer Log")
#     log_cols = ["Device Type","Serial Number","From owner","To owner","Date issued","Registered by"]
#     log = safe_load_ws(TRANSFERLOG_WS, log_cols, "transfer log")
#     if not log.empty and "Date issued" in log.columns:
#         _ts = pd.to_datetime(log["Date issued"], errors="coerce")
#         log = log.assign(_ts=_ts).sort_values("_ts", ascending=False, na_position="last").drop(columns="_ts")
#     st.dataframe(nice_display(log), use_container_width=True)

# # ==============================
# # 5) EXPORT
# # ==============================
# with tab_export:
#     st.subheader("Download Exports")

#     inv = safe_load_ws(INVENTORY_WS, ALL_COLS, "inventory")
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
#     log = safe_load_ws(TRANSFERLOG_WS, log_cols, "transfer log")
#     log_x = BytesIO()
#     with pd.ExcelWriter(log_x, engine="openpyxl") as w:
#         log.to_excel(w, index=False)
#     log_x.seek(0)
#     st.download_button(
#         "⬇ Download Transfer Log", log_x.getvalue(),
#         file_name="transfer_log.xlsx",
#         mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
#     )




from unittest.mock import mock_open, patch

import pandas as pd
import pytest
import streamlit as st
from pandas.testing import assert_frame_equal

from streamlit_gsheets import GSheetsConnection


@pytest.fixture()
def expected_df() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "date": ["1/1/1975", "2/1/1975", "3/1/1975", "4/1/1975", "5/1/1975"],
            "births": [265775, 241045, 268849, 247455, 254545],
        }
    )


def test_read_public_sheet(expected_df: pd.DataFrame):
    url = "https://docs.google.com/spreadsheets/d/1SHp6gOW4ltsyOT41rwo85e_LELrHkwSwKN33K6XNHFI/edit?gid=405007082#gid=405007082"

    conn = st.connection("connection_name", type=GSheetsConnection)

    df = conn.read(spreadsheet=url, usecols=[0, 1])

    assert_frame_equal(df.head(), expected_df)


def test_query_public_sheet():
    url = "https://docs.google.com/spreadsheets/d/1SHp6gOW4ltsyOT41rwo85e_LELrHkwSwKN33K6XNHFI/edit?gid=405007082#gid=405007082"

    conn = st.connection("connection_name", type=GSheetsConnection)

    df = conn.query("select date from my_table where births = 265775", spreadsheet=url)

    assert len(df) == 1
    assert df["date"].values[0] == "1/1/1975"


def test_query_worksheet_public_sheet():
    url = "https://docs.google.com/spreadsheets/d/1JDy9md2VZPz4JbYtRPJLs81_3jUK47nx6GYQjgU8qNY/edit"
    worksheet = 405007082  # Example 2, note that this is the gid, not the worksheet name

    conn = st.connection("connection_name", type=GSheetsConnection)

    df = conn.query(
        "select date from my_table where births = 1000000",
        spreadsheet=url,
        worksheet=worksheet,
    )

    assert len(df) == 1
    assert df["date"].values[0] == "1/1/1975"


secrets_contents = """
[connections.test_connection_name]
spreadsheet = "https://docs.google.com/spreadsheets/d/1JDy9md2VZPz4JbYtRPJLs81_3jUK47nx6GYQjgU8qNY/edit"
"""


@patch("builtins.open", mock_open(read_data=secrets_contents))
def test_secrets_contents(expected_df):
    conn = st.connection("test_connection_name", type=GSheetsConnection)

    df = conn.read()

    assert_frame_equal(df.head(), expected_df)


def test_no_secrets_contents():
    conn = st.connection("other_connection_name", type=GSheetsConnection)

    with pytest.raises(ValueError, match="Spreadsheet must be specified"):
        conn.read()
