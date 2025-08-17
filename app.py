import streamlit as st
import pandas as pd
from streamlit_gsheets import GSheetsConnection

st.set_page_config(page_title="Inventory Viewer", layout="wide")
st.title("Tracking Inventory Management System")
st.caption("AdvancedConstruction")

# Connect using the name from secrets: [connections.gsheets]
conn = st.connection("gsheets", type=GSheetsConnection)

# Option A: read by worksheet/tab NAME (e.g. "truckinventory")
INVENTORY_WS = st.secrets.get("inventory_tab", "truckinventory")

# Option B: read by GID (works even if tab name changes)
# INVENTORY_WS = 405007082

# Read specific columns (e.g. A and F => indexes 0 and 5)
try:
    df = conn.read(worksheet=INVENTORY_WS, usecols=[0, 5], ttl=0)
    df = df.dropna(how="all")  # clean empty rows
    st.subheader("Inventory Preview (A & F)")
    st.dataframe(df, use_container_width=True)
except Exception as e:
    st.error("Could not read Google Sheet.")
    st.exception(e)

with st.expander("🔍 Diagnostics", expanded=False):
    cfg = st.secrets.get("connections", {}).get("gsheets", {})
    st.write({"type": cfg.get("type"), "spreadsheet": cfg.get("spreadsheet")})
    st.write({"INVENTORY_WS": INVENTORY_WS})


# Read full worksheet
full_df = conn.read(worksheet=INVENTORY_WS, ttl=0).dropna(how="all")
st.subheader("Full Inventory")
st.dataframe(full_df, use_container_width=True)

# Example: write back (requires service account + sheet shared with it)
# conn.update(worksheet=INVENTORY_WS, data=full_df)
