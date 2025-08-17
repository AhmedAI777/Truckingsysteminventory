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

INVENTORY_WS   = "truckinventory"
TRANSFERLOG_WS = "transferlog"

# -----------------------------
# PAGE / HEADER
# -----------------------------
st.set_page_config(page_title=APP_TITLE, layout="wide")
st.markdown(f"## {APP_TITLE}\n**{SUBTITLE}**")

# -----------------------------
# Connect to Google Sheets
# -----------------------------
conn = st.connection("gsheets", type=GSheetsConnection)

# -----------------------------
# Helpers
# -----------------------------
def _ensure_cols(df: pd.DataFrame, cols: list[str]) -> pd.DataFrame:
    if df is None or df.empty:
        return pd.DataFrame(columns=cols)
    df = df.fillna("")
    for c in cols:
        if c not in df.columns:
            df[c] = ""
    return df[cols + [c for c in df.columns if c not in cols]]

def load_ws(worksheet: str, cols: list[str]) -> pd.DataFrame:
    df = conn.read(worksheet=worksheet, ttl=0)
    return _ensure_cols(df, cols)

def save_ws(worksheet: str, df: pd.DataFrame) -> None:
    conn.update(worksheet=worksheet, data=df)

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

# -----------------------------
# Columns & Tabs
# -----------------------------
ALL_COLS = ["Serial Number","Device Type","Brand","Model","CPU",
            "Hard Drive 1","Hard Drive 2","Memory","GPU","Screen Size",
            "USER","Previous User","TO","Department","Email Address",
            "Contact Number","Location","Office","Notes","Date issued","Registered by"]

tabs = st.tabs(["📝 Register", "📦 View Inventory", "🔄 Transfer Device", "📜 Transfer Log", "⬇ Export"])
