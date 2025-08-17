# app.py

import os
import json
import time
import hmac
import base64
import hashlib
from io import BytesIO
from datetime import datetime
from typing import Dict, Optional, Tuple

import numpy as np
import pandas as pd
import streamlit as st
from streamlit_gsheets import GSheetsConnection


# =============================================================================
# BASIC APP SETTINGS
# =============================================================================
APP_TITLE = "Tracking Inventory Management System"
SUBTITLE  = "AdvancedConstruction"
DATE_FMT  = "%Y-%m-%d %H:%M:%S"  # keep your sheet dates like '2025-08-10 06:52:09'

st.set_page_config(page_title=APP_TITLE, layout="wide")

# Optional: minimal theming tweaks for a cleaner look
st.markdown(
    """
    <style>
      /* tighten top padding a little */
      section.main > div { padding-top: 1.2rem; }
    </style>
    """,
    unsafe_allow_html=True
)


# =============================================================================
# AUTH: USERS + PERSISTENT LOGIN VIA SIGNED TOKEN IN URL
# =============================================================================
# .streamlit/secrets.toml example (change the secret!):
# [auth]
# secret = "change-me-to-a-long-random-string"
#
# [auth.admins]
# admin1 = "admin@2025"
# admin2 = "admin@2025"
# admin3 = "admin@2025"
# admin4 = "admin@2025"
# admin5 = "admin@2025"
#
# [auth.staff]
# staff1 = "staff@2025"
# ... up to staff15

DEFAULT_ADMIN_PW = "admin@2025"
DEFAULT_STAFF_PW = "staff@2025"

ADMINS: Dict[str, str] = dict(getattr(st.secrets.get("auth", {}), "admins", {})) if hasattr(st, "secrets") else {}
STAFFS: Dict[str, str] = dict(getattr(st.secrets.get("auth", {}), "staff", {})) if hasattr(st, "secrets") else {}

if not ADMINS:
    ADMINS = {f"admin{i}": DEFAULT_ADMIN_PW for i in range(1, 6)}
if not STAFFS:
    STAFFS = {f"staff{i}": DEFAULT_STAFF_PW for i in range(1, 16)}

AUTH_SECRET = (
    st.secrets.get("auth", {}).get("secret")
    if hasattr(st, "secrets") else None
) or "dev-only-please-change-me-to-a-long-random-string"


def authenticate(username: str, password: str) -> Optional[str]:
    if username in ADMINS and ADMINS[username] == password:
        return "admin"
    if username in STAFFS and STAFFS[username] == password:
        return "staff"
    return None


def _now() -> int:
    return int(time.time())


def _make_token(username: str, role: str, ttl_days: int = 30) -> str:
    """Create a signed, url-safe token with expiry (default 30 days)."""
    payload = {"u": username, "r": role, "exp": _now() + ttl_days * 86400}
    raw = json.dumps(payload, separators=(",", ":")).encode()
    sig = hmac.new(AUTH_SECRET.encode(), raw, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(raw + sig).decode()


def _parse_token(token: str) -> Optional[Tuple[str, str, int]]:
    """Return (username, role, exp_ts) if valid; else None."""
    try:
        data = base64.urlsafe_b64decode(token.encode())
        raw, sig = data[:-32], data[-32:]
        good_sig = hmac.new(AUTH_SECRET.encode(), raw, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, good_sig):
            return None
        payload = json.loads(raw.decode())
        if payload.get("exp", 0) < _now():
            return None
        return payload.get("u"), payload.get("r"), payload.get("exp")
    except Exception:
        return None


def _get_query_auth() -> Optional[str]:
    # Streamlit >= 1.30
    try:
        return st.query_params.get("auth")
    except Exception:
        params = st.experimental_get_query_params()
        v = params.get("auth", [None])
        return v[0] if isinstance(v, list) else v


def _set_query_auth(token: Optional[str]):
    """Set or clear the ?auth=... query parameter."""
    try:
        if token is None:
            if "auth" in st.query_params:
                del st.query_params["auth"]
        else:
            st.query_params["auth"] = token
    except Exception:
        if token is None:
            st.experimental_set_query_params()
        else:
            st.experimental_set_query_params(auth=token)


def ensure_auth():
    """Keep users signed in across refreshes until they click Logout."""
    if "auth_user" not in st.session_state:
        st.session_state.auth_user = None
        st.session_state.auth_role = None

    # Try restore from URL token
    if not st.session_state.auth_user:
        token = _get_query_auth()
        parsed = _parse_token(token) if token else None
        if parsed:
            u, r, exp = parsed
            st.session_state.auth_user = u
            st.session_state.auth_role = r
            # Auto-renew if expiring soon
            if exp - _now() < 3 * 86400:
                _set_query_auth(_make_token(u, r, ttl_days=30))
            return True

    # Already in this runtime session?
    if st.session_state.auth_user and st.session_state.auth_role:
        return True

    # ---------- Login UI ----------
    st.markdown(f"## {APP_TITLE}")
    st.caption(SUBTITLE)
    st.info("Please sign in to continue.")

    with st.form("login_form", clear_on_submit=False):
        u = st.text_input("Username", key="login_user")
        p = st.text_input("Password", type="password", key="login_pw")
        submitted = st.form_submit_button("Login", type="primary")

    if submitted:
        role = authenticate(u.strip(), p)
        if role:
            st.session_state.auth_user = u.strip()
            st.session_state.auth_role = role
            # Always persist login
            _set_query_auth(_make_token(st.session_state.auth_user, role, ttl_days=30))
            st.rerun()
        else:
            st.error("Invalid username or password.")
    st.stop()


def logout_button():
    right = st.columns([1, 1, 8])[1]
    with right:
        if st.button("Logout"):
            for k in ("auth_user", "auth_role"):
                st.session_state.pop(k, None)
            _set_query_auth(None)
            st.rerun()


# =============================================================================
# GOOGLE SHEETS CONNECTION
# =============================================================================
# Put the spreadsheet URL in secrets (recommended):
# [connections.gsheets]
# spreadsheet = "https://docs.google.com/spreadsheets/d/XXXXXXXXXXXX/edit"
SPREADSHEET = (
    st.secrets.get("connections", {}).get("gsheets", {}).get("spreadsheet")
    if hasattr(st, "secrets") else None
) or "https://docs.google.com/spreadsheets/d/1SHp6gOW4ltsyOT41rwo85e_LELrHkwSwKN33K6XNHFI/edit"

# Worksheet identifiers (tab names or numeric GIDs as strings)
INVENTORY_WS   = str(st.secrets.get("inventory_tab", "0"))          # first sheet gid "0"
TRANSFERLOG_WS = str(st.secrets.get("transferlog_tab", "405007082"))

conn = st.connection("gsheets", type=GSheetsConnection)


# =============================================================================
# HELPERS
# =============================================================================
def _ensure_cols(df: pd.DataFrame, cols: list[str]) -> pd.DataFrame:
    if df is None or df.empty:
        return pd.DataFrame(columns=cols)
    df = df.fillna("")
    for c in cols:
        if c not in df.columns:
            df[c] = ""
    return df[cols + [c for c in df.columns if c not in cols]]


def parse_dates_safe(series: pd.Series) -> pd.Series:
    """Fast try with DATE_FMT, then safe fallback; return string formatted."""
    # Fast path
    dt = pd.to_datetime(series, format=DATE_FMT, errors="coerce")
    # Fallback for anything that failed
    needs = dt.isna() & series.astype(str).str.len().gt(0)
    if needs.any():
        dt2 = pd.to_datetime(series[needs], errors="coerce")
        dt.loc[needs] = dt2
    # Final string form
    out = dt.dt.strftime(DATE_FMT)
    return out.replace("NaT", "")


def nice_display(df: pd.DataFrame) -> pd.DataFrame:
    if df is None or df.empty:
        return df
    out = df.copy()
    for col in out.columns:
        try:
            if np.issubdtype(out[col].dtype, np.datetime64) or "date" in col.lower():
                out[col] = parse_dates_safe(out[col].astype(str))
        except Exception:
            pass
    out = out.replace({np.nan: ""})
    for c in out.columns:
        out[c] = out[c].astype(str).replace({"NaT": "", "nan": "", "NaN": ""})
    return out


def read_ws(worksheet: str, cols: list[str], ttl: int = 0) -> pd.DataFrame:
    df = conn.read(spreadsheet=SPREADSHEET, worksheet=worksheet, ttl=ttl)
    return _ensure_cols(df, cols)


def safe_read_ws(worksheet: str, cols: list[str], label: str, ttl: int = 0) -> pd.DataFrame:
    try:
        return read_ws(worksheet, cols, ttl=ttl)
    except Exception as e:
        st.warning(
            f"Couldn’t read **{label}** from Google Sheets. "
            f"Check sharing, tab name (or gid), or publishing. Error: {type(e).__name__}"
        )
        return _ensure_cols(None, cols)


def write_ws(worksheet: str, df: pd.DataFrame):
    conn.update(spreadsheet=SPREADSHEET, worksheet=worksheet, data=df)


def app_header(user: str, role: str):
    """Header with logo + title on left, user info + logout on right."""
    c_logo, c_main, c_user = st.columns([1, 5, 3], gap="small")

    with c_logo:
        logo_path = "company_logo.jpeg"
        if os.path.exists(logo_path):
            st.image(logo_path, use_column_width=True)
        else:
            st.write("")  # placeholder

    with c_main:
        st.markdown(f"### {APP_TITLE}")
        st.caption(SUBTITLE)

    with c_user:
        st.markdown(f"#### Welcome, **{user}**  \nRole: **{role.capitalize()}**")
        logout_button()

    st.markdown("---")


# =============================================================================
# DATA MODEL (columns)
# =============================================================================
ALL_COLS = [
    "Serial Number","Device Type","Brand","Model","CPU",
    "Hard Drive 1","Hard Drive 2","Memory","GPU","Screen Size",
    "USER","Previous User","TO","Department","Email Address",
    "Contact Number","Location","Office","Notes","Date issued","Registered by"
]
LOG_COLS = ["Device Type","Serial Number","From owner","To owner","Date issued","Registered by"]


# =============================================================================
# MAIN
# =============================================================================
ensure_auth()
USER = st.session_state.auth_user
ROLE = st.session_state.auth_role
IS_ADMIN = ROLE == "admin"

# Hide table tools for STAFF (eye/download/fullscreen)
if not IS_ADMIN:
    st.markdown(
        """
        <style>
          div[data-testid="stDataFrame"] div[data-testid="stElementToolbar"] { display:none !important; }
          div[data-testid="stDataEditor"] div[data-testid="stElementToolbar"] { display:none !important; }
          div[data-testid="stElementToolbar"] { display:none !important; }
        </style>
        """,
        unsafe_allow_html=True
    )

# Header row
app_header(USER, ROLE)

# Tabs: Admin (5), Staff (3)
if IS_ADMIN:
    tabs = st.tabs(["📝 Register", "📦 View Inventory", "🔄 Transfer Device", "📜 Transfer Log", "⬇ Export"])
else:
    tabs = st.tabs(["📦 View Inventory", "🔄 Transfer Device", "📜 Transfer Log"])

# ----------------------------- Admin: Register
if IS_ADMIN:
    with tabs[0]:
        st.subheader("Register New Inventory Item")
        with st.form("reg_form", clear_on_submit=True):
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
            submitted = st.form_submit_button("Save Item", type="primary")

        if submitted:
            if not serial.strip() or not device.strip():
                st.error("Serial Number and Device Type are required.")
            else:
                inv = safe_read_ws(INVENTORY_WS, ALL_COLS, "inventory")
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
                        "Registered by": USER,
                    }
                    inv = pd.concat([inv, pd.DataFrame([row])], ignore_index=True)
                    write_ws(INVENTORY_WS, inv)
                    st.success("✅ Saved to Google Sheets.")

# ----------------------------- View Inventory
view_tab_index = 1 if IS_ADMIN else 0
with tabs[view_tab_index]:
    st.subheader("Current Inventory")
    inv = safe_read_ws(INVENTORY_WS, ALL_COLS, "inventory", ttl=0)
    if not inv.empty and "Date issued" in inv.columns:
        inv["Date issued"] = parse_dates_safe(inv["Date issued"].astype(str))
        # Sort by parsed date (descending)
        _ts = pd.to_datetime(inv["Date issued"], format=DATE_FMT, errors="coerce")
        inv = inv.assign(_ts=_ts).sort_values("_ts", ascending=False, na_position="last").drop(columns="_ts")
    st.dataframe(nice_display(inv), use_container_width=True, hide_index=True)

# ----------------------------- Transfer Device
transfer_tab_index = 2 if IS_ADMIN else 1
with tabs[transfer_tab_index]:
    st.subheader("Register Ownership Transfer")

    inv = safe_read_ws(INVENTORY_WS, ALL_COLS, "inventory")
    serials = sorted(inv["Serial Number"].astype(str).dropna().unique().tolist())
    pick = st.selectbox("Serial Number", ["— Select —"] + serials)
    chosen_serial = None if pick == "— Select —" else pick

    if chosen_serial:
        row = inv[inv["Serial Number"].astype(str) == chosen_serial]
        if not row.empty:
            r = row.iloc[0]
            st.caption(
                f"Device: {r.get('Device Type','')} • Brand: {r.get('Brand','')} • "
                f"Model: {r.get('Model','')} • CPU: {r.get('CPU','')}"
            )
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

            # Update inventory row
            inv.loc[idx, "Previous User"] = str(prev_user or "")
            inv.loc[idx, "USER"] = new_owner.strip()
            inv.loc[idx, "TO"] = new_owner.strip()
            inv.loc[idx, "Date issued"] = datetime.now().strftime(DATE_FMT)
            inv.loc[idx, "Registered by"] = USER

            # Append to transfer log
            log = safe_read_ws(TRANSFERLOG_WS, LOG_COLS, "transfer log")
            log_row = {
                "Device Type": inv.loc[idx, "Device Type"],
                "Serial Number": chosen_serial,
                "From owner": str(prev_user or ""),
                "To owner": new_owner.strip(),
                "Date issued": datetime.now().strftime(DATE_FMT),
                "Registered by": USER,
            }
            log = pd.concat([log, pd.DataFrame([log_row])], ignore_index=True)

            # Save
            write_ws(INVENTORY_WS, inv)
            write_ws(TRANSFERLOG_WS, log)
            st.success(f"✅ Transfer saved: {prev_user or '(blank)'} → {new_owner.strip()}")

# ----------------------------- Transfer Log
log_tab_index = 3 if IS_ADMIN else 2
with tabs[log_tab_index]:
    st.subheader("Transfer Log")
    log = safe_read_ws(TRANSFERLOG_WS, LOG_COLS, "transfer log", ttl=0)
    if not log.empty and "Date issued" in log.columns:
        # Normalize and sort by date desc
        log["Date issued"] = parse_dates_safe(log["Date issued"].astype(str))
        _ts = pd.to_datetime(log["Date issued"], format=DATE_FMT, errors="coerce")
        log = log.assign(_ts=_ts).sort_values("_ts", ascending=False, na_position="last").drop(columns="_ts")
    st.dataframe(nice_display(log), use_container_width=True, hide_index=True)

# ----------------------------- Admin: Export
if IS_ADMIN:
    with tabs[4]:
        st.subheader("Download Exports")

        inv = safe_read_ws(INVENTORY_WS, ALL_COLS, "inventory")
        inv_x = BytesIO()
        with pd.ExcelWriter(inv_x, engine="openpyxl") as w:
            inv.to_excel(w, index=False)
        inv_x.seek(0)
        st.download_button(
            "⬇ Download Inventory", inv_x.getvalue(),
            file_name="inventory.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )

        log = safe_read_ws(TRANSFERLOG_WS, LOG_COLS, "transfer log")
        log_x = BytesIO()
        with pd.ExcelWriter(log_x, engine="openpyxl") as w:
            log.to_excel(w, index=False)
        log_x.seek(0)
        st.download_button(
            "⬇ Download Transfer Log", log_x.getvalue(),
            file_name="transfer_log.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
