# app.py
import os
import json
import time
import hmac
import base64
import hashlib
from io import BytesIO
from datetime import datetime
from typing import Dict, Optional, Tuple, List

import numpy as np
import pandas as pd
import streamlit as st
from streamlit_gsheets import GSheetsConnection


# =============================================================================
# BASIC APP SETTINGS
# =============================================================================
APP_TITLE = "Tracking Inventory Management System"
SUBTITLE  = "Advanced Construction"
DATE_FMT  = "%Y-%m-%d %H:%M:%S"   # display/storage format

st.set_page_config(page_title=APP_TITLE, layout="wide")


# =============================================================================
# OPTIONAL CUSTOM FONT (place OTF next to app.py to use)
# =============================================================================
def _inject_font_css(font_path: str, family: str = "FounderGroteskCondensed"):
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

_inject_font_css("FounderGroteskCondensed-Regular.otf")


# =============================================================================
# AUTH (persistent via ?auth= token in URL)
# =============================================================================
DEFAULT_ADMIN_PW = "admin@2025"
DEFAULT_STAFF_PW = "staff@2025"

ADMINS: Dict[str, str] = dict(getattr(st.secrets.get("auth", {}), "admins", {})) if hasattr(st, "secrets") else {}
STAFFS: Dict[str, str] = dict(getattr(st.secrets.get("auth", {}), "staff", {})) if hasattr(st, "secrets") else {}

if not ADMINS:
    ADMINS = {f"admin{i}": DEFAULT_ADMIN_PW for i in range(1, 6)}
if not STAFFS:
    STAFFS = {f"staff{i}": DEFAULT_STAFF_PW for i in range(1, 16)}

AUTH_SECRET = (
    st.secrets.get("auth", {}).get("secret") if hasattr(st, "secrets") else None
) or "change-me-now-very-long-random-string"

def authenticate(username: str, password: str) -> Optional[str]:
    if username in ADMINS and ADMINS[username] == password:
        return "admin"
    if username in STAFFS and STAFFS[username] == password:
        return "staff"
    return None

def _now() -> int:
    return int(time.time())

def _make_token(username: str, role: str, ttl_days: int = 30) -> str:
    payload = {"u": username, "r": role, "exp": _now() + ttl_days * 86400}
    raw = json.dumps(payload, separators=(",", ":")).encode()
    sig = hmac.new(AUTH_SECRET.encode(), raw, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(raw + sig).decode()

def _parse_token(token: str) -> Optional[Tuple[str, str, int]]:
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
    try:
        return st.query_params.get("auth")
    except Exception:
        params = st.experimental_get_query_params()
        v = params.get("auth", [None])
        return v[0] if isinstance(v, list) else v

def _set_query_auth(token: Optional[str]):
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
    """Keep users signed in on refresh until they click Logout."""
    if "auth_user" not in st.session_state:
        st.session_state.auth_user = None
        st.session_state.auth_role = None

    if not st.session_state.auth_user:
        token = _get_query_auth()
        parsed = _parse_token(token) if token else None
        if parsed:
            u, r, exp = parsed
            st.session_state.auth_user = u
            st.session_state.auth_role = r
            if exp - _now() < 3 * 86400:
                _set_query_auth(_make_token(u, r, ttl_days=30))
            return True

    if st.session_state.auth_user and st.session_state.auth_role:
        return True

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
            _set_query_auth(_make_token(st.session_state.auth_user, role, ttl_days=30))
            st.rerun()
        else:
            st.error("Invalid username or password.")
    st.stop()

def logout_button():
    if st.button("Logout"):
        for k in ("auth_user", "auth_role"):
            st.session_state.pop(k, None)
        _set_query_auth(None)
        st.rerun()


# =============================================================================
# GOOGLE SHEETS CONNECTION
# =============================================================================
SPREADSHEET = (
    st.secrets.get("connections", {}).get("gsheets", {}).get("spreadsheet")
    if hasattr(st, "secrets") else None
) or "https://docs.google.com/spreadsheets/d/1SHp6gOW4ltsyOT41rwo85e_LELrHkwSwKN33K6XNHFI/edit"

INVENTORY_WS   = str(st.secrets.get("inventory_tab", "0"))
TRANSFERLOG_WS = str(st.secrets.get("transferlog_tab", "405007082"))
# NEW: optional directory tab for auto contacts
DIRECTORY_WS   = str(st.secrets.get("directory_tab", "directory"))

conn = st.connection("gsheets", type=GSheetsConnection)

def _has_service_account() -> bool:
    try:
        svc = st.secrets["connections"]["gsheets"].get("service_account")
        return bool(svc)
    except Exception:
        return False

IS_READ_ONLY = not _has_service_account()


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
    return df[cols] + [c for c in df.columns if c not in cols]

def _to_datetime_no_warn(values: pd.Series) -> pd.Series:
    dt = pd.to_datetime(values, format=DATE_FMT, errors="coerce")
    mask = dt.isna() & values.astype(str).str.len().gt(0)
    if not mask.any():
        return dt
    try:
        dt2 = pd.to_datetime(values[mask], format="mixed", errors="coerce")
        dt.loc[mask] = dt2
        mask = dt.isna() & values.astype(str).str.len().gt(0)
    except Exception:
        pass
    if not mask.any():
        return dt
    parsed = []
    for v in values[mask].astype(str).tolist():
        try:
            parsed.append(pd.to_datetime(v, errors="coerce"))
        except Exception:
            parsed.append(pd.NaT)
    dt.loc[mask] = parsed
    return dt

def parse_dates_safe(series: pd.Series) -> pd.Series:
    dt = _to_datetime_no_warn(series)
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

def write_ws(worksheet: str, df: pd.DataFrame) -> Tuple[bool, Optional[str]]:
    try:
        conn.update(spreadsheet=SPREADSHEET, worksheet=worksheet, data=df)
        return True, None
    except Exception as e:
        return False, str(e)

def commit_writes(writes: List[Tuple[str, pd.DataFrame]], *, show_error: bool) -> bool:
    for ws, df in writes:
        ok, err = write_ws(ws, df)
        if not ok:
            if show_error:
                st.error(
                    "This app cannot write to the Google Sheet (read-only or missing "
                    "Service Account permissions).\n\n"
                    "➡️ To enable saving, add a Google **Service Account** in secrets and share "
                    "the spreadsheet with that account (Editor access).\n\n"
                    f"Details: {err}"
                )
            return False
    return True

# ---------- NEW: contact lookup ----------
CONTACT_EMAIL_COLS = ["Email Address", "Email", "E-mail"]
CONTACT_PHONE_COLS = ["Contact Number", "Phone", "Mobile", "Contact"]

def _norm(s: str) -> str:
    return " ".join((s or "").strip().lower().split())

def _first_existing_col(df: pd.DataFrame, candidates: List[str]) -> Optional[str]:
    for c in candidates:
        if c in df.columns:
            return c
    return None

def lookup_contact(new_owner: str, inv_df: pd.DataFrame) -> Tuple[str, str]:
    """Find email/phone for owner using directory sheet first, then inventory."""
    name = _norm(new_owner)
    email = ""
    phone = ""

    # 1) try directory
    try:
        directory = conn.read(spreadsheet=SPREADSHEET, worksheet=DIRECTORY_WS, ttl=300)
        if isinstance(directory, pd.DataFrame) and not directory.empty:
            if "Name" in directory.columns:
                dir_email_col = _first_existing_col(directory, CONTACT_EMAIL_COLS)
                dir_phone_col = _first_existing_col(directory, CONTACT_PHONE_COLS)
                if dir_email_col or dir_phone_col:
                    mask = directory["Name"].astype(str).str.lower().str.strip() == name
                    if mask.any():
                        row = directory[mask].iloc[0]
                        email = str(row.get(dir_email_col, "") or "")
                        phone = str(row.get(dir_phone_col, "") or "")
                        if email or phone:
                            return email, phone
    except Exception:
        pass

    # 2) fallback: reuse from inventory if same USER appears elsewhere with data
    try:
        user_col = "USER" if "USER" in inv_df.columns else None
        if user_col:
            # prefer most recent by date
            df2 = inv_df.copy()
            if "Date issued" in df2.columns:
                dt = pd.to_datetime(df2["Date issued"], errors="coerce")
                df2 = df2.assign(_ts=dt).sort_values("_ts", ascending=False, na_position="last")
            email_col = _first_existing_col(df2, ["Email Address", "Email"])
            phone_col = _first_existing_col(df2, ["Contact Number", "Phone", "Mobile"])
            if email_col or phone_col:
                mask = df2[user_col].astype(str).str.lower().str.strip() == name
                if mask.any():
                    row = df2[mask].iloc[0]
                    email = str(row.get(email_col, "") or "")
                    phone = str(row.get(phone_col, "") or "")
    except Exception:
        pass

    return email, phone


# =============================================================================
# HEADER (logo left, title mid, user+logout right)
# =============================================================================
def app_header(user: str, role: str):
    c_logo, c_title, c_user = st.columns([1.2, 6, 3], gap="small")

    with c_logo:
        logo = "company_logo.jpeg"
        if os.path.exists(logo):
            st.image(logo, use_container_width=True)

    with c_title:
        st.markdown(f"### {APP_TITLE}")
        st.caption(SUBTITLE)

    with c_user:
        st.markdown(
            f"""
            <div style="display:flex; align-items:center; justify-content:flex-end; gap:1rem;">
              <div>
                <div style="font-weight:600;">Welcome, {user}</div>
                <div>Role: <b>{role.capitalize()}</b></div>
              </div>
              <div>
            """,
            unsafe_allow_html=True,
        )
        logout_button()
        st.markdown("</div></div><hr style='margin-top:0.8rem;'>", unsafe_allow_html=True)


# =============================================================================
# DATA MODEL
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

# Hide table toolbars for STAFF (eye/download/fullscreen)
if not IS_ADMIN:
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

# Queues in session: pending transfer log rows + per-serial inventory overrides
if "pending_transfers" not in st.session_state:
    st.session_state.pending_transfers: List[dict] = []
if "pending_overrides" not in st.session_state:
    st.session_state.pending_overrides: Dict[str, Dict[str, str]] = {}

app_header(USER, ROLE)

# Tabs
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
                    if commit_writes([(INVENTORY_WS, inv)], show_error=True):
                        st.success("✅ Saved to Google Sheets.")

# ----------------------------- View Inventory
view_tab_index = 1 if IS_ADMIN else 0
with tabs[view_tab_index]:
    st.subheader("Current Inventory")
    inv = safe_read_ws(INVENTORY_WS, ALL_COLS, "inventory", ttl=0)

    # Overlay pending overrides so staff sees updated rows instantly
    for sn, changes in st.session_state.pending_overrides.items():
        idxs = inv.index[inv["Serial Number"].astype(str) == sn].tolist()
        for i in idxs:
            for k, v in changes.items():
                if k in inv.columns:
                    inv.loc[i, k] = v

    if not inv.empty and "Date issued" in inv.columns:
        inv["Date issued"] = parse_dates_safe(inv["Date issued"].astype(str))
        _ts = pd.to_datetime(inv["Date issued"], format=DATE_FMT, errors="coerce")
        inv = inv.assign(_ts=_ts).sort_values("_ts", ascending=False, na_position="last").drop(columns="_ts")
    st.dataframe(nice_display(inv), use_container_width=True, hide_index=True)

# ----------------------------- Transfer Device (STAFF + ADMIN)
transfer_tab_index = 2 if IS_ADMIN else 1
with tabs[transfer_tab_index]:
    st.subheader("Register Ownership Transfer")

    inv = safe_read_ws(INVENTORY_WS, ALL_COLS, "inventory")
    serials = sorted(inv["Serial Number"].astype(str).dropna().unique().tolist())
    pick = st.selectbox("Serial Number", ["— Select —"] + serials)
    chosen_serial = None if pick == "— Select —" else pick

    # NEW: only ask for the owner's name; email/phone will be auto-resolved
    new_owner = st.text_input("New Owner (required)")

    # Show selected device summary
    if chosen_serial:
        row = inv[inv["Serial Number"].astype(str) == chosen_serial]
        if not row.empty:
            r = row.iloc[0]
            st.caption(
                f"Device: {r.get('Device Type','')} • Brand: {r.get('Brand','')} • "
                f"Model: {r.get('Model','')} • CPU: {r.get('CPU','')}"
            )

    # Resolve email/phone automatically
    auto_email, auto_phone = ("", "")
    if new_owner.strip():
        auto_email, auto_phone = lookup_contact(new_owner.strip(), inv)
        st.caption(f"Auto-contact → Email: **{auto_email or '—'}** • Phone: **{auto_phone or '—'}**")

    # Staff/Admin can click Transfer; we write (or queue if read-only)
    do_transfer = st.button(
        "Transfer Now",
        type="primary",
        disabled=not (chosen_serial and new_owner.strip())
    )

    if do_transfer:
        idx_list = inv.index[inv["Serial Number"].astype(str) == chosen_serial].tolist()
        if not idx_list:
            st.error(f"Device with Serial Number {chosen_serial} not found!")
        else:
            idx = idx_list[0]
            prev_user = inv.loc[idx, "USER"]
            now = datetime.now().strftime(DATE_FMT)

            # 1) local update in memory (so UI shows it immediately)
            inv.loc[idx, "Previous User"]  = str(prev_user or "")
            inv.loc[idx, "USER"]           = new_owner.strip()
            inv.loc[idx, "TO"]             = new_owner.strip()
            if "Email Address" in inv.columns:
                inv.loc[idx, "Email Address"] = auto_email
            if "Contact Number" in inv.columns:
                inv.loc[idx, "Contact Number"] = auto_phone
            inv.loc[idx, "Date issued"]    = now
            inv.loc[idx, "Registered by"]  = USER

            # 2) update transfer log object
            log = safe_read_ws(TRANSFERLOG_WS, LOG_COLS, "transfer log")
            log_row = {
                "Device Type": inv.loc[idx, "Device Type"],
                "Serial Number": chosen_serial,
                "From owner": str(prev_user or ""),
                "To owner": new_owner.strip(),
                "Date issued": now,
                "Registered by": USER,
            }
            log = pd.concat([log, pd.DataFrame([log_row])], ignore_index=True)

            # 3) Try to write (admins see errors, staff won't)
            wrote = commit_writes([(INVENTORY_WS, inv), (TRANSFERLOG_WS, log)],
                                  show_error=IS_ADMIN)

            if wrote:
                # Clear any stale overrides/logs for this serial
                st.session_state.pending_overrides.pop(chosen_serial, None)
                st.session_state.pending_transfers = [
                    r for r in st.session_state.pending_transfers
                    if r.get("Serial Number") != chosen_serial or r.get("Date issued") != now
                ]
                st.success(f"✅ Transfer saved: {prev_user or '(blank)'} → {new_owner.strip()}")
            else:
                # Queue for later sync:
                st.session_state.pending_transfers.append(log_row)
                st.session_state.pending_overrides[chosen_serial] = {
                    "Previous User": str(prev_user or ""),
                    "USER": new_owner.strip(),
                    "TO": new_owner.strip(),
                    "Email Address": auto_email,
                    "Contact Number": auto_phone,
                    "Date issued": now,
                    "Registered by": USER,
                }
                st.success("✅ Transfer recorded and visible in the app. Admin will sync to Sheets later.")

    # Show pending queue:
    if st.session_state.pending_transfers or st.session_state.pending_overrides:
        with st.expander("🕒 Pending updates (not yet synced)"):
            if st.session_state.pending_transfers:
                st.markdown("**Queued Transfer Log Entries**")
                pend_df = pd.DataFrame(st.session_state.pending_transfers)
                st.dataframe(pend_df, use_container_width=True, hide_index=True)

            if st.session_state.pending_overrides:
                st.markdown("**Queued Inventory Row Overrides**")
                ov = []
                for sn, ch in st.session_state.pending_overrides.items():
                    row = {"Serial Number": sn}
                    row.update(ch)
                    ov.append(row)
                ov_df = pd.DataFrame(ov)
                st.dataframe(ov_df, use_container_width=True, hide_index=True)

            # Admin-only: try to sync all queued items
            if IS_ADMIN and st.button("Sync queued changes now"):
                inv2 = safe_read_ws(INVENTORY_WS, ALL_COLS, "inventory")
                log2 = safe_read_ws(TRANSFERLOG_WS, LOG_COLS, "transfer log")

                # Apply overrides to inventory
                for sn, changes in st.session_state.pending_overrides.items():
                    idxs = inv2.index[inv2["Serial Number"].astype(str) == sn].tolist()
                    for i in idxs:
                        for k, v in changes.items():
                            if k in inv2.columns:
                                inv2.loc[i, k] = v

                # Append queued log rows
                if st.session_state.pending_transfers:
                    log2 = pd.concat([log2, pd.DataFrame(st.session_state.pending_transfers)], ignore_index=True)

                if commit_writes([(INVENTORY_WS, inv2), (TRANSFERLOG_WS, log2)], show_error=True):
                    st.success("✅ Synced all queued changes.")
                    st.session_state.pending_transfers.clear()
                    st.session_state.pending_overrides.clear()

# ----------------------------- Transfer Log
log_tab_index = 3 if IS_ADMIN else 2
with tabs[log_tab_index]:
    st.subheader("Transfer Log")
    log = safe_read_ws(TRANSFERLOG_WS, LOG_COLS, "transfer log", ttl=0)

    # Show queued (unsynced) log rows too, so staff sees them in history
    if st.session_state.pending_transfers:
        log = pd.concat([log, pd.DataFrame(st.session_state.pending_transfers)], ignore_index=True)

    if not log.empty and "Date issued" in log.columns:
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
