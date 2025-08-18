# app.py
import os, json, time, hmac, base64, hashlib
from io import BytesIO
from datetime import datetime
from typing import Dict, Optional, Tuple, List

import numpy as np
import pandas as pd
import streamlit as st
from streamlit_gsheets import GSheetsConnection

# --------------------- APP SETTINGS ---------------------
APP_TITLE = "Tracking Inventory Management System"
SUBTITLE  = "Advanced Construction"
DATE_FMT  = "%Y-%m-%d %H:%M:%S"
st.set_page_config(page_title=APP_TITLE, layout="wide")

# --------------------- AUTH (keeps session across refresh) ---------------------
DEFAULT_ADMIN_PW = "admin@2025"
DEFAULT_STAFF_PW = "staff@2025"

ADMINS: Dict[str, str] = dict(getattr(st.secrets.get("auth", {}), "admins", {})) if hasattr(st, "secrets") else {}
STAFFS: Dict[str, str] = dict(getattr(st.secrets.get("auth", {}), "staff", {})) if hasattr(st, "secrets") else {}
if not ADMINS: ADMINS = {f"admin{i}": DEFAULT_ADMIN_PW for i in range(1, 6)}
if not STAFFS: STAFFS = {f"staff{i}": DEFAULT_STAFF_PW for i in range(1, 16)}

AUTH_SECRET = (st.secrets.get("auth", {}).get("secret") if hasattr(st, "secrets") else None) or "please-change-me!"

def _now() -> int: return int(time.time())
def _make_token(username: str, role: str, ttl_days: int = 30) -> str:
    payload = {"u": username, "r": role, "exp": _now() + ttl_days * 86400}
    raw = json.dumps(payload, separators=(",", ":")).encode()
    sig = hmac.new(AUTH_SECRET.encode(), raw, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(raw + sig).decode()

def _parse_token(token: str) -> Optional[Tuple[str, str, int]]:
    try:
        data = base64.urlsafe_b64decode(token.encode())
        raw, sig = data[:-32], data[-32:]
        good = hmac.new(AUTH_SECRET.encode(), raw, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, good): return None
        payload = json.loads(raw.decode())
        if payload.get("exp", 0) < _now(): return None
        return payload.get("u"), payload.get("r"), payload.get("exp")
    except Exception:
        return None

def _get_query_auth() -> Optional[str]:
    try:
        return st.query_params.get("auth")
    except Exception:
        qp = st.experimental_get_query_params()
        v = qp.get("auth", [None]); return v[0] if isinstance(v, list) else v

def _set_query_auth(token: Optional[str]):
    try:
        if token is None:
            if "auth" in st.query_params: del st.query_params["auth"]
        else:
            st.query_params["auth"] = token
    except Exception:
        if token is None: st.experimental_set_query_params()
        else: st.experimental_set_query_params(auth=token)

def authenticate(u: str, p: str) -> Optional[str]:
    if u in ADMINS and ADMINS[u] == p: return "admin"
    if u in STAFFS and STAFFS[u] == p: return "staff"
    return None

def ensure_auth():
    if "auth_user" not in st.session_state: st.session_state.auth_user = None; st.session_state.auth_role = None
    if not st.session_state.auth_user:
        t = _get_query_auth(); parsed = _parse_token(t) if t else None
        if parsed:
            u, r, exp = parsed
            st.session_state.auth_user, st.session_state.auth_role = u, r
            if exp - _now() < 3 * 86400: _set_query_auth(_make_token(u, r))
            return True
    if st.session_state.auth_user: return True

    st.markdown(f"## {APP_TITLE}"); st.caption(SUBTITLE); st.info("Please sign in to continue.")
    with st.form("login_form", clear_on_submit=False):
        u = st.text_input("Username"); p = st.text_input("Password", type="password")
        go = st.form_submit_button("Login", type="primary")
    if go:
        role = authenticate(u.strip(), p)
        if role:
            st.session_state.auth_user = u.strip(); st.session_state.auth_role = role
            _set_query_auth(_make_token(st.session_state.auth_user, role))
            st.rerun()
        else:
            st.error("Invalid username or password.")
    st.stop()

def logout_button():
    if st.button("Logout"):
        for k in ("auth_user", "auth_role"): st.session_state.pop(k, None)
        _set_query_auth(None); st.rerun()

# --------------------- GOOGLE SHEETS CONNECTION ---------------------
# 👉 IMPORTANT: always pass spreadsheet=SPREADSHEET_URL in EVERY read/update call.
# Prefer taking it from secrets, otherwise a hard-coded fallback is used.
SPREADSHEET_URL = (
    st.secrets.get("connections", {}).get("gsheets", {}).get("spreadsheet")
    if hasattr(st, "secrets") else None
) or "https://docs.google.com/spreadsheets/d/1Gc3Wi1vpTP4g5rnWuaRJDZWycZHvKO7F2xCv1ZGo0oU/edit"

# Use names or gids (as strings) – override in secrets if needed.
INVENTORY_WS   = str(st.secrets.get("inventory_tab",   "truckinventory"))
TRANSFERLOG_WS = str(st.secrets.get("transferlog_tab", "transfer_log"))

conn = st.connection("gsheets", type=GSheetsConnection)

def _has_service_account() -> bool:
    try: return bool(st.secrets["connections"]["gsheets"].get("service_account"))
    except Exception: return False

IS_READ_ONLY = not _has_service_account()

def _ws_arg(v: str):
    # Accept gid like "405007082" or tab name like "truckinventory"
    return int(v) if v.isdigit() else v

# --------------------- DATA HELPERS ---------------------
ALL_COLS = [
    "Serial Number","Device Type","Brand","Model","CPU",
    "Hard Drive 1","Hard Drive 2","Memory","GPU","Screen Size",
    "USER","Previous User","TO","Department","Email Address",
    "Contact Number","Location","Office","Notes","Date issued","Registered by",
]
LOG_COLS = ["Device Type","Serial Number","From owner","To owner","Date issued","Registered by"]

def _ensure_cols(df: pd.DataFrame, cols: list[str]) -> pd.DataFrame:
    if df is None or df.empty: return pd.DataFrame(columns=cols)
    df = df.fillna("")
    for c in cols:
        if c not in df.columns: df[c] = ""
    return df[cols + [c for c in df.columns if c not in cols]]

def parse_dates_safe(series: pd.Series) -> pd.Series:
    dt = pd.to_datetime(series, errors="coerce", format=DATE_FMT)
    out = dt.dt.strftime(DATE_FMT); return out.replace("NaT", "")

def nice_display(df: pd.DataFrame) -> pd.DataFrame:
    if df is None or df.empty: return df
    out = df.copy()
    for col in out.columns:
        try:
            if np.issubdtype(out[col].dtype, np.datetime64) or "date" in col.lower():
                out[col] = parse_dates_safe(out[col].astype(str))
        except Exception: pass
    out = out.replace({np.nan: ""})
    for c in out.columns: out[c] = out[c].astype(str).replace({"NaT":"","nan":"","NaN":""})
    return out

def read_ws(ws: str, cols: list[str], ttl: int = 0) -> pd.DataFrame:
    df = conn.read(spreadsheet=SPREADSHEET_URL, worksheet=_ws_arg(ws), ttl=ttl)
    return _ensure_cols(df, cols)

def safe_read_ws(ws: str, cols: list[str], label: str, ttl: int = 0) -> pd.DataFrame:
    try: return read_ws(ws, cols, ttl)
    except Exception as e:
        st.warning(f"Couldn’t read **{label}** from Google Sheets. Error: {type(e).__name__}")
        return _ensure_cols(None, cols)

def write_ws(ws: str, df: pd.DataFrame) -> Tuple[bool, Optional[str]]:
    try:
        conn.update(spreadsheet=SPREADSHEET_URL, worksheet=_ws_arg(ws), data=df)
        return True, None
    except Exception as e:
        return False, str(e)

def commit_writes(writes: List[Tuple[str, pd.DataFrame]], *, show_error: bool) -> bool:
    for ws, df in writes:
        ok, err = write_ws(ws, df)
        if not ok:
            if show_error:
                st.error(
                    "Can't write to Google Sheet (public or missing Service Account permissions).\n"
                    "Add a **service_account** in secrets and share the Sheet with that account (Editor)."
                    f"\n\nDetails: {err}"
                )
            return False
    return True

# --------------------- HEADER ---------------------
def app_header(user: str, role: str):
    c_logo, c_title, c_user = st.columns([1.2, 6, 3], gap="small")
    with c_logo:
        if os.path.exists("company_logo.jpeg"): st.image("company_logo.jpeg", use_container_width=True)
    with c_title:
        st.markdown(f"### {APP_TITLE}"); st.caption(SUBTITLE)
    with c_user:
        st.markdown(
            f"<div style='display:flex;justify-content:flex-end;gap:1rem;'>"
            f"<div><div style='font-weight:600;'>Welcome, {user}</div><div>Role: <b>{role.capitalize()}</b></div></div>",
            unsafe_allow_html=True,
        )
        logout_button()
        st.markdown("</div><hr style='margin-top:.8rem;'>", unsafe_allow_html=True)

# --------------------- MAIN ---------------------
ensure_auth()
USER = st.session_state.auth_user
ROLE = st.session_state.auth_role
IS_ADMIN = ROLE == "admin"

# Hide toolbar for staff
if not IS_ADMIN:
    st.markdown("""
    <style>
      div[data-testid="stDataFrame"] div[data-testid="stElementToolbar"]{display:none !important;}
      div[data-testid="stDataEditor"]  div[data-testid="stElementToolbar"]{display:none !important;}
    </style>""", unsafe_allow_html=True)

# Local queues so staff can "transfer" even if sheet is read-only
if "pending_transfers" not in st.session_state: st.session_state.pending_transfers: List[dict] = []
if "pending_overrides" not in st.session_state: st.session_state.pending_overrides: Dict[str, Dict[str, str]] = {}

app_header(USER, ROLE)

# Tabs
tabs = (
    st.tabs(["📝 Register","📦 View Inventory","🔄 Transfer Device","📜 Transfer Log","⬇ Export"])
    if IS_ADMIN else
    st.tabs(["📦 View Inventory","🔄 Transfer Device","📜 Transfer Log"])
)

# --------------- Admin: Register
if IS_ADMIN:
    with tabs[0]:
        st.subheader("Register New Inventory Item")
        with st.form("reg_form", clear_on_submit=True):
            c1, c2 = st.columns(2)
            with c1:
                serial = st.text_input("Serial Number *"); device = st.text_input("Device Type *")
                brand  = st.text_input("Brand"); model = st.text_input("Model"); cpu = st.text_input("CPU")
            with c2:
                hdd1 = st.text_input("Hard Drive 1"); hdd2 = st.text_input("Hard Drive 2")
                mem  = st.text_input("Memory"); gpu = st.text_input("GPU"); screen = st.text_input("Screen Size")
            go = st.form_submit_button("Save Item", type="primary")
        if go:
            if not serial.strip() or not device.strip():
                st.error("Serial Number and Device Type are required.")
            else:
                inv = safe_read_ws(INVENTORY_WS, ALL_COLS, "inventory")
                if serial.strip() in inv["Serial Number"].astype(str).values:
                    st.error(f"Serial Number '{serial}' already exists.")
                else:
                    row = {
                        "Serial Number": serial.strip(), "Device Type": device.strip(),
                        "Brand": brand.strip(), "Model": model.strip(), "CPU": cpu.strip(),
                        "Hard Drive 1": hdd1.strip(), "Hard Drive 2": hdd2.strip(),
                        "Memory": mem.strip(), "GPU": gpu.strip(), "Screen Size": screen.strip(),
                        "USER": "", "Previous User": "", "TO": "", "Department": "",
                        "Email Address": "", "Contact Number": "", "Location": "",
                        "Office": "", "Notes": "", "Date issued": datetime.now().strftime(DATE_FMT),
                        "Registered by": USER,
                    }
                    inv = pd.concat([inv, pd.DataFrame([row])], ignore_index=True)
                    if commit_writes([(INVENTORY_WS, inv)], show_error=True): st.success("✅ Saved to Google Sheets.")

# --------------- View Inventory
view_idx = 1 if IS_ADMIN else 0
with tabs[view_idx]:
    st.subheader("Current Inventory")
    inv = safe_read_ws(INVENTORY_WS, ALL_COLS, "inventory", ttl=0)

    # Overlay queued (unsynced) local overrides
    for sn, ch in st.session_state.pending_overrides.items():
        idxs = inv.index[inv["Serial Number"].astype(str) == sn].tolist()
        for i in idxs:
            for k, v in ch.items():
                if k in inv.columns: inv.loc[i, k] = v

    if not inv.empty and "Date issued" in inv.columns:
        inv["Date issued"] = parse_dates_safe(inv["Date issued"].astype(str))
        _ts = pd.to_datetime(inv["Date issued"], format=DATE_FMT, errors="coerce")
        inv = inv.assign(_ts=_ts).sort_values("_ts", ascending=False, na_position="last").drop(columns="_ts")

    st.dataframe(nice_display(inv), use_container_width=True, hide_index=True)

# --------------- Transfer Device (staff + admin)
xfer_idx = 2 if IS_ADMIN else 1
with tabs[xfer_idx]:
    st.subheader("Register Ownership Transfer")
    inv = safe_read_ws(INVENTORY_WS, ALL_COLS, "inventory")
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

    go = st.button("Transfer Now", type="primary", disabled=not (chosen_serial and new_owner.strip()))
    if go:
        idxs = inv.index[inv["Serial Number"].astype(str) == chosen_serial].tolist()
        if not idxs:
            st.error(f"Device with Serial Number {chosen_serial} not found!")
        else:
            i = idxs[0]
            prev = inv.loc[i, "USER"]
            now  = datetime.now().strftime(DATE_FMT)

            # Update inventory row in memory
            inv.loc[i, "Previous User"] = str(prev or "")
            inv.loc[i, "USER"] = new_owner.strip()
            inv.loc[i, "TO"]   = new_owner.strip()
            inv.loc[i, "Date issued"]   = now
            inv.loc[i, "Registered by"] = USER

            # Append transfer log
            log = safe_read_ws(TRANSFERLOG_WS, LOG_COLS, "transfer log")
            log_row = {
                "Device Type": inv.loc[i, "Device Type"],
                "Serial Number": chosen_serial,
                "From owner": str(prev or ""),
                "To owner": new_owner.strip(),
                "Date issued": now, "Registered by": USER,
            }
            log = pd.concat([log, pd.DataFrame([log_row])], ignore_index=True)

            wrote = commit_writes([(INVENTORY_WS, inv), (TRANSFERLOG_WS, log)], show_error=IS_ADMIN)
            if wrote:
                st.session_state.pending_overrides.pop(chosen_serial, None)
                st.session_state.pending_transfers = [
                    r for r in st.session_state.pending_transfers
                    if r.get("Serial Number") != chosen_serial or r.get("Date issued") != now
                ]
                st.success(f"✅ Transfer saved: {prev or '(blank)'} → {new_owner.strip()}")
            else:
                # Queue locally so UI still shows the change
                st.session_state.pending_transfers.append(log_row)
                st.session_state.pending_overrides[chosen_serial] = {
                    "Previous User": str(prev or ""), "USER": new_owner.strip(), "TO": new_owner.strip(),
                    "Date issued": now, "Registered by": USER,
                }
                st.success("✅ Transfer recorded locally. Admin can sync when write access is enabled.")

    # Optional: show queue & admin sync button
    if st.session_state.pending_transfers or st.session_state.pending_overrides:
        with st.expander("🕒 Pending updates (not yet synced)"):
            if st.session_state.pending_transfers:
                st.markdown("**Queued Transfer Log Entries**")
                st.dataframe(pd.DataFrame(st.session_state.pending_transfers), use_container_width=True, hide_index=True)
            if st.session_state.pending_overrides:
                st.markdown("**Queued Inventory Row Overrides**")
                ov = [{"Serial Number": sn, **ch} for sn, ch in st.session_state.pending_overrides.items()]
                st.dataframe(pd.DataFrame(ov), use_container_width=True, hide_index=True)
            if IS_ADMIN and st.button("Sync queued changes now"):
                inv2 = safe_read_ws(INVENTORY_WS, ALL_COLS, "inventory")
                log2 = safe_read_ws(TRANSFERLOG_WS, LOG_COLS, "transfer log")
                for sn, ch in st.session_state.pending_overrides.items():
                    idxs = inv2.index[inv2["Serial Number"].astype(str) == sn].tolist()
                    for i in idxs:
                        for k, v in ch.items():
                            if k in inv2.columns: inv2.loc[i, k] = v
                if st.session_state.pending_transfers:
                    log2 = pd.concat([log2, pd.DataFrame(st.session_state.pending_transfers)], ignore_index=True)
                if commit_writes([(INVENTORY_WS, inv2), (TRANSFERLOG_WS, log2)], show_error=True):
                    st.success("✅ Synced all queued changes."); st.session_state.pending_transfers.clear(); st.session_state.pending_overrides.clear()

# --------------- Transfer Log
log_idx = 3 if IS_ADMIN else 2
with tabs[log_idx]:
    st.subheader("Transfer Log")
    log = safe_read_ws(TRANSFERLOG_WS, LOG_COLS, "transfer log", ttl=0)
    if st.session_state.pending_transfers:
        log = pd.concat([log, pd.DataFrame(st.session_state.pending_transfers)], ignore_index=True)
    if not log.empty and "Date issued" in log.columns:
        log["Date issued"] = parse_dates_safe(log["Date issued"].astype(str))
        _ts = pd.to_datetime(log["Date issued"], format=DATE_FMT, errors="coerce")
        log = log.assign(_ts=_ts).sort_values("_ts", ascending=False, na_position="last").drop(columns="_ts")
    st.dataframe(nice_display(log), use_container_width=True, hide_index=True)

# --------------- Admin: Export
if IS_ADMIN:
    with tabs[4]:
        st.subheader("Download Exports")
        inv = safe_read_ws(INVENTORY_WS, ALL_COLS, "inventory")
        b1 = BytesIO(); 
        with pd.ExcelWriter(b1, engine="openpyxl") as w: inv.to_excel(w, index=False)
        b1.seek(0)
        st.download_button("⬇ Download Inventory", b1.getvalue(), file_name="inventory.xlsx",
                           mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        log = safe_read_ws(TRANSFERLOG_WS, LOG_COLS, "transfer log")
        b2 = BytesIO();
        with pd.ExcelWriter(b2, engine="openpyxl") as w: log.to_excel(w, index=False)
        b2.seek(0)
        st.download_button("⬇ Download Transfer Log", b2.getvalue(), file_name="transfer_log.xlsx",
                           mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

# --------------- Diagnostics (optional)
with st.expander("🔎 Connection diagnostics"):
    st.json({"spreadsheet": SPREADSHEET_URL})
    st.json({"INVENTORY_WS": INVENTORY_WS, "TRANSFERLOG_WS": TRANSFERLOG_WS})
    try:
        probe = conn.read(spreadsheet=SPREADSHEET_URL, worksheet=_ws_arg(INVENTORY_WS), nrows=3, ttl=0)
        st.caption(f"Inventory probe: {probe.shape}"); st.dataframe(probe, use_container_width=True)
    except Exception as e:
        st.error(f"Inventory probe failed: {e}")
    try:
        probe = conn.read(spreadsheet=SPREADSHEET_URL, worksheet=_ws_arg(TRANSFERLOG_WS), nrows=3, ttl=0)
        st.caption(f"Transfer log probe: {probe.shape}"); st.dataframe(probe, use_container_width=True)
    except Exception as e:
        st.error(f"Transfer log probe failed: {e}")
