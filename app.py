
# pip install streamlit gspread gspread-dataframe extra-streamlit-components pandas google-auth
import os
import re
import base64
import json
import hmac
import hashlib
import time
from datetime import datetime, timedelta

import streamlit as st
import pandas as pd
import gspread
from google.oauth2.service_account import Credentials
from gspread_dataframe import set_with_dataframe
import extra_streamlit_components as stx

# =============================================================================
# CONFIG
# =============================================================================
APP_TITLE = "Tracking Inventory Management System"
SUBTITLE  = "AdvancedConstruction"
DATE_FMT  = "%Y-%m-%d %H:%M:%S"

# Cookie/session config (assumption: persist login across refresh + browser restarts for 30 days)
SESSION_TTL_DAYS = 30  # change to 0 for session-only cookie
SESSION_TTL_SECONDS = SESSION_TTL_DAYS * 24 * 60 * 60
COOKIE_NAME = "ac_auth"
COOKIE_PATH = "/"
COOKIE_SECURE = False  # set True if you serve via HTTPS only
COOKIE_SAMESITE = "Lax"  # "Strict" or "None" (with SECURE=True) are also possible

# Default to your sheet URL; can be overridden in secrets
SHEET_URL_DEFAULT = "https://docs.google.com/spreadsheets/d/1SHp6gOW4ltsyOT41rwo85e_LELrHkwSwKN33K6XNHFI/edit"

# Worksheet titles (created if missing)
INVENTORY_WS    = "truckinventory"
TRANSFERLOG_WS  = "transfer_log"
EMPLOYEE_WS     = "mainlists"

# Canonical inventory columns
INVENTORY_COLS = [
    "Serial Number","Device Type","Brand","Model","CPU",
    "Hard Drive 1","Hard Drive 2","Memory","GPU","Screen Size",
    "USER","Previous User","TO",
    "Department","Email Address","Contact Number","Department.1","Location","Office",
    "Notes","Date issued","Registered by"
]
LOG_COLS = ["Device Type","Serial Number","From owner","To owner","Date issued","Registered by"]

# Employees sheet columns (canonical names)
EMPLOYEE_CANON_COLS = [
    "New Employeer","Employee ID","New Signature","Name","Address",
    "APLUS","Active","Position","Department","Location (KSA)",
    "Project","Microsoft Teams","Mobile Number"
]

# Accept common synonym/typo headers and normalize to canon
HEADER_SYNONYMS = {
    "new employee": "New Employeer",
    "new employeer": "New Employeer",
    "employeeid": "Employee ID",
    "newsignature": "New Signature",
    "locationksa": "Location (KSA)",
    "microsoftteams": "Microsoft Teams",
    "microsoftteam": "Microsoft Teams",
    "mobile": "Mobile Number",
    "mobilenumber": "Mobile Number",
}

st.set_page_config(page_title=APP_TITLE, layout="wide")

# Mount CookieManager once (no global delete_all calls — that can wipe component state in some browsers)
COOKIE_MGR = stx.CookieManager(key="ac_cookie_mgr")

# =============================================================================
# AUTH HELPERS (COOKIE + HMAC)
# =============================================================================

def _cookie_key() -> str:
    # Put a strong random in secrets:
    # [auth]
    # cookie_key = "your-very-long-random-secret"
    return st.secrets.get("auth", {}).get("cookie_key", "PLEASE_SET_auth.cookie_key_IN_SECRETS")


def _sign(raw: bytes) -> str:
    return hmac.new(_cookie_key().encode(), raw, hashlib.sha256).hexdigest()


def _issue_session_cookie(username: str, role: str):
    iat = int(time.time())
    exp = iat + (SESSION_TTL_SECONDS if SESSION_TTL_SECONDS > 0 else 0)
    payload = {"u": username, "r": role, "iat": iat, "exp": exp, "v": 1}
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    token = base64.urlsafe_b64encode(raw).decode() + "." + _sign(raw)
    # persist across refresh; if SESSION_TTL_SECONDS == 0 => session-only
    if SESSION_TTL_SECONDS > 0:
        COOKIE_MGR.set(
            COOKIE_NAME,
            token,
            max_age=SESSION_TTL_SECONDS,
            path=COOKIE_PATH,
            secure=COOKIE_SECURE,
            same_site=COOKIE_SAMESITE,
        )
    else:
        COOKIE_MGR.set(
            COOKIE_NAME,
            token,
            path=COOKIE_PATH,
            secure=COOKIE_SECURE,
            same_site=COOKIE_SAMESITE,
        )


def _read_cookie():
    token = COOKIE_MGR.get(COOKIE_NAME)
    if not token:
        return None
    try:
        data_b64, sig = token.split(".", 1)
        raw = base64.urlsafe_b64decode(data_b64.encode())
        if not hmac.compare_digest(sig, _sign(raw)):
            # bad signature — toss the cookie
            COOKIE_MGR.delete(COOKIE_NAME, path=COOKIE_PATH)
            return None
        payload = json.loads(raw.decode())
        # expiry check if set
        exp = int(payload.get("exp", 0))
        now = int(time.time())
        if exp and now > exp:
            COOKIE_MGR.delete(COOKIE_NAME, path=COOKIE_PATH)
            return None
        return payload
    except Exception:
        COOKIE_MGR.delete(COOKIE_NAME, path=COOKIE_PATH)
        return None


def do_login(username: str, role: str):
    st.session_state.authenticated = True
    st.session_state.username = username
    st.session_state.name = username
    st.session_state.role = role
    st.session_state.just_logged_out = False
    _issue_session_cookie(username, role)
    st.rerun()


def do_logout():
    try:
        COOKIE_MGR.delete(COOKIE_NAME, path=COOKIE_PATH)
        # also set a past expiry just in case older browsers cache it
        COOKIE_MGR.set(COOKIE_NAME, "", expires_at=datetime.utcnow() - timedelta(days=1), path=COOKIE_PATH)
    except Exception:
        pass
    for k in ["authenticated", "role", "username", "name"]:
        st.session_state.pop(k, None)
    st.session_state.just_logged_out = True  # avoid trying to re-read cookie this rerun
    st.rerun()


# Ensure CookieManager is mounted before first read
if "cookie_bootstrapped" not in st.session_state:
    st.session_state.cookie_bootstrapped = True
    _ = COOKIE_MGR.get_all()  # primes the component
    st.rerun()


# =============================================================================
# STYLE
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


def render_header():
    _inject_font_css("FounderGroteskCondensed-Regular.otf")

    c_logo, c_title, c_user = st.columns([1.2, 6, 3], gap="small")
    with c_logo:
        if os.path.exists("company_logo.jpeg"):
            try:
                st.image("company_logo.jpeg", use_container_width=True)
            except TypeError:
                st.image("company_logo.jpeg", use_column_width=True)
    with c_title:
        st.markdown(f"### {APP_TITLE}")
        st.caption(SUBTITLE)
    with c_user:
        username = st.session_state.get("username", "")
        role = st.session_state.get("role", "")
        st.markdown(
            f"""<div style="display:flex; align-items:center; justify-content:flex-end; gap:1rem;">
                   <div>
                     <div style="font-weight:600;">Welcome, {username or '—'}</div>
                     <div>Role: <b>{role or '—'}</b></div>
                   </div>
                 </div>""",
            unsafe_allow_html=True,
        )
        if st.session_state.get("authenticated") and st.button("Logout"):
            do_logout()

    st.markdown("<hr style='margin-top:0.8rem;'>", unsafe_allow_html=True)


def hide_table_toolbar_for_non_admin():
    if st.session_state.get("role") != "Admin":
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


# =============================================================================
# GOOGLE SHEETS — LAZY + RETRY + CACHED READS
# =============================================================================
SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive",
]


@st.cache_resource(show_spinner=False)
def _get_gc():
    creds = Credentials.from_service_account_info(
        st.secrets["gcp_service_account"], scopes=SCOPES
    )
    return gspread.authorize(creds)


@st.cache_resource(show_spinner=False)
def _get_sheet_url():
    return st.secrets.get("sheets", {}).get("url", SHEET_URL_DEFAULT)


def get_sh():
    gc = _get_gc()
    url = _get_sheet_url()
    last_exc = None
    for attempt in range(3):
        try:
            return gc.open_by_url(url)
        except gspread.exceptions.APIError as e:
            last_exc = e
            time.sleep(0.6 * (attempt + 1))
    st.error("Google Sheets API error while opening the spreadsheet. "
             "Please confirm the service account has access and try again.")
    raise last_exc


def _norm_title(t: str) -> str:
    return (t or "").strip().lower()


def _norm_header(h: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (h or "").strip().lower())


def _canon_header(h: str) -> str:
    key = _norm_header(h)
    return HEADER_SYNONYMS.get(key, h.strip())


def reorder_columns(df: pd.DataFrame, desired: list[str]) -> pd.DataFrame:
    for c in desired:
        if c not in df.columns:
            df[c] = ""
    tail = [c for c in df.columns if c not in desired]
    return df[desired + tail]


def _find_ws_candidates(title: str):
    sh = get_sh()
    target = _norm_title(title)
    return [ws for ws in sh.worksheets() if _norm_title(ws.title) == target]


def _score_header(values: list[list[str]], expected_canon: set[str]) -> tuple[int, int]:
    best_idx, best_count = 0, 0
    rows_to_scan = min(len(values), 10)
    for i in range(rows_to_scan):
        row = values[i]
        canon = {_canon_header(c) for c in row if str(c).strip()}
        overlap = len(canon & expected_canon)
        if overlap > best_count:
            best_idx, best_count = i, overlap
    return best_idx, best_count


def _read_ws_as_dataframe(ws: gspread.Worksheet, expected_cols: list[str]) -> tuple[pd.DataFrame, int, int]:
    values = ws.get_all_values() or []
    if not values:
        return pd.DataFrame(columns=expected_cols), 0, 0

    expected_canon = set(expected_cols)
    header_idx, score = _score_header(values, expected_canon)
    headers_raw = values[header_idx]
    headers_canon = [_canon_header(h) for h in headers_raw]
    preferred = [HEADER_SYNONYMS.get(_norm_header(h), h) for h in headers_raw]

    data_rows = values[header_idx + 1 :]
    df = pd.DataFrame(data_rows, columns=preferred).replace({None: ""})
    df = df.dropna(how="all").reset_index(drop=True)
    df = reorder_columns(df, expected_cols)
    return df, header_idx, score


def get_employee_ws() -> gspread.Worksheet:
    sh = get_sh()
    ws_id = st.session_state.get("emp_ws_id")
    if ws_id:
        ws = sh.get_worksheet_by_id(ws_id)
        if ws is not None:
            return ws

    cands = _find_ws_candidates(EMPLOYEE_WS)
    if not cands:
        ws = sh.add_worksheet(title=EMPLOYEE_WS, rows=500, cols=80)
        st.session_state.emp_ws_id = ws.id
        return ws

    if len(cands) == 1:
        ws = cands[0]
        st.session_state.emp_ws_id = ws.id
        return ws

    best_ws, best_score = None, -1
    for ws in cands:
        try:
            _, _, score = _read_ws_as_dataframe(ws, EMPLOYEE_CANON_COLS)
            if score > best_score:
                best_ws, best_score = ws, score
        except Exception:
            continue

    ws = best_ws or cands[0]
    st.session_state.emp_ws_id = ws.id
    return ws


def get_or_create_ws(title, rows=500, cols=80):
    sh = get_sh()
    try:
        return sh.worksheet(title)
    except gspread.exceptions.WorksheetNotFound:
        return sh.add_worksheet(title=title, rows=rows, cols=cols)


@st.cache_data(ttl=120, show_spinner=False)
def _read_worksheet_cached(ws_title: str) -> pd.DataFrame:
    if ws_title == EMPLOYEE_WS:
        ws = get_employee_ws()
        df, header_idx, overlap = _read_ws_as_dataframe(ws, EMPLOYEE_CANON_COLS)
        st.session_state.emp_debug = {
            "title": ws.title, "gid": ws.id,
            "header_row": header_idx + 1, "overlap": overlap, "rows": len(df),
        }
        return df
    ws = get_or_create_ws(ws_title)
    data = ws.get_all_records()
    df = pd.DataFrame(data)
    if ws_title == INVENTORY_WS:
        return reorder_columns(df, INVENTORY_COLS)
    if ws_title == TRANSFERLOG_WS:
        return reorder_columns(df, LOG_COLS)
    return df


def read_worksheet(ws_title):
    try:
        return _read_worksheet_cached(ws_title)
    except Exception as e:
        st.error(f"Error reading sheet '{ws_title}': {e}")
        if ws_title == INVENTORY_WS:   return pd.DataFrame(columns=INVENTORY_COLS)
        if ws_title == TRANSFERLOG_WS: return pd.DataFrame(columns=LOG_COLS)
        if ws_title == EMPLOYEE_WS:    return pd.DataFrame(columns=EMPLOYEE_CANON_COLS)
        return pd.DataFrame()


def write_worksheet(ws_title, df):
    ws = get_employee_ws() if ws_title == EMPLOYEE_WS else get_or_create_ws(ws_title)
    ws.clear()
    set_with_dataframe(ws, df)
    st.cache_data.clear()


def append_to_worksheet(ws_title, new_data):
    ws = get_employee_ws() if ws_title == EMPLOYEE_WS else get_or_create_ws(ws_title)
    df_existing = pd.DataFrame(ws.get_all_records())
    df_combined = pd.concat([df_existing, new_data], ignore_index=True)
    set_with_dataframe(ws, df_combined)
    st.cache_data.clear()


# =============================================================================
# AUTH (users) + LOGIN FORM
# =============================================================================

def load_users():
    admins = st.secrets.get("auth", {}).get("admins", {})
    staff  = st.secrets.get("auth", {}).get("staff", {})
    users = {}
    for user, pw in admins.items():
        if user != "type":
            users[user] = {"password": pw, "role": "Admin", "name": user}
    for user, pw in staff.items():
        users[user] = {"password": pw, "role": "Staff", "name": user}
    return users


USERS = load_users()


def show_login():
    st.subheader("🔐 Sign In")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login", type="primary"):
        user = USERS.get(username)
        if user and user["password"] == password:
            do_login(username, user["role"])  # sets cookie + rerun
        else:
            st.error("❌ Invalid username or password.")


# =============================================================================
# TABS
# =============================================================================

def employees_view_tab():
    st.subheader("📇 Employees (mainlists)")
    df = read_worksheet(EMPLOYEE_WS)
    if df.empty:
        st.info("No employees found in 'mainlists'.")
    else:
        st.dataframe(df, use_container_width=True, hide_index=True)


def inventory_tab():
    st.subheader("📋 Inventory")
    df = read_worksheet(INVENTORY_WS)
    if df.empty:
        st.warning("Inventory is empty.")
    else:
        if st.session_state.role == "Admin":
            st.dataframe(df, use_container_width=True)
        else:
            st.dataframe(df, use_container_width=True, hide_index=True)


def register_device_tab():
    st.subheader("📝 Register New Device")
    with st.form("register_device", clear_on_submit=True):
        r1c1, r1c2, r1c3 = st.columns(3)
        with r1c1:
            serial = st.text_input("Serial Number *")
        with r1c2:
            device = st.text_input("Device Type *")
        with r1c3:
            brand  = st.text_input("Brand")

        r2c1, r2c2, r2c3 = st.columns(3)
        with r2c1:
            model  = st.text_input("Model")
        with r2c2:
            cpu    = st.text_input("CPU")
        with r2c3:
            mem    = st.text_input("Memory")

        r3c1, r3c2, r3c3 = st.columns(3)
        with r3c1:
            hdd1   = st.text_input("Hard Drive 1")
        with r3c2:
            hdd2   = st.text_input("Hard Drive 2")
        with r3c3:
            gpu    = st.text_input("GPU")

        r4c1, r4c2, r4c3 = st.columns(3)
        with r4c1:
            screen = st.text_input("Screen Size")
        with r4c2:
            email  = st.text_input("Email Address")
        with r4c3:
            contact = st.text_input("Contact Number")

        r5c1, r5c2, r5c3 = st.columns(3)
        with r5c1:
            dept   = st.text_input("Department")
        with r5c2:
            dept1  = st.text_input("Department.1")
        with r5c3:
            location = st.text_input("Location")

        r6c1, r6c2 = st.columns([1, 2])
        with r6c1:
            office = st.text_input("Office")
        with r6c2:
            notes  = st.text_area("Notes", height=60)

        submitted = st.form_submit_button("Save Device", type="primary")

    if submitted:
        if not serial.strip() or not device.strip():
            st.error("Serial Number and Device Type are required.")
            return

        inv = read_worksheet(INVENTORY_WS)
        if not inv.empty and serial.strip() in inv["Serial Number"].astype(str).values:
            st.error(f"Serial Number '{serial}' already exists.")
            return

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
            "Department": dept.strip(),
            "Email Address": email.strip(),
            "Contact Number": contact.strip(),
            "Department.1": dept1.strip(),
            "Location": location.strip(),
            "Office": office.strip(),
            "Notes": notes.strip(),
            "Date issued": datetime.now().strftime(DATE_FMT),
            "Registered by": st.session_state.get("username", ""),
        }

        inv = pd.concat([inv, pd.DataFrame([row])], ignore_index=True) if not inv.empty else pd.DataFrame([row])
        inv = reorder_columns(inv, INVENTORY_COLS)
        write_worksheet(INVENTORY_WS, inv)
        st.success("✅ Device registered and added to Inventory.")


def transfer_tab():
    st.subheader("🔁 Transfer Device")
    inventory_df = read_worksheet(INVENTORY_WS)
    if inventory_df.empty:
        st.warning("Inventory is empty.")
        return

    serial_list = sorted(inventory_df["Serial Number"].dropna().astype(str).unique().tolist())
    serial = st.selectbox("Serial Number", ["— Select —"] + serial_list)
    chosen_serial = None if serial == "— Select —" else serial

    existing_users = sorted([u for u in inventory_df["USER"].dropna().astype(str).unique().tolist() if u.strip()])
    new_owner_choice = st.selectbox("New Owner", ["— Select —"] + existing_users + ["Type a new name…"])
    if new_owner_choice == "Type a new name…":
        new_owner = st.text_input("Enter new owner name")
    else:
        new_owner = new_owner_choice if new_owner_choice != "— Select —" else ""

    do_transfer = st.button("Transfer Now", type="primary", disabled=not (chosen_serial and new_owner.strip()))

    if do_transfer:
        match = inventory_df[inventory_df["Serial Number"].astype(str) == chosen_serial]
        if match.empty:
            st.warning("Serial number not found.")
            return

        idx = match.index[0]
        prev_user = str(inventory_df.loc[idx, "USER"] or "")
        now_str   = datetime.now().strftime(DATE_FMT)
        actor     = st.session_state.get("username", "")

        inventory_df.loc[idx, "Previous User"] = prev_user
        inventory_df.loc[idx, "USER"]          = new_owner.strip()
        inventory_df.loc[idx, "TO"]            = new_owner.strip()
        inventory_df.loc[idx, "Date issued"]   = now_str
        inventory_df.loc[idx, "Registered by"] = actor

        inventory_df = reorder_columns(inventory_df, INVENTORY_COLS)
        write_worksheet(INVENTORY_WS, inventory_df)

        log_row = {
            "Device Type": inventory_df.loc[idx, "Device Type"],
            "Serial Number": chosen_serial,
            "From owner": prev_user,
            "To owner": new_owner.strip(),
            "Date issued": now_str,
            "Registered by": actor,
        }
        append_to_worksheet(TRANSFERLOG_WS, pd.DataFrame([log_row]))

        st.success(f"✅ Transfer saved: {prev_user or '(blank)'} → {new_owner.strip()}")


def history_tab():
    st.subheader("📜 Transfer Log")
    df = read_worksheet(TRANSFERLOG_WS)
    if df.empty:
        st.info("No transfer history found.")
    else:
        st.dataframe(df, use_container_width=True, hide_index=True)


def employee_register_tab():
    st.subheader("🧑‍💼 Register New Employee (mainlists)")
    emp_df = read_worksheet(EMPLOYEE_WS)
    try:
        ids = pd.to_numeric(emp_df["Employee ID"], errors="coerce").dropna().astype(int)
        next_id_suggestion = str(ids.max() + 1) if len(ids) else str(len(emp_df) + 1)
    except Exception:
        next_id_suggestion = str(len(emp_df) + 1)

    with st.form("register_employee", clear_on_submit=True):
        r1c1, r1c2, r1c3 = st.columns(3)
        with r1c1:
            new_emp_status = st.text_input("New Employeer")  # blank by default
        with r1c2:
            emp_id = st.text_input("Employee ID", help=f"Suggested next ID: {next_id_suggestion}")
        with r1c3:
            new_sig = st.text_input("New Signature")

        r2c1, r2c2, r2c3 = st.columns(3)
        with r2c1:
            name = st.text_input("Name *")
        with r2c2:
            address = st.text_input("Address")
        with r2c3:
            aplus = st.text_input("APLUS")  # blank by default

        r3c1, r3c2, r3c3 = st.columns(3)
        with r3c1:
            active = st.text_input("Active")  # blank by default
        with r3c2:
            position = st.text_input("Position")
        with r3c3:
            department = st.text_input("Department")

        r4c1, r4c2, r4c3 = st.columns(3)
        with r4c1:
            location_ksa = st.text_input("Location (KSA)")
        with r4c2:
            project = st.text_input("Project")
        with r4c3:
            teams = st.text_input("Microsoft Teams")

        mobile = st.text_input("Mobile Number")

        submitted = st.form_submit_button("Save Employee", type="primary")

    if submitted:
        if not name.strip():
            st.error("Name is required.")
            return
        if emp_id.strip() and not emp_df.empty and emp_id.strip() in emp_df["Employee ID"].astype(str).values:
            st.error(f"Employee ID '{emp_id}' already exists.")
            return

        row = {
            "New Employeer": new_emp_status.strip(),
            "Employee ID": emp_id.strip() if emp_id.strip() else next_id_suggestion,
            "New Signature": new_sig.strip(),
            "Name": name.strip(),
            "Address": address.strip(),
            "APLUS": aplus.strip(),
            "Active": active.strip(),
            "Position": position.strip(),
            "Department": department.strip(),
            "Location (KSA)": location_ksa.strip(),
            "Project": project.strip(),
            "Microsoft Teams": teams.strip(),
            "Mobile Number": mobile.strip(),
        }
        new_df = pd.concat([emp_df, pd.DataFrame([row])], ignore_index=True) if not emp_df.empty else pd.DataFrame([row])
        new_df = reorder_columns(new_df, EMPLOYEE_CANON_COLS)
        write_worksheet(EMPLOYEE_WS, new_df)
        st.success("✅ Employee saved to 'mainlists'.")




def export_tab():
    st.subheader("⬇️ Export (always fresh)")
    inv = read_worksheet(INVENTORY_WS)
    log = read_worksheet(TRANSFERLOG_WS)
    emp = read_worksheet(EMPLOYEE_WS)
    st.caption(f"Last fetched: {datetime.now().strftime(DATE_FMT)}")
    c1, c2, c3 = st.columns(3)
    with c1:
        st.download_button("Inventory CSV", inv.to_csv(index=False).encode("utf-8"),
                           "inventory.csv", "text/csv")
    with c2:
        st.download_button("Transfer Log CSV", log.to_csv(index=False).encode("utf-8"),
                           "transfer_log.csv", "text/csv")
    with c3:
        st.download_button("Employees CSV", emp.to_csv(index=False).encode("utf-8"),
                           "employees.csv", "text/csv")


# =============================================================================
# MAIN
# =============================================================================

def run_app():
    render_header()
    hide_table_toolbar_for_non_admin()

    if st.session_state.role == "Admin":
        tabs = st.tabs([
            "🧑‍💼 Employee Register",
            "📇 View Employees",
            "📝 Register Device",
            "📋 View Inventory",
            "🔁 Transfer Device",
            "📜 Transfer Log",
            "⬇️ Export"
        ])
        with tabs[0]: employee_register_tab()
        with tabs[1]: employees_view_tab()
        with tabs[2]: register_device_tab()
        with tabs[3]: inventory_tab()
        with tabs[4]: transfer_tab()
        with tabs[5]: history_tab()
        with tabs[6]: export_tab()
    else:
        tabs = st.tabs(["📋 View Inventory", "🔁 Transfer Device", "📜 Transfer Log"])
        with tabs[0]: inventory_tab()
        with tabs[1]: transfer_tab()
        with tabs[2]: history_tab()


# =============================================================================
# ENTRY
# =============================================================================
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

# Refresh behavior:
# - If you're logged in, cookie keeps you in (persisting for SESSION_TTL_DAYS).
# - If you just logged out, skip cookie read once to prevent flash re-login.
if not st.session_state.authenticated and not st.session_state.get("just_logged_out"):
    payload = _read_cookie()
    if payload:
        st.session_state.authenticated = True
        st.session_state.username = payload["u"]
        st.session_state.name = payload["u"]
        st.session_state.role = payload.get("r", "")

if st.session_state.authenticated:
    run_app()
else:
    show_login()
