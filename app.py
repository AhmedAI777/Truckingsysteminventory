import os, re, io, json, hmac, time, base64, hashlib
SESSION_TTL_SECONDS = SESSION_TTL_DAYS * 24 * 60 * 60
COOKIE_NAME = "ac_auth_v2"

SHEET_URL_DEFAULT = "https://docs.google.com/spreadsheets/d/1SHp6gOW4ltsyOT41rwo85e_LELrHkwSwKN33K6XNHFI/edit"

INVENTORY_WS = "truckinventory"
TRANSFERLOG_WS = "transfer_log"
EMPLOYEE_WS = "mainlists"
PENDING_DEVICE_WS = "pending_device_reg"
PENDING_TRANSFER_WS = "pending_transfers"
DEVICE_CATALOG_WS = st.secrets.get("sheets", {}).get("catalog_ws", "truckingsysteminventory")
COUNTERS_WS = "counters"

INVENTORY_COLS = ["Serial Number", "Device Type", "Brand", "Model", "CPU",
"Hard Drive 1", "Hard Drive 2", "Memory", "GPU", "Screen Size",
"Current user", "Previous User", "TO",
"Department", "Email Address", "Contact Number", "Location", "Office",
"Notes", "Date issued", "Registered by"]

CATALOG_COLS = ["Serial Number", "Device Type", "Brand", "Model", "CPU",
"Hard Drive 1", "Hard Drive 2", "Memory", "GPU", "Screen Size"]

LOG_COLS = ["Device Type", "Serial Number", "From owner", "To owner", "Date issued", "Registered by"]

EMPLOYEE_HEADERS = ["Name", "Email", "APLUS", "Active", "Position", "Department",
"Location (KSA)", "Project", "Microsoft Teams", "Mobile Number"]

APPROVAL_META_COLS = ["Approval Status", "Approval PDF", "Approval File ID",
"Submitted by", "Submitted at", "Approver", "Decision at"]

PENDING_DEVICE_COLS = INVENTORY_COLS + APPROVAL_META_COLS
PENDING_TRANSFER_COLS = LOG_COLS + APPROVAL_META_COLS
COUNTER_COLS = ["Action", "Serial Number", "Order Number", "Timestamp"]

UNASSIGNED_LABEL = "Unassigned (Stock)"

ICT_TEMPLATE_FILE_ID = st.secrets.get("drive", {}).get("template_file_id", "1BdbeVEpDuS_hpQgxNLGij5sl01azT_zG")
TRANSFER_TEMPLATE_FILE_ID = st.secrets.get("drive", {}).get("transfer_template_file_id", ICT_TEMPLATE_FILE_ID)

CITY_MAP = {"Jeddah": "JED", "Riyadh": "RUH", "Taif": "TIF", "Madinah": "MED"}

# Cookie manager
COOKIE_MGR = stx.CookieManager(key="ac_cookie_mgr")
for k in ("reg_pdf_ref", "transfer_pdf_ref"):
ss.setdefault(k, None)

# =========================
# Auth
# =========================
def _load_users_from_secrets():
    cfg = st.secrets.get("auth", {}).get("users", [])
    return {
        u["username"]: {"password": u.get("password", ""), "role": u.get("role", "Staff")}
        for u in cfg
    }

USERS = _load_users_from_secrets()

def _verify_password(raw: str, stored: str) -> bool:
    return hmac.compare_digest(str(stored), str(raw))

def _cookie_keys() -> list[str]:
    keys = [st.secrets.get("auth", {}).get("cookie_key", "")]
    keys += st.secrets.get("auth", {}).get("legacy_cookie_keys", [])
    return [k for k in keys if k]

def _sign(raw: bytes, *, key: str | None = None) -> str:
    use = key or st.secrets.get("auth", {}).get("cookie_key", "")
    return hmac.new(use.encode(), raw, hashlib.sha256).hexdigest()

def _verify_sig(sig: str, raw: bytes) -> bool:
    for k in _cookie_keys():
        if hmac.compare_digest(sig, _sign(raw, key=k)):
            return True
    return False

def _issue_session_cookie(username: str, role: str):
    iat = int(time.time())
    exp = iat + SESSION_TTL_SECONDS if SESSION_TTL_SECONDS > 0 else 0
    payload = {"u": username, "r": role, "iat": iat, "exp": exp, "v": 1}
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    token = base64.urlsafe_b64encode(raw).decode() + "." + _sign(raw)
    COOKIE_MGR.set(
        COOKIE_NAME,
        token,
        expires_at=(datetime.utcnow() + timedelta(seconds=SESSION_TTL_SECONDS)) if SESSION_TTL_SECONDS > 0 else None,
        secure=st.secrets.get("auth", {}).get("cookie_secure", True),
    )

def _read_cookie():
    token = COOKIE_MGR.get(COOKIE_NAME)
    if not token:
        return None
    try:
        data_b64, sig = token.split(".", 1)
        raw = base64.urlsafe_b64decode(data_b64.encode())
        if not _verify_sig(sig, raw):
            COOKIE_MGR.delete(COOKIE_NAME)
            return None
        payload = json.loads(raw.decode())
        exp = int(payload.get("exp", 0))
        now = int(time.time())
        if exp and now > exp:
            COOKIE_MGR.delete(COOKIE_NAME)
            return None
        return payload
    except Exception:
        COOKIE_MGR.delete(COOKIE_NAME)
        return None

def do_login(username: str, role: str):
    st.session_state["authenticated"] = True
    st.session_state["username"] = username
    st.session_state["role"] = role
    st.session_state["just_logged_out"] = False
    _issue_session_cookie(username, role)
    st.rerun()

def do_logout():
    try:
        COOKIE_MGR.delete(COOKIE_NAME)
        COOKIE_MGR.set(COOKIE_NAME, "", expires_at=datetime.utcnow() - timedelta(days=1))
    except Exception:
        pass
    for key in ["authenticated", "role", "username"]:
        st.session_state.pop(key, None)
    st.session_state["just_logged_out"] = True
    st.rerun()

if "cookie_bootstrapped" not in st.session_state:
    st.session_state["cookie_bootstrapped"] = True
    _ = COOKIE_MGR.get_all()
    st.rerun()

# =========================
# Google APIs Setup
# =========================
SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive"
]
OAUTH_SCOPES = ["https://www.googleapis.com/auth/drive.file"]
ALLOW_OAUTH_FALLBACK = st.secrets.get("drive", {}).get("allow_oauth_fallback", True)
# =========================
# Google Service Account Loader
# =========================
def _load_sa_info() -> dict:
    raw = st.secrets.get("gcp_service_account", {})
    sa = {}

    if isinstance(raw, dict):
        sa = dict(raw)
    elif isinstance(raw, str) and raw.strip():
        try:
            sa = json.loads(raw)
        except json.JSONDecodeError:
            sa = {}

    if not sa:
        env_json = os.environ.get("GOOGLE_SERVICE_ACCOUNT_JSON", "")
        if env_json:
            try:
                sa = json.loads(env_json)
            except Exception:
                sa = {}

    pk = sa.get("private_key", "")
    if isinstance(pk, str) and "\\n" in pk:
        sa["private_key"] = pk.replace("\\n", "\n")

    if "private_key" not in sa:
        raise RuntimeError("Service account JSON missing or incomplete.")

    return sa


# =========================
# Google API Clients
# =========================
@st.cache_resource(show_spinner=False)
def _get_creds():
    return Credentials.from_service_account_info(_load_sa_info(), scopes=SCOPES)

@st.cache_resource(show_spinner=False)
def _get_gc():
    return gspread.authorize(_get_creds())

@st.cache_resource(show_spinner=False)
def _get_drive():
    return build("drive", "v3", credentials=_get_creds())

@st.cache_resource(show_spinner=False)
def _get_user_creds():
    cfg = st.secrets.get("google_oauth", {})
    token_json = cfg.get("token_json")

    if token_json:
        try:
            info = json.loads(token_json)
            creds = UserCredentials.from_authorized_user_info(info, OAUTH_SCOPES)
            if not creds.valid and creds.refresh_token:
                creds.refresh(Request())
            return creds
        except Exception:
            st.error("Invalid OAuth token_json in secrets.")
            st.stop()

    if os.environ.get("LOCAL_OAUTH", "0") == "1":
        client_id = cfg.get("client_id")
        client_secret = cfg.get("client_secret")
        if not client_id or not client_secret:
            st.error("Missing client_id/client_secret for local OAuth.")
            st.stop()

        flow = InstalledAppFlow.from_client_config(
            {
                "installed": {
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": ["http://localhost"],
                }
            },
            scopes=OAUTH_SCOPES,
        )
        return flow.run_local_server(port=0)

    st.error("OAuth fallback not configured.")
    st.stop()

@st.cache_resource(show_spinner=False)
def _get_user_drive():
    return build("drive", "v3", credentials=_get_user_creds())

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
    st.error("Failed to open spreadsheet after multiple attempts.")
    raise last_exc


# =========================
# Drive Helpers
# =========================
def ensure_drive_subfolder(root_id: str, path_parts: list[str], drive_cli=None) -> str:
    cli = drive_cli or _get_drive()
    parent = root_id
    for part in path_parts:
        q = (
            f"'{parent}' in parents and name='{part}' "
            "and mimeType='application/vnd.google-apps.folder' and trashed=false"
        )
        res = cli.files().list(q=q, spaces="drive", fields="files(id,name)", supportsAllDrives=True).execute()
        items = res.get("files", [])
        if items:
            parent = items[0]["id"]
        else:
            meta = {"name": part, "mimeType": "application/vnd.google-apps.folder", "parents": [parent]}
            newf = cli.files().create(body=meta, fields="id", supportsAllDrives=True).execute()
            parent = newf["id"]
    return parent

def upload_pdf_and_get_link(file_bytes: bytes, *, name: str, office: str, project_location: str) -> tuple[str, str]:
    """Uploads a PDF to Drive and returns (link, file_id)."""
    from googleapiclient.discovery import build
    from googleapiclient.http import MediaIoBaseUpload
    from google.oauth2 import service_account
    import io

    SHARED_DRIVE_ID = "1KatH0TQregGV_pajnySOGcPAXTNhex7L"
    ROOT_OFFICE_FOLDER_ID = {
        "Head Office (HO)": "1KatH0TQregGV_pajnySOGcPAXTNhex7L",
    }

    creds = service_account.Credentials.from_service_account_info(
        st.secrets["gcp_service_account"],
        scopes=["https://www.googleapis.com/auth/drive"]
    )
    service = build("drive", "v3", credentials=creds)

    if office not in ROOT_OFFICE_FOLDER_ID:
        raise ValueError(f"Unknown office: {office}")

    office_folder_id = ROOT_OFFICE_FOLDER_ID[office]

    query = f"'{office_folder_id}' in parents and name='{project_location}' and mimeType='application/vnd.google-apps.folder' and trashed = false"
    results = service.files().list(
        q=query,
        corpora="drive",
        driveId=SHARED_DRIVE_ID,
        includeItemsFromAllDrives=True,
        supportsAllDrives=True,
        fields="files(id, name)"
    ).execute()

    items = results.get("files", [])

    if items:
        project_folder_id = items[0]["id"]
    else:
        folder_metadata = {
            "name": project_location,
            "mimeType": "application/vnd.google-apps.folder",
            "parents": [office_folder_id],
            "driveId": SHARED_DRIVE_ID
        }
        folder = service.files().create(
            body=folder_metadata,
            fields="id",
            supportsAllDrives=True
        ).execute()
        project_folder_id = folder.get("id")

    filename = f"{name}.pdf"
    file_metadata = {
        "name": filename,
        "parents": [project_folder_id],
        "driveId": SHARED_DRIVE_ID,
        "mimeType": "application/pdf"
    }

    media = MediaIoBaseUpload(io.BytesIO(file_bytes), mimetype="application/pdf", resumable=True)

    file = service.files().create(
        body=file_metadata,
        media_body=media,
        fields="id",
        supportsAllDrives=True
    ).execute()

    file_id = file.get("id")

    service.permissions().create(
        fileId=file_id,
        supportsAllDrives=True,
        body={"type": "anyone", "role": "reader"}
    ).execute()

    link = f"https://drive.google.com/file/d/{file_id}/view"
    return link, file_id


# =========================
# Sheets Helpers
# =========================
def _norm_header(h: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (h or "").strip().lower())

def canon_inventory_columns(df: pd.DataFrame) -> pd.DataFrame:
    rename = {}
    for c in df.columns:
        key = _norm_header(c)
        if key in {"user": "Current user", "currentuser": "Current user"}:
            rename[c] = "Current user"
    if rename:
        df = df.rename(columns=rename)
    return df.astype(str)

def reorder_columns(df: pd.DataFrame, desired: list[str]) -> pd.DataFrame:
    for c in desired:
        if c not in df.columns:
            df[c] = ""
    tail = [c for c in df.columns if c not in desired]
    return df[desired + tail]

def get_or_create_ws(title, rows=500, cols=80):
    sh = get_sh()
    try:
        return sh.worksheet(title)
    except gspread.exceptions.WorksheetNotFound:
        return sh.add_worksheet(title=title, rows=rows, cols=cols)

# (similar helpers for read_worksheet, write_worksheet, append_to_worksheet…)
# (these remain unchanged from your version, except now cleaned where needed)

# =========================
# UI Tabs
# =========================

# =========================
# UI Tabs
# =========================

def employee_register_tab():
st.subheader("🧑‍💼 Register New Employee")
with st.form("employee_register", clear_on_submit=True):
name = st.text_input("Full Name *")
emp_id = st.text_input("Employee ID (APLUS) *")
email = st.text_input("Email")
mobile = st.text_input("Mobile Number")
position = st.text_input("Position")
dept = st.text_input("Department")
loc = st.text_input("Location (KSA)")
proj = st.text_input("Project / Office")
teams = st.text_input("Microsoft Teams")
submitted = st.form_submit_button("Save Employee", type="primary")
if submitted:
if not name.strip() or not emp_id.strip():
st.error("Name and Employee ID are required.")
return
new_row = pd.DataFrame([{ "Name": name.strip(), "Email": email.strip(), "APLUS": emp_id.strip(),
"Active": "Yes", "Position": position.strip(), "Department": dept.strip(),
"Location (KSA)": loc.strip(), "Project": proj.strip(), "Microsoft Teams": teams.strip(),
"Mobile Number": mobile.strip()}])
append_to_worksheet(EMPLOYEE_WS, new_row)
st.success(f"✅ Employee '{name}' registered.")

def employees_view_tab():
st.subheader("📇 Employees (mainlists)")
df = read_worksheet(EMPLOYEE_WS)
if df.empty:
st.info("No employees found.")
else:
st.dataframe(df, use_container_width=True, hide_index=True)

def inventory_tab():
st.subheader("📋 Inventory")
df = read_worksheet(INVENTORY_WS)
if df.empty:
st.warning("Inventory is empty.")
else:
st.dataframe(df, use_container_width=True, hide_index=True)

def history_tab():
st.subheader("📜 Transfer Log")
df = read_worksheet(TRANSFERLOG_WS)
if df.empty:
st.info("No transfer history found.")
else:
st.dataframe(df, use_container_width=True, hide_index=True)


def register_device_tab():
    st.subheader("📝 Register New Device")
    st.session_state.setdefault("current_owner", UNASSIGNED_LABEL)
    emp_df = read_worksheet(EMPLOYEE_WS)
    employee_names = sorted({*unique_nonempty(emp_df, "New Employeer"), *unique_nonempty(emp_df, "Name")})
    owner_options = [UNASSIGNED_LABEL] + employee_names

    st.selectbox(
        "Current owner (at registration)",
        owner_options,
        index=owner_options.index(st.session_state["current_owner"])
        if st.session_state["current_owner"] in owner_options else 0,
        key="current_owner",
        on_change=_owner_changed,
        args=(emp_df,),
    )

    with st.form("register_device", clear_on_submit=False):
        st.text_input("Serial Number *", key="reg_serial")
        st.text_input("Device Type *", key="reg_device")
        st.text_input("Brand", key="reg_brand")
        st.text_input("Model", key="reg_model")
        st.text_input("CPU", key="reg_cpu")
        st.text_input("Memory", key="reg_mem")
        st.text_input("Hard Drive 1", key="reg_hdd1")
        st.text_input("Hard Drive 2", key="reg_hdd2")
        st.text_input("GPU", key="reg_gpu")
        st.text_input("Screen Size", key="reg_screen")
        st.text_input("Email Address", key="reg_email")
        st.text_input("Contact Number", key="reg_contact")
        st.text_input("Department", key="reg_dept")
        st.text_input("Location", key="reg_location")
        st.text_input("Office", key="reg_office")
        st.text_area("Notes", height=80, key="reg_notes")

        pdf_file = st.file_uploader("Upload signed PDF", type=["pdf"], key="reg_pdf")

        c1, c2 = st.columns([1, 1])
        with c1:
            download_btn = st.form_submit_button("📄 Download Prefilled PDF")
        with c2:
            submitted = st.form_submit_button("💾 Save Device", type="primary")

    def build_row(now_str, actor):
        return {
            "Serial Number": st.session_state.get("reg_serial", "").strip(),
            "Device Type": st.session_state.get("reg_device", "").strip(),
            "Brand": st.session_state.get("reg_brand", "").strip(),
            "Model": st.session_state.get("reg_model", "").strip(),
            "CPU": st.session_state.get("reg_cpu", "").strip(),
            "Hard Drive 1": st.session_state.get("reg_hdd1", "").strip(),
            "Hard Drive 2": st.session_state.get("reg_hdd2", "").strip(),
            "Memory": st.session_state.get("reg_mem", "").strip(),
            "GPU": st.session_state.get("reg_gpu", "").strip(),
            "Screen Size": st.session_state.get("reg_screen", "").strip(),
            "Current user": st.session_state.get("current_owner", UNASSIGNED_LABEL).strip(),
            "Department": st.session_state.get("reg_dept", "").strip(),
            "Email Address": st.session_state.get("reg_email", "").strip(),
            "Contact Number": st.session_state.get("reg_contact", "").strip(),
            "Location": st.session_state.get("reg_location", "").strip(),
            "Office": st.session_state.get("reg_office", "").strip(),
            "Notes": st.session_state.get("reg_notes", "").strip(),
            "Date issued": now_str,
            "Registered by": actor,
        }

    if submitted:
        serial = st.session_state.get("reg_serial", "")
        device = st.session_state.get("reg_device", "")
        if not serial or not device:
            st.error("Serial Number and Device Type are required.")
            return

        pdf_file_obj = pdf_file or st.session_state.get("reg_pdf")
        if pdf_file_obj is None:
            st.error("Signed ICT Registration PDF is required.")
            return

        # ✅ FIX: convert to bytes
        pdf_bytes = pdf_file_obj.read()

        now_str = datetime.now().strftime(DATE_FMT)
        actor = st.session_state.get("username", "")
        row = build_row(now_str, actor)
        emp_row = _get_employee_row_by_name(emp_df, row["Current user"])
        order_no = get_next_order_number("REG", serial)

        link, fid = upload_pdf_and_get_link(
            pdf_bytes,
            name=f"REG-{serial}",
            office="Head Office (HO)",
            project_location="JEDDAH (JEDDAH)"
        )

        if not fid:
            return
        pending = {
            **row,
            "Approval Status": "Pending",
            "Approval PDF": link,
            "Approval File ID": fid,
            "Submitted by": actor,
            "Submitted at": now_str,
            "Approver": "",
            "Decision at": "",
        }
        append_to_worksheet(PENDING_DEVICE_WS, pd.DataFrame([pending]))
        st.success("🕒 Device registration submitted for Admin approval.")


def transfer_tab():
    st.subheader("🔄 Device Transfer")
    inv_df = read_worksheet(INVENTORY_WS)
    emp_df = read_worksheet(EMPLOYEE_WS)
    if inv_df.empty:
        st.info("No devices in inventory.")
        return

    serials = inv_df["Serial Number"].dropna().tolist()
    employees = sorted({*unique_nonempty(emp_df, "New Employeer"), *unique_nonempty(emp_df, "Name")})

    with st.form("transfer_form", clear_on_submit=False):
        serial = st.selectbox("Select Serial Number", serials, key="trf_serial")
        new_owner = st.selectbox("Select New Owner", employees, key="trf_new_owner")
        pdf_file = st.file_uploader("Upload signed transfer PDF", type=["pdf"], key="trf_pdf")

        c1, c2 = st.columns([1, 1])
        with c1:
            dl = st.form_submit_button("📄 Download Prefilled Transfer PDF")
        with c2:
            submitted = st.form_submit_button("💾 Submit Transfer Request", type="primary")

    if submitted:
        if not serial or not new_owner:
            st.error("Serial number and new owner required.")
            return
        if pdf_file is None:
            st.error("Signed ICT Transfer PDF is required.")
            return

        # ✅ FIX: convert to bytes
        pdf_bytes = pdf_file.read()

        row = inv_df.loc[inv_df["Serial Number"] == serial].iloc[0].to_dict()
        now_str = datetime.now().strftime(DATE_FMT)
        actor = st.session_state.get("username", "")
        order_no = get_next_order_number("TRN", serial)
        emp_row = _get_employee_row_by_name(emp_df, new_owner)

        link, fid = upload_pdf_and_get_link(
            pdf_bytes,
            name=f"TRN-{serial}",
            office="Head Office (HO)",
            project_location="JEDDAH (JEDDAH)"
        )

        if not fid:
            return

        pending = {
            **row,
            "From owner": row.get("Current user", ""),
            "To owner": new_owner,
            "Approval Status": "Pending",
            "Approval PDF": link,
            "Approval File ID": fid,
            "Submitted by": actor,
            "Submitted at": now_str,
            "Approver": "",
            "Decision at": "",
        }
        append_to_worksheet(PENDING_TRANSFER_WS, pd.DataFrame([pending]))
        st.success("🕒 Transfer request submitted for Admin approval.")

# =========================
# Approvals Tab
# =========================
def approvals_tab():
    st.subheader("✅ Approvals")

    # --- Pending Device Registrations ---
    st.markdown("### 📦 Pending Device Registrations")
    pend_df = read_worksheet(PENDING_DEVICE_WS)
    if pend_df.empty or not (pend_df["Approval Status"] == "Pending").any():
        st.info("No pending device registrations.")
    else:
        for i, row in pend_df.iterrows():
            if row.get("Approval Status") != "Pending":
                continue
            serial = row.get("Serial Number", "")
            device_type = row.get("Device Type", "")
            with st.expander(f"🔍 Serial: {serial} — {device_type}"):
                st.write(row.to_dict())
                pdf_link = row.get("Approval PDF", "")
                if pdf_link:
                    st.markdown(f"[📄 View PDF]({pdf_link})", unsafe_allow_html=True)
                c1, c2 = st.columns(2)
                with c1:
                    if st.button("✅ Approve", key=f"approve_device_{serial}_{i}"):
                        _approve_device_row(row)
                        st.rerun()
                with c2:
                    if st.button("❌ Reject", key=f"reject_device_{serial}_{i}"):
                        _reject_row(PENDING_DEVICE_WS, row)
                        st.rerun()

    st.divider()

    # --- Pending Transfers ---
    st.markdown("### 🔄 Pending Transfers")
    pend_trf = read_worksheet(PENDING_TRANSFER_WS)
    if pend_trf.empty or not (pend_trf["Approval Status"] == "Pending").any():
        st.info("No pending transfers.")
    else:
        for i, row in pend_trf.iterrows():
            if row.get("Approval Status") != "Pending":
                continue
            serial = row.get("Serial Number", "")
            to_owner = row.get("To owner", "")
            with st.expander(f"🔄 Serial: {serial} — Transfer to {to_owner}"):
                st.write(row.to_dict())
                pdf_link = row.get("Approval PDF", "")
                if pdf_link:
                    st.markdown(f"[📄 View PDF]({pdf_link})", unsafe_allow_html=True)
                c1, c2 = st.columns(2)
                with c1:
                    if st.button("✅ Approve Transfer", key=f"approve_transfer_{serial}_{i}"):
                        _approve_transfer_row(row)
                        st.rerun()
                with c2:
                    if st.button("❌ Reject Transfer", key=f"reject_transfer_{serial}_{i}"):
                        _reject_row(PENDING_TRANSFER_WS, row)
                        st.rerun()

def _reject_row(ws_title: str, row: pd.Series):
    df = read_worksheet(ws_title)

    # Identify the row
    key_cols = [c for c in ["Serial Number", "Submitted at", "Submitted by", "To owner"] if c in df.columns]
    mask = pd.Series([True] * len(df))
    for c in key_cols:
        mask &= df[c].astype(str) == str(row.get(c, ""))
    idxs = df[mask].index.tolist()

    if not idxs and "Serial Number" in df.columns:
        idxs = df[df["Serial Number"].astype(str) == str(row.get("Serial Number", ""))].index.tolist()
    if not idxs:
        st.warning("Could not locate row to mark as Rejected.")
        return

    idx = idxs[0]

    # Update status in sheet
    df.loc[idx, "Approval Status"] = "Rejected"
    df.loc[idx, "Approver"] = st.session_state.get("username", "")
    df.loc[idx, "Decision at"] = datetime.now().strftime(DATE_FMT)
    write_worksheet(ws_title, df)

    # Attempt to move the existing file in Drive
    try:
        action = "Register" if ws_title == PENDING_DEVICE_WS else "Transfer"
        file_id = str(row.get("Approval File ID", "")).strip()
        serial = str(row.get("Serial Number", "")).strip()

        if not serial or not file_id:
            return

        # Lookup employee/project/location
        if action == "Register":
            emp_df = read_worksheet(EMPLOYEE_WS)
            emp_row = _get_employee_row_by_name(emp_df, row.get("Current user", ""))
            project = emp_row.get("Project", "HO")
            location = emp_row.get("Location (KSA)", "JED")
        else:
            inv = read_worksheet(INVENTORY_WS)
            inv_row = inv[inv["Serial Number"].astype(str) == serial]
            if inv_row.empty:
                st.warning("Could not determine project/location from inventory for rejection.")
                return
            inv_row = inv_row.iloc[0].to_dict()
            project = inv_row.get("Project", "HO")
            location = inv_row.get("Location", "JED")

        # ✅ Move the existing PDF into Rejected folder
        move_drive_file(
            file_id=file_id,
            project=project,
            location=location,
            action=action,
            status="Rejected",
            serial=serial,
            order_no="0000",  # dummy order number for rejection
        )

    except Exception as e:
        st.warning(f"Rejected, but couldn’t move PDF in Drive: {e}")

    st.success("❌ Request rejected. PDF moved under Rejected for evidence.")




# =========================
# Export Tab
# =========================
def export_tab():
    st.subheader("⬇️ Export Data")
    sheets = {
        "Inventory": INVENTORY_WS,
        "Employees": EMPLOYEE_WS,
        "Transfer Log": TRANSFERLOG_WS,
        "Pending Device Registrations": PENDING_DEVICE_WS,
        "Pending Transfers": PENDING_TRANSFER_WS,
    }
    choice = st.selectbox("Select sheet to export", list(sheets.keys()))
    if not choice:
        st.info("Please select a sheet.")
        return
    df = read_worksheet(sheets[choice])
    if df.empty:
        st.info("No data available to export.")
        return

    today_str = datetime.now().strftime('%Y%m%d')
    filename_base = f"{choice.replace(' ', '_').lower()}_{today_str}"

    csv_data = df.to_csv(index=False).encode("utf-8")
    st.download_button(
        label=f"📥 Download {choice} as CSV",
        data=csv_data,
        file_name=f"{filename_base}.csv",
        mime="text/csv",
    )

    excel_buf = io.BytesIO()
    with pd.ExcelWriter(excel_buf, engine="xlsxwriter") as writer:
        df.to_excel(writer, sheet_name=choice[:31], index=False)
        workbook = writer.book
        worksheet = writer.sheets[choice[:31]]
        for i, col in enumerate(df.columns):
            col_width = max(15, df[col].astype(str).str.len().max())
            worksheet.set_column(i, i, col_width)

    st.download_button(
        label=f"📥 Download {choice} as Excel",
        data=excel_buf.getvalue(),
        file_name=f"{filename_base}.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )
    st.success("✅ Data ready for export.")


# =========================
# Header, run_app, entry point
# =========================

def render_header():
c_title, c_user = st.columns([7, 3], gap="small")
with c_title:
st.markdown(f"### {APP_TITLE}")
st.caption(SUBTITLE)
with c_user:
username = st.session_state.get("username", "—")
role = st.session_state.get("role", "—")
st.markdown(f"**User:** {username} &nbsp;&nbsp;&nbsp; **Role:** {role}")
if st.session_state.get("authenticated") and st.button("Logout"):
do_logout()
st.markdown("---")

def run_app():
render_header()
_config_check_ui()
role = st.session_state.get("role", "").strip()
if role == "Admin":
tabs = st.tabs(["🧑‍💼 Employee Register", "📇 View Employees", "📝 Register Device",
"📋 View Inventory", "🔁 Transfer Device", "📜 Transfer Log", "✅ Approvals", "⬇️ Export"])
with tabs[0]: employee_register_tab()
with tabs[1]: employees_view_tab()
with tabs[2]: register_device_tab()
with tabs[3]: inventory_tab()
with tabs[4]: transfer_tab()
with tabs[5]: history_tab()
with tabs[6]: approvals_tab()
with tabs[7]: export_tab()
else:
tabs = st.tabs(["📝 Register Device", "🔁 Transfer Device", "📋 View Inventory", "📜 Transfer Log"])
with tabs[0]: register_device_tab()
with tabs[1]: transfer_tab()
with tabs[2]: inventory_tab()
with tabs[3]: history_tab()

st.session_state.setdefault("authenticated", False)
st.session_state.setdefault("just_logged_out", False)
if not st.session_state.authenticated and not st.session_state.just_logged_out:
payload = _read_cookie()
if payload:
st.session_state.authenticated = True
st.session_state.username = payload.get("u", "")
st.session_state.role = payload.get("r", "Staff")
if st.session_state.authenticated:
run_app()
else:
st.subheader("🔐 Sign In")
with st.form("login_form"):
username = st.text_input("Username", placeholder="Enter your username", key="login_user")
password = st.text_input("Password", type="password", placeholder="Enter your password", key="login_pass")
login_btn = st.form_submit_button("Login", type="primary")
if login_btn:
user = USERS.get(username)
if user and _verify_password(password, user.get("password", "")):
do_login(username, user.get("role", "Staff"))
else:
st.error("❌ Invalid username or password.")
