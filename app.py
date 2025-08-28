import os, re, glob, base64, json, hmac, hashlib, time, io
from datetime import datetime, timedelta

import pandas as pd
import requests

import streamlit as st
st.set_page_config(page_title="Tracking Inventory Management System", layout="wide")

import gspread
from gspread_dataframe import set_with_dataframe
import extra_streamlit_components as stx
from streamlit import session_state as ss
from streamlit_pdf_viewer import pdf_viewer

from google.oauth2.service_account import Credentials
from google.oauth2.credentials import Credentials as UserCredentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload
from googleapiclient.errors import HttpError

from PyPDF2 import PdfReader, PdfWriter
from PyPDF2.generic import NameObject, DictionaryObject, BooleanObject

# =============================================================================
# CONFIG
# =============================================================================
APP_TITLE = "Tracking Inventory Management System"
SUBTITLE  = "Advanced Construction"
DATE_FMT  = "%Y-%m-%d %H:%M:%S"

INVENTORY_WS    = "truckinventory"
TRANSFERLOG_WS  = "transfer_log"
EMPLOYEE_WS     = "mainlists"
PENDING_DEVICE_WS    = "pending_device_reg"
PENDING_TRANSFER_WS  = "pending_transfers"

INVENTORY_COLS = [
    "Serial Number","Device Type","Brand","Model","CPU",
    "Hard Drive 1","Hard Drive 2","Memory","GPU","Screen Size",
    "Current user","Previous User","TO",
    "Department","Email Address","Contact Number","Location","Office",
    "Notes","Date issued","Registered by"
]
LOG_COLS = ["Device Type","Serial Number","From owner","To owner","Date issued","Registered by"]
APPROVAL_META_COLS = [
    "Approval Status","Approval PDF","Approval File ID",
    "Submitted by","Submitted at","Approver","Decision at"
]

COOKIE_MGR = stx.CookieManager(key="ac_cookie_mgr")

def get_pdf_template_bytes() -> bytes:
    tpl_id = st.secrets.get("drive", {}).get("template_file_id", "")
    if not tpl_id:
        st.error("Template form file id/url not configured in secrets.")
        return b""
    try:
        url = f"https://drive.google.com/uc?export=download&id={tpl_id}"
        r = requests.get(url, timeout=30)
        if r.ok and r.content[:4] == b"%PDF":
            return r.content
    except Exception as e:
        st.error(f"Error fetching template: {e}")
    return b""

def fill_pdf_form(template_bytes: bytes, values: dict[str, str]) -> bytes:
    reader = PdfReader(io.BytesIO(template_bytes))
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)
    writer.update_page_form_field_values(writer.pages[0], values)
    if "/AcroForm" in reader.trailer["/Root"]:
        writer._root_object.update({
            NameObject("/AcroForm"): DictionaryObject({
                NameObject("/NeedAppearances"): BooleanObject(False)
            })
        })
    out = io.BytesIO()
    writer.write(out)
    out.seek(0)
    return out.read()

def make_form_filename(action: str, serial: str, counter: int = 1) -> str:
    today = datetime.now().strftime("%Y%m%d")
    return f"HO-JED-{action}-{serial}-{counter:04d}-{today}.pdf"

def get_sh():
    gc = gspread.authorize(_get_creds())
    url = st.secrets.get("sheets", {}).get("url", "")
    return gc.open_by_url(url)

def read_worksheet(ws_title):
    sh = get_sh()
    try:
        ws = sh.worksheet(ws_title)
        df = pd.DataFrame(ws.get_all_records())
        return df
    except gspread.exceptions.WorksheetNotFound:
        return pd.DataFrame()

def write_worksheet(ws_title, df):
    sh = get_sh()
    try:
        ws = sh.worksheet(ws_title)
    except gspread.exceptions.WorksheetNotFound:
        ws = sh.add_worksheet(title=ws_title, rows=500, cols=50)
    ws.clear()
    set_with_dataframe(ws, df)

def append_to_worksheet(ws_title, df_new):
    df_existing = read_worksheet(ws_title)
    df_out = pd.concat([df_existing, df_new], ignore_index=True)
    write_worksheet(ws_title, df_out)

def unique_nonempty(df: pd.DataFrame, col: str) -> list[str]:
    if df.empty or col not in df.columns:
        return []
    vals = [str(x).strip() for x in df[col].dropna().astype(str).tolist()]
    return sorted({v for v in vals if v})

def get_device_from_inventory(serial: str) -> dict:
    df = read_worksheet(INVENTORY_WS)
    if df.empty:
        return {}
    df["Serial Number"] = df["Serial Number"].astype(str).str.strip().str.upper()
    match = df[df["Serial Number"] == serial.upper()]
    if not match.empty:
        return match.iloc[0].to_dict()
    return {}

def get_employee_names() -> list[str]:
    df = read_worksheet(EMPLOYEE_WS)
    return sorted({
        *unique_nonempty(df, "New Employeer"),
        *unique_nonempty(df, "Name"),
    })

def register_device_tab():
    st.subheader("📝 Register New Device")

    emp_names = get_employee_names()

    with st.form("register_device", clear_on_submit=True):
        serial = st.text_input("Serial Number *")
        current_user = st.selectbox("Assign to Current User", ["— Select —"] + emp_names)
        pdf_file = st.file_uploader("Signed ICT Form (PDF)", type=["pdf"], key="reg_pdf")
        submitted = st.form_submit_button("Submit for Approval", type="primary")

    device_info = {}
    if serial.strip():
        device_info = get_device_from_inventory(serial.strip())
        if device_info:
            st.success("Device info auto-filled from Inventory.")
            st.json(device_info)

            tpl_bytes = get_pdf_template_bytes()
            if tpl_bytes:
                field_map = {
                    "Text Field0": device_info.get("Device Type",""),
                    "Text Field1": device_info.get("Brand",""),
                    "Text Field2": device_info.get("Model",""),
                    "Text Field3": device_info.get("CPU",""),
                    "Text Field4": device_info.get("Memory",""),
                    "Text Field5": device_info.get("Hard Drive 1",""),
                    "Text Field6": device_info.get("Hard Drive 2",""),
                    "Text Field7": device_info.get("GPU",""),
                    "Text Field8": device_info.get("Screen Size",""),
                    "Text Field9": serial.strip(),
                    "Text Field10": current_user if current_user != "— Select —" else "",
                }
                filled_pdf = fill_pdf_form(tpl_bytes, field_map)
                fname = make_form_filename("REG", serial.strip(), counter=1)
                st.download_button("🖨️ Download ICT Form", filled_pdf, file_name=fname, mime="application/pdf")

    if submitted:
        if not device_info:
            st.error("Serial not found in Inventory.")
            return
        if current_user == "— Select —":
            st.error("Please select a Current User.")
            return
        if not pdf_file:
            st.error("Signed ICT Form required.")
            return

        now_str = datetime.now().strftime(DATE_FMT)
        actor   = st.session_state.get("username", "")

        row = {**device_info,
               "Current user": current_user.strip(),
               "Previous User": "",
               "TO": "",
               "Date issued": now_str,
               "Registered by": actor,
        }

        link, fid = upload_pdf_and_link(pdf_file, prefix=f"device_{serial}")
        if not fid:
            return

        pending = {**row,
            "Approval Status": "Pending",
            "Approval PDF": link,
            "Approval File ID": fid,
            "Submitted by": actor,
            "Submitted at": now_str,
            "Approver": "",
            "Decision at": "",
        }
        append_to_worksheet(PENDING_DEVICE_WS, pd.DataFrame([pending]))
        st.success("🕒 Submitted for admin approval.")

def transfer_tab():
    st.subheader("🔁 Transfer Device")

    inv_df = read_worksheet(INVENTORY_WS)
    if inv_df.empty:
        st.warning("Inventory is empty.")
        return

    # Serial from Inventory
    serials = sorted(inv_df["Serial Number"].dropna().astype(str).unique())
    c1, c2 = st.columns([2, 2])
    with c1:
        chosen_serial = st.selectbox("Serial Number", ["— Select —"] + serials)
        chosen_serial = None if chosen_serial == "— Select —" else chosen_serial
    with c2:
        # New owner from Employees sheet
        emp_names = get_employee_names()
        new_owner = st.selectbox("New Owner (from Employees)", ["— Select —"] + emp_names)

    # Show snapshot for the selected serial
    device_row = {}
    if chosen_serial:
        match = inv_df[inv_df["Serial Number"].astype(str) == chosen_serial]
        if not match.empty:
            device_row = match.iloc[0].to_dict()
            st.caption("Current device details")
            st.json({k: device_row.get(k, "") for k in [
                "Device Type","Brand","Model","CPU","Memory","Hard Drive 1",
                "Hard Drive 2","GPU","Screen Size","Current user"
            ]})

    # Optional: offer an auto-filled transfer PDF (NOT signed yet)
    if chosen_serial and new_owner and new_owner != "— Select —":
        tpl = get_pdf_template_bytes()
        if tpl:
            # ⚠️ Map these to your PDF's actual field names
            field_map = {
                "Text Field0": device_row.get("Device Type", ""),
                "Text Field1": device_row.get("Brand", ""),
                "Text Field2": device_row.get("Model", ""),
                "Text Field3": device_row.get("CPU", ""),
                "Text Field4": device_row.get("Memory", ""),
                "Text Field5": device_row.get("Hard Drive 1", ""),
                "Text Field6": device_row.get("Hard Drive 2", ""),
                "Text Field7": device_row.get("GPU", ""),
                "Text Field8": device_row.get("Screen Size", ""),
                "Text Field9": chosen_serial,       # Serial
                "Text Field10": new_owner,          # To owner
            }
            trf_pdf = fill_pdf_form(tpl, field_map)
            st.download_button(
                "🖨️ Download Transfer ICT Form (auto-filled)",
                trf_pdf,
                file_name=make_form_filename("TRF", re.sub(r"[^A-Z0-9]","",str(chosen_serial).upper()), counter=1),
                mime="application/pdf",
                key=f"dl_trf_{chosen_serial}"
            )
            st.caption("Download → sign → upload the signed PDF below.")

    # Upload signed transfer PDF and submit for approval
    signed_pdf = st.file_uploader("Signed ICT Transfer Form (PDF)", type=["pdf"], key="transfer_pdf")
    submit = st.button(
        "Submit Transfer for Approval",
        type="primary",
        disabled=not (chosen_serial and new_owner and new_owner != "— Select —" and signed_pdf)
    )

    if submit:
        if chosen_serial is None:
            st.error("Please pick a Serial Number.")
            return
        if new_owner == "— Select —":
            st.error("Please choose the New Owner from Employees.")
            return
        if not signed_pdf:
            st.error("Signed ICT Transfer Form is required.")
            return

        actor   = st.session_state.get("username", "")
        now_str = datetime.now().strftime(DATE_FMT)

        link, fid = upload_pdf_and_link(signed_pdf, prefix=f"transfer_{re.sub(r'[^A-Z0-9]','',chosen_serial.upper())}")
        if not fid:
            return

        prev_user = str(device_row.get("Current user", "")) if device_row else ""
        pend = {
            "Device Type": device_row.get("Device Type",""),
            "Serial Number": chosen_serial,
            "From owner": prev_user,
            "To owner": new_owner.strip(),
            "Date issued": now_str,
            "Registered by": actor,
            "Approval Status": "Pending",
            "Approval PDF": link,
            "Approval File ID": fid,
            "Submitted by": actor,
            "Submitted at": now_str,
            "Approver": "",
            "Decision at": "",
        }
        append_to_worksheet(PENDING_TRANSFER_WS, pd.DataFrame([pend]))
        st.success("🕒 Transfer submitted for admin approval.")
# ----------------------- Approvals helpers -----------------------

def _mark_decision(ws_title: str, row: pd.Series, *, status: str):
    df = read_worksheet(ws_title)
    if df.empty:
        return
    # match by serial + submitted metadata
    mask = (df.get("Serial Number","").astype(str) == str(row.get("Serial Number","")))
    if "Submitted at" in df.columns:
        mask &= (df["Submitted at"].astype(str) == str(row.get("Submitted at","")))
    idxs = df[mask].index.tolist()
    if not idxs:
        return
    idx = idxs[0]
    df.loc[idx, "Approval Status"] = status
    df.loc[idx, "Approver"] = st.session_state.get("username", "")
    df.loc[idx, "Decision at"] = datetime.now().strftime(DATE_FMT)
    write_worksheet(ws_title, df)

def _approve_device_row(row: pd.Series):
    """Apply device registration (set Current user on the Inventory row for this Serial)."""
    inv = read_worksheet(INVENTORY_WS)
    sn = str(row.get("Serial Number",""))
    match = inv[inv["Serial Number"].astype(str) == sn]
    now_str = datetime.now().strftime(DATE_FMT)
    approver = st.session_state.get("username", "")

    if match.empty:
        # If not present, create a new row using the registration payload
        new_row = {k: row.get(k, "") for k in INVENTORY_COLS}
        new_row["Date issued"] = now_str
        new_row["Registered by"] = approver
        inv_out = pd.concat([inv, pd.DataFrame([new_row])], ignore_index=True)
        write_worksheet(INVENTORY_WS, inv_out)
    else:
        idx = match.index[0]
        # Update assignment, keep device specs as in Inventory
        inv.loc[idx, "Previous User"] = str(inv.loc[idx, "Current user"] or "")
        inv.loc[idx, "Current user"]  = str(row.get("Current user",""))
        inv.loc[idx, "TO"]            = ""  # only used on transfer
        inv.loc[idx, "Date issued"]   = now_str
        inv.loc[idx, "Registered by"] = approver
        write_worksheet(INVENTORY_WS, inv)

    _mark_decision(PENDING_DEVICE_WS, row, status="Approved")
    st.success("✅ Device registration approved and applied to Inventory.")

def _approve_transfer_row(row: pd.Series):
    """Apply transfer on Inventory and append to log."""
    inv = read_worksheet(INVENTORY_WS)
    sn = str(row.get("Serial Number",""))
    match = inv[inv["Serial Number"].astype(str) == sn]
    if match.empty:
        st.error("Serial not found in Inventory.")
        return

    idx = match.index[0]
    now_str = datetime.now().strftime(DATE_FMT)
    approver = st.session_state.get("username", "")

    prev_user = str(inv.loc[idx, "Current user"] or "")
    inv.loc[idx, "Previous User"] = prev_user
    inv.loc[idx, "Current user"]  = str(row.get("To owner",""))
    inv.loc[idx, "TO"]            = str(row.get("To owner",""))
    inv.loc[idx, "Date issued"]   = now_str
    inv.loc[idx, "Registered by"] = approver
    write_worksheet(INVENTORY_WS, inv)

    log_row = {
        "Device Type": inv.loc[idx, "Device Type"],
        "Serial Number": sn,
        "From owner": prev_user,
        "To owner": str(row.get("To owner","")),
        "Date issued": now_str,
        "Registered by": approver,
    }
    append_to_worksheet(TRANSFERLOG_WS, pd.DataFrame([log_row]))

    _mark_decision(PENDING_TRANSFER_WS, row, status="Approved")
    st.success("✅ Transfer approved and applied.")

def _reject_row(ws_title: str, row: pd.Series):
    _mark_decision(ws_title, row, status="Rejected")
    st.info("❌ Request rejected.")

# ----------------------- Approvals UI -----------------------

REQUIRE_REVIEW_CHECK = True  # keep gate in UI

def approvals_tab():
    st.subheader("✅ Approvals (Admin)")
    if st.session_state.get("role") != "Admin":
        st.info("Only Admins can view approvals.")
        return

    # Pending Device Registrations
    pend_dev = read_worksheet(PENDING_DEVICE_WS)
    st.markdown("### Pending Device Registrations")
    df_dev = pend_dev[pend_dev.get("Approval Status","").astype(str).isin(["", "Pending"])] if not pend_dev.empty else pd.DataFrame()
    if df_dev.empty:
        st.success("No pending device registrations.")
    else:
        for i, r in df_dev.reset_index(drop=True).iterrows():
            with st.expander(f"SN {r['Serial Number']} → {r.get('Current user','')}  (by {r.get('Submitted by','')})", expanded=False):
                c1, c2 = st.columns([3,2])
                with c1:
                    st.json({k: r.get(k, "") for k in INVENTORY_COLS})
                    # Inline PDF preview (best-effort)
                    try:
                        pdf_bytes = _fetch_public_pdf_bytes(r.get("Approval File ID",""), r.get("Approval PDF",""))
                        if pdf_bytes:
                            st.caption("Approval PDF Preview")
                            pdf_viewer(input=pdf_bytes, width=700, key=f"viewer_dev_{i}")
                        elif r.get("Approval PDF"):
                            st.markdown(f"[Open Approval PDF]({r['Approval PDF']})")
                    except Exception:
                        pass
                with c2:
                    pdf_ok = bool(r.get("Approval File ID")) and bool(r.get("Approval PDF"))
                    if not pdf_ok:
                        st.error("⚠️ No signed ICT Equipment Form attached. Cannot approve.")
                    reviewed = True
                    if REQUIRE_REVIEW_CHECK:
                        reviewed = st.checkbox("I reviewed the attached PDF", key=f"review_dev_{i}")
                    a_col, r_col = st.columns(2)
                    if a_col.button("Approve", key=f"approve_dev_{i}", disabled=not (reviewed and pdf_ok)):
                        _approve_device_row(r)
                    if r_col.button("Reject", key=f"reject_dev_{i}"):
                        _reject_row(PENDING_DEVICE_WS, r)

    st.markdown("---")

    # Pending Transfers
    pend_tr = read_worksheet(PENDING_TRANSFER_WS)
    st.markdown("### Pending Transfers")
    df_tr = pend_tr[pend_tr.get("Approval Status","").astype(str).isin(["", "Pending"])] if not pend_tr.empty else pd.DataFrame()
    if df_tr.empty:
        st.success("No pending transfers.")
    else:
        for i, r in df_tr.reset_index(drop=True).iterrows():
            with st.expander(f"SN {r['Serial Number']}: {r.get('From owner','')} → {r.get('To owner','')} (by {r.get('Submitted by','')})", expanded=False):
                c1, c2 = st.columns([3,2])
                with c1:
                    st.json({k: r.get(k, "") for k in LOG_COLS})
                    try:
                        pdf_bytes = _fetch_public_pdf_bytes(r.get("Approval File ID",""), r.get("Approval PDF",""))
                        if pdf_bytes:
                            st.caption("Approval PDF Preview")
                            pdf_viewer(input=pdf_bytes, width=700, key=f"viewer_tr_{i}")
                        elif r.get("Approval PDF"):
                            st.markdown(f"[Open Approval PDF]({r['Approval PDF']})")
                    except Exception:
                        pass
                with c2:
                    pdf_ok = bool(r.get("Approval File ID")) and bool(r.get("Approval PDF"))
                    if not pdf_ok:
                        st.error("⚠️ No signed ICT Equipment Form attached. Cannot approve.")
                    reviewed = True
                    if REQUIRE_REVIEW_CHECK:
                        reviewed = st.checkbox("I reviewed the attached PDF", key=f"review_tr_{i}")
                    a_col, r_col = st.columns(2)
                    if a_col.button("Approve", key=f"approve_tr_{i}", disabled=not (reviewed and pdf_ok)):
                        _approve_transfer_row(r)
                    if r_col.button("Reject", key=f"reject_tr_{i}"):
                        _reject_row(PENDING_TRANSFER_WS, r)

# ----------------------- Main runner & entry -----------------------

def run_app():
    st.markdown(f"### {APP_TITLE}"); st.caption(SUBTITLE)

    tabs = st.tabs([
        "📝 Register Device",
        "🔁 Transfer Device",
        "✅ Approvals",
    ])
    with tabs[0]: register_device_tab()
    with tabs[1]: transfer_tab()
    with tabs[2]: approvals_tab()

# Entry
if __name__ == "__main__" or True:
    run_app()
