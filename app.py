# # app.py — Tracking Inventory System (Streamlit)
# # ✅ Tabs order: 1) 📝 Register Inventory, 2) 📦 View Inventory, 3) 🔄 Transfer Device, 4) 📜 View Transfer Log, 5) ⬇ Export Files
# # ✅ Register tab saves directly to main inventory (truckinventory.xlsx)
# # ✅ Auto-switch to "View Inventory" after saving (JS helper + session flag)
# # ✅ Clean header + easy knobs (logo size/placement, fonts, spacing)
# # ✅ Logout row UNDER the header (right-aligned)
# # ✅ Persistent login across refresh (signed token using st.query_params)
# # ✅ Arrow-safe display for mixed-type columns
# # ✅ No deprecated API calls

# import streamlit as st
# import streamlit.components.v1 as components  # ← for tab auto-switch helper
# import pandas as pd
# import numpy as np
# from datetime import datetime
# from io import BytesIO
# import json
# import os
# import shutil
# import base64
# import hmac
# import hashlib

# # ============================
# # 🔧 EASY CONTROLS — Tweak these
# # ============================
# APP_TITLE        = "Tracking Inventory Management System"           # ← Title text
# APP_TAGLINE      = "Advanced Construction"                           # ← Subtitle text
# FONT_FAMILY      = "Times New Roman"                                # ← Global font (system-safe)
# TOP_PADDING_REM  = 2                                                # ← Space from very top of page
# MAX_CONTENT_W    = 1400                                             # ← Page max width (px)

# # --- Logo controls ---
# LOGO_FILE        = "assets/company_logo.jpeg"                       # ← Path to logo image
# LOGO_WIDTH_PX    = 500                                              # ← Logo width in px (try 120–420)
# LOGO_HEIGHT_PX   = 80                                               # ← Set an int (e.g., 60/80) or None to auto
# LOGO_ALT_EMOJI   = "🖥️"                                             # ← Fallback if file missing

# # --- Title & tagline sizing ---
# TITLE_SIZE_PX    = 46                                               # ← Title font-size (px)
# TAGLINE_SIZE_PX  = 16                                               # ← Tagline font-size (px)

# # --- Spacing around header ---
# GAP_BELOW_HEADER_PX = 16                                            # ← Space below header divider
# LOGOUT_ROW_TOP_MARG = 8                                             # ← Top margin (px) before Logout row

# # --- Favicon (optional) ---
# ICON_FILE        = "assets/favicon.png"                             # ← Path to favicon (or leave missing)

# # --- Security / Login persistence ---
# # Put these in .streamlit/secrets.toml for production:
# # auth_secret = "a-very-long-random-string"
# # users_json = '[{"username":"admin","password":"123","role":"admin"}]'
# AUTH_SECRET      = st.secrets.get("auth_secret", "change-me")       # ← Replace in secrets for production

# # ============================
# # STREAMLIT PAGE CONFIG
# # ============================
# st.set_page_config(
#     page_title="Tracking Inventory System",
#     page_icon=ICON_FILE if os.path.exists(ICON_FILE) else LOGO_ALT_EMOJI,
#     layout="wide",
#     initial_sidebar_state="collapsed",
# )

# # ============================
# # GLOBAL CSS (uses the knobs above)
# # ============================
# st.markdown(f"""
# <style>
# /* Global font */
# html, body, .stApp, .stApp * {{
#   font-family: "{FONT_FAMILY}", Times, serif !important;
# }}

# /* Hide the sidebar completely */
# [data-testid="stSidebar"] {{ display: none !important; }}

# /* Page container padding & width */
# .block-container {{
#   padding-top: {TOP_PADDING_REM}rem;      /* ← change TOP_PADDING_REM above */
#   max-width: {MAX_CONTENT_W}px;           /* ← change MAX_CONTENT_W above */
# }}

# .brand-title {{
#   font-weight: 700;
#   font-size: {TITLE_SIZE_PX}px;           /* ← change TITLE_SIZE_PX above */
#   margin: 0;
#   line-height: 1.1;
# }}
# .brand-tag {{
#   margin: 2px 0 0;
#   color: #64748b;
#   font-weight: 400;
#   font-size: {TAGLINE_SIZE_PX}px;         /* ← change TAGLINE_SIZE_PX above */
# }}

# .header-divider {{
#   height: 1px;
#   background: #e5e7eb;
#   margin: 10px 0 {GAP_BELOW_HEADER_PX}px; /* ← change GAP_BELOW_HEADER_PX above */
# }}

# .logout-row {{ margin-top: {LOGOUT_ROW_TOP_MARG}px; }}  /* ← change LOGOUT_ROW_TOP_MARG above */

# /* Button sizing/shape consistent with Streamlit toolbar */
# .stButton > button {{
#   height: 38px;
#   padding: 0 .9rem;
#   border-radius: 8px;
#   font-weight: 600;
# }}
# .logout-col .stButton > button {{
#   background: #f3f4f6;
#   color: #111827;
#   border: 1px solid #e5e7eb;
# }}
# .logout-col .stButton > button:hover {{ background: #e5e7eb; }}

# /* Tiny breathing room for tabs & subheaders */
# .stTabs {{ margin-top: 6px; }}
# section[tabindex="0"] h2 {{ margin-top: 8px; }}

# #MainMenu, footer {{ visibility: hidden; }}
# </style>
# """, unsafe_allow_html=True)

# # ============================
# # SESSION DEFAULTS
# # ============================
# if "authenticated" not in st.session_state:
#     st.session_state["authenticated"] = False
# if "role" not in st.session_state:
#     st.session_state["role"] = None
# if "username" not in st.session_state:
#     st.session_state["username"] = ""

# # ============================
# # USERS (from secrets)
# # ============================
# try:
#     USERS = json.loads(st.secrets["users_json"])
# except Exception:
#     st.error(
#         "Missing `users_json` in secrets. Example: "
#         '`[{"username":"admin","password":"123","role":"admin"}]`'
#     )
#     st.stop()

# def get_user_role(username: str):
#     for u in USERS:
#         if u.get("username") == username:
#             return u.get("role")
#     return None

# # ============================
# # URL TOKEN (persistent login across refresh)
# # ============================
# def make_token(username: str) -> str:
#     return hmac.new(
#         AUTH_SECRET.encode("utf-8"),
#         msg=username.encode("utf-8"),
#         digestmod=hashlib.sha256
#     ).hexdigest()

# def set_auth_query_params(username: str):
#     st.query_params.clear()
#     st.query_params.update({"u": username, "t": make_token(username)})

# def clear_auth_query_params():
#     st.query_params.clear()

# def try_auto_login_from_url():
#     if st.session_state.get("authenticated"):
#         return
#     params = st.query_params
#     u = params.get("u")
#     t = params.get("t")
#     if not u or not t:
#         return
#     if hmac.compare_digest(t, make_token(u)):
#         role = get_user_role(u)
#         if role:
#             st.session_state["authenticated"] = True
#             st.session_state["username"] = u
#             st.session_state["role"] = role

# try_auto_login_from_url()

# # ============================
# # SMALL UTILS
# # ============================
# def img_to_base64(path: str) -> str | None:
#     if os.path.exists(path):
#         with open(path, "rb") as f:
#             return base64.b64encode(f.read()).decode("utf-8")
#     return None

# def logo_html(src_path: str, width_px: int, height_px: int | None, alt_emoji: str) -> str:
#     """
#     Renders logo with exact width/height via HTML (so you can control BOTH).
#     - Set height_px to None to keep aspect ratio (auto height).
#     """
#     b64 = img_to_base64(src_path)
#     if not b64:
#         return f"<div style='font-size:{int(width_px*0.7)}px;line-height:1'>{alt_emoji}</div>"
#     h_style = f"height:{height_px}px;" if height_px else ""
#     return f"<img src='data:image/png;base64,{b64}' alt='logo' style='width:{width_px}px;{h_style}display:block;'/>"

# # Arrow-safe display-only copy (keeps NaN empty, casts to str)
# def for_display(df: pd.DataFrame) -> pd.DataFrame:
#     if df is None or df.empty:
#         return df
#     out = df.copy()
#     out = out.replace({np.nan: ""})
#     for c in out.columns:
#         out[c] = out[c].astype(str)
#     return out

# # === JS helper: click a tab by its visible text (used to jump to "View Inventory") ===
# def _switch_to_tab_by_text(partial_label: str):
#     """Client-side: click the tab whose label contains the given text."""
#     components.html(
#         f"""
#         <script>
#         const wanted = {json.dumps(partial_label)};
#         function clickTab() {{
#           const root = window.parent.document;
#           const tabs = root.querySelectorAll('button[role="tab"]');
#           for (const t of tabs) {{
#             if ((t.innerText || "").trim().includes(wanted)) {{
#               t.click();
#               return;
#             }}
#           }}
#           setTimeout(clickTab, 60); // try again if tabs not ready
#         }}
#         clickTab();
#         </script>
#         """,
#         height=0,
#     )

# # ============================
# # HEADER (row1: logo+title, row2: logout right)
# # ============================
# def show_header():
#     # Row 1 — Logo + Text
#     c_logo, c_text = st.columns([0.16, 0.84])
#     with c_logo:
#         st.markdown(logo_html(LOGO_FILE, LOGO_WIDTH_PX, LOGO_HEIGHT_PX, LOGO_ALT_EMOJI), unsafe_allow_html=True)
#     with c_text:
#         st.markdown(
#             f"<h1 class='brand-title'>{APP_TITLE}</h1>"
#             f"<div class='brand-tag'>{APP_TAGLINE}</div>",
#             unsafe_allow_html=True
#         )

#     # Row 2 — Logout (right-aligned, below header)
#     s, btn = st.columns([0.85, 0.15])
#     with btn:
#         st.markdown("<div class='logout-col logout-row'>", unsafe_allow_html=True)
#         if st.session_state.get("authenticated"):
#             if st.button("Logout", use_container_width=True, key="logout_btn"):
#                 st.session_state["authenticated"] = False
#                 st.session_state["role"] = None
#                 st.session_state["username"] = ""
#                 clear_auth_query_params()
#                 st.rerun()
#         st.markdown("</div>", unsafe_allow_html=True)

#     # Divider under both rows
#     st.markdown('<div class="header-divider"></div>', unsafe_allow_html=True)

# show_header()

# # ============================
# # FILES & HELPERS
# # ============================
# INVENTORY_FILE         = "truckinventory.xlsx"                      # ← MAIN INVENTORY FILE
# TRANSFER_LOG_PRIMARY   = "transferlog.xlsx"
# TRANSFER_LOG_ALT       = "transferlogin.xlsx"
# TRANSFER_LOG_FILE      = TRANSFER_LOG_PRIMARY if os.path.exists(TRANSFER_LOG_PRIMARY) else (
#                          TRANSFER_LOG_ALT if os.path.exists(TRANSFER_LOG_ALT) else TRANSFER_LOG_PRIMARY)

# BACKUP_FOLDER          = "backups"
# os.makedirs(BACKUP_FOLDER, exist_ok=True)

# # --- Required hardware columns for Register tab ---
# HW_COLUMNS = [
#     "Serial Number", "Device Type", "Brand", "Model", "CPU",
#     "Hard Drive 1", "Hard Drive 2", "Memory", "GPU", "Screen Size"
# ]
# # Meta columns already used elsewhere in app
# META_COLUMNS = ["USER", "Previous User", "TO", "Date issued", "Registered by"]
# ALL_INVENTORY_COLUMNS = HW_COLUMNS + META_COLUMNS

# def backup_file(file_path):
#     if os.path.exists(file_path):
#         base = os.path.basename(file_path).split(".")[0]
#         ts = datetime.now().strftime("%Y%m%d_%H%M%S")
#         shutil.copy(file_path, f"{BACKUP_FOLDER}/{base}_{ts}.xlsx")

# def ensure_inventory_file():
#     if not os.path.exists(INVENTORY_FILE):
#         pd.DataFrame(columns=ALL_INVENTORY_COLUMNS).to_excel(INVENTORY_FILE, index=False)

# def ensure_transfer_log_file():
#     if not os.path.exists(TRANSFER_LOG_FILE):
#         cols = ["Device Type", "Serial Number", "From owner", "To owner", "Date issued", "Registered by"]
#         pd.DataFrame(columns=cols).to_excel(TRANSFER_LOG_FILE, index=False)

# def load_inventory() -> pd.DataFrame:
#     ensure_inventory_file()
#     df = pd.read_excel(INVENTORY_FILE)
#     # Auto-add any missing columns to existing file
#     for col in ALL_INVENTORY_COLUMNS:
#         if col not in df.columns:
#             df[col] = ""
#     # Re-order columns nicely (hardware first, then meta, then any extras)
#     ordered = [c for c in ALL_INVENTORY_COLUMNS if c in df.columns] + \
#               [c for c in df.columns if c not in ALL_INVENTORY_COLUMNS]
#     df = df[ordered]
#     return df

# def load_transfer_log() -> pd.DataFrame:
#     ensure_transfer_log_file()
#     return pd.read_excel(TRANSFER_LOG_FILE)

# def save_inventory(df: pd.DataFrame):
#     backup_file(INVENTORY_FILE)
#     df.to_excel(INVENTORY_FILE, index=False)

# def save_transfer_log(df: pd.DataFrame):
#     backup_file(TRANSFER_LOG_FILE)
#     df.to_excel(TRANSFER_LOG_FILE, index=False)

# # === Helper: SAVE TO MAIN INVENTORY (used by Register tab) ===
# def add_inventory_item(item: dict) -> tuple[bool, str]:
#     """
#     Append one item to the main inventory Excel (truckinventory.xlsx).
#     Returns (ok, message). Prevents duplicate Serial Number.
#     """
#     inv = load_inventory()
#     serial = str(item.get("Serial Number", "")).strip()
#     if not serial:
#         return False, "Serial Number is required."

#     # duplicate check
#     if serial in inv["Serial Number"].astype(str).values:
#         return False, f"Serial Number '{serial}' already exists."

#     # Make sure all known columns exist in the item; fill missing with empty
#     for col in ALL_INVENTORY_COLUMNS:
#         item.setdefault(col, "")

#     inv = pd.concat([inv, pd.DataFrame([item])], ignore_index=True)
#     save_inventory(inv)
#     return True, "Saved to main inventory."

# # ============================
# # AUTH (login card)
# # ============================
# if not st.session_state.get("authenticated", False):
#     st.subheader("Sign in")
#     in_user = st.text_input("Username", placeholder="your.username")
#     in_pass = st.text_input("Password", type="password", placeholder="••••••••")
#     if st.button("Login", type="primary"):
#         role = None
#         for u in USERS:
#             if u.get("username") == in_user and u.get("password") == in_pass:
#                 role = u.get("role")
#                 break
#         if role:
#             st.session_state["authenticated"] = True
#             st.session_state["role"] = role
#             st.session_state["username"] = in_user
#             set_auth_query_params(in_user)  # persist via URL
#             st.success(f"✅ Logged in as {in_user} ({role})")
#             st.rerun()
#         else:
#             st.error("❌ Invalid username or password")
#     st.stop()

# # ============================
# # TABS (main app) — ORDER
# # ============================
# # New order: Register | View | Transfer | Log | Export
# tabs = ["📝 Register Inventory", "📦 View Inventory", "🔄 Transfer Device", "📜 View Transfer Log"]
# if st.session_state.get("role") == "admin":
#     tabs.append("⬇ Export Files")
# tab_objects = st.tabs(tabs)

# # If a previous action asked us to jump to a tab, do it now (client-side click)
# _target = st.session_state.pop("__jump_to_tab__", None)
# if _target:
#     _switch_to_tab_by_text(_target)  # e.g., "View Inventory" or "📦 View Inventory"

# # TAB 1 – 📝 Register Inventory  (SAVES TO MAIN INVENTORY + auto-switch)
# with tab_objects[0]:
#     st.subheader("Register New Inventory Item")
#     with st.form("register_inventory_form", clear_on_submit=False):
#         c1, c2 = st.columns(2)
#         with c1:
#             r_serial = st.text_input("Serial Number *")
#             r_device = st.text_input("Device Type *")
#             r_brand  = st.text_input("Brand")
#             r_model  = st.text_input("Model")
#             r_cpu    = st.text_input("CPU")
#         with c2:
#             r_hdd1   = st.text_input("Hard Drive 1")
#             r_hdd2   = st.text_input("Hard Drive 2")
#             r_mem    = st.text_input("Memory")
#             r_gpu    = st.text_input("GPU")
#             r_screen = st.text_input("Screen Size")
#         submitted = st.form_submit_button("Save Item")
#     if submitted:
#         # Build the item dict with meta columns
#         item = {
#             "Serial Number": r_serial.strip(),
#             "Device Type":   r_device.strip(),
#             "Brand":         r_brand.strip(),
#             "Model":         r_model.strip(),
#             "CPU":           r_cpu.strip(),
#             "Hard Drive 1":  r_hdd1.strip(),
#             "Hard Drive 2":  r_hdd2.strip(),
#             "Memory":        r_mem.strip(),
#             "GPU":           r_gpu.strip(),
#             "Screen Size":   r_screen.strip(),
#             "USER":          "",  # default empty; will be filled on transfer
#             "Previous User": "",
#             "TO":            "",
#             "Date issued":   "",  # set now if you want created-at: datetime.now().strftime("%m/%d/%Y %H:%M:%S")
#             "Registered by": st.session_state.get("username",""),
#         }
#         ok, msg = add_inventory_item(item)  # ← SAVE TO MAIN INVENTORY
#         if ok:
#             st.success("✅ Inventory item saved to main inventory.")
#             # Ask the app to jump to the "View Inventory" tab on the next run:
#             st.session_state["__jump_to_tab__"] = "View Inventory"  # or "📦 View Inventory"
#             st.rerun()
#         else:
#             st.error(f"❌ {msg}")

# # TAB 2 – 📦 View Inventory
# with tab_objects[1]:
#     st.subheader("Current Inventory")
#     df_inventory = load_inventory()
#     if st.session_state.get("role") == "admin":
#         st.dataframe(for_display(df_inventory), use_container_width=True)
#     else:
#         st.table(for_display(df_inventory))

# # TAB 3 – 🔄 Transfer Device
# with tab_objects[2]:
#     st.subheader("Register Ownership Transfer")
#     serial_number  = st.text_input("Enter Serial Number")
#     new_owner      = st.text_input("Enter NEW Owner's Name")
#     registered_by  = st.session_state.get("username", "")
#     if st.button("Transfer Now", type="primary"):
#         if not serial_number.strip() or not new_owner.strip():
#             st.error("⚠ All fields are required.")
#             st.stop()

#         df_inventory = load_inventory()
#         df_log       = load_transfer_log()

#         if "Serial Number" not in df_inventory.columns:
#             st.error("Inventory file is missing 'Serial Number' column.")
#             st.stop()

#         if serial_number not in df_inventory["Serial Number"].astype(str).values:
#             st.error(f"Device with Serial Number {serial_number} not found!")
#         else:
#             idx         = df_inventory[df_inventory["Serial Number"].astype(str) == serial_number].index[0]
#             from_owner  = df_inventory.loc[idx, "USER"] if "USER" in df_inventory.columns else ""
#             device_type = df_inventory.loc[idx, "Device Type"] if "Device Type" in df_inventory.columns else ""

#             if "Previous User" in df_inventory.columns:
#                 df_inventory.loc[idx, "Previous User"] = from_owner
#             if "USER" in df_inventory.columns:
#                 df_inventory.loc[idx, "USER"] = new_owner
#             if "TO" in df_inventory.columns:
#                 df_inventory.loc[idx, "TO"]  = new_owner
#             if "Date issued" in df_inventory.columns:
#                 df_inventory.loc[idx, "Date issued"] = datetime.now().strftime("%m/%d/%Y %H:%M:%S")
#             if "Registered by" in df_inventory.columns:
#                 df_inventory.loc[idx, "Registered by"] = registered_by

#             log_entry = {
#                 "Device Type": device_type,
#                 "Serial Number": serial_number,
#                 "From owner": from_owner,
#                 "To owner": new_owner,
#                 "Date issued": datetime.now().strftime("%m/%d/%Y %H:%M:%S"),
#                 "Registered by": registered_by
#             }
#             # append to transfer log file
#             df_log = pd.concat([df_log, pd.DataFrame([log_entry])], ignore_index=True)

#             save_inventory(df_inventory)
#             save_transfer_log(df_log)
#             st.success(f"✅ Transfer logged: {from_owner} → {new_owner}")

# # TAB 4 – 📜 View Transfer Log
# with tab_objects[3]:
#     st.subheader("Transfer Log History")
#     df_log = load_transfer_log()
#     if st.session_state.get("role") == "admin":
#         st.dataframe(for_display(df_log), use_container_width=True)
#     else:
#         st.table(for_display(df_log))

# # TAB 5 – ⬇ Export Files (Admins Only)
# if st.session_state.get("role") == "admin" and len(tab_objects) > 4:
#     with tab_objects[4]:
#         st.subheader("Download Updated Files")

#         # Inventory export
#         df_inventory = load_inventory()
#         out_inv = BytesIO()
#         with pd.ExcelWriter(out_inv, engine="openpyxl") as writer:
#             df_inventory.to_excel(writer, index=False)
#         out_inv.seek(0)
#         st.download_button(
#             label="⬇ Download Inventory",
#             data=out_inv.getvalue(),
#             file_name="truckinventory_updated.xlsx",
#             mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
#         )

#         # Transfer log export
#         df_log = load_transfer_log()
#         out_log = BytesIO()
#         with pd.ExcelWriter(out_log, engine="openpyxl") as writer:
#             df_log.to_excel(writer, index=False)
#         out_log.seek(0)
#         st.download_button(
#             label="⬇ Download Transfer Log",
#             data=out_log.getvalue(),
#             file_name="transferlog_updated.xlsx",
#             mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
#         )


# app.py — Tracking Inventory System (Streamlit)
# Tabs: 1) 📝 Register Inventory, 2) 📦 View Inventory, 3) 🔄 Transfer Device,
#       4) 📜 View Transfer Log, 5) ⬇ Export Files
# app.py — Tracking Inventory System (Streamlit)
# Tabs: 1) 📝 Register Inventory, 2) 📦 View Inventory, 3) 🔄 Transfer Device,
#       4) 📜 View Transfer Log, 5) ⬇ Export Files
# app.py — Tracking Inventory System (Streamlit)
# Tabs: 1) 📝 Register Inventory, 2) 📦 View Inventory, 3) 🔄 Transfer Device,
#       4) 📜 View Transfer Log, 5) ⬇ Export Files
# app.py — Tracking Inventory System (Streamlit)
# Tabs: 1) 📝 Register Inventory, 2) 📦 View Inventory, 3) 🔄 Transfer Device,
#       4) 📜 View Transfer Log, 5) ⬇ Export Files

# app.py — Tracking Inventory System (Streamlit)
# Tabs: 1) 📝 Register Inventory, 2) 📦 View Inventory, 3) 🔄 Transfer Device,
#       4) 📜 View Transfer Log, 5) ⬇ Export Files

# import streamlit as st
# import streamlit.components.v1 as components
# import pandas as pd
# import numpy as np
# from datetime import datetime
# from io import BytesIO
# import json
# import os
# import shutil
# import base64
# import hmac
# import hashlib
# import tempfile

# # ============================
# # EASY CONTROLS
# # ============================
# APP_TITLE        = "Tracking Inventory Management System"
# APP_TAGLINE      = "AdvancedConstruction"
# FONT_FAMILY      = "Times New Roman"
# TOP_PADDING_REM  = 2
# MAX_CONTENT_W    = 1300

# # Logo
# LOGO_FILE        = "assets/company_logo.jpeg"
# LOGO_WIDTH_PX    = 400
# LOGO_HEIGHT_PX   = 60
# LOGO_ALT_EMOJI   = "🖥️"

# # Title sizes
# TITLE_SIZE_PX    = 46
# TAGLINE_SIZE_PX  = 16

# # Spacing
# GAP_BELOW_HEADER_PX = 16
# LOGOUT_ROW_TOP_MARG = 8

# # Favicon
# ICON_FILE        = "assets/favicon.png"

# # Auth (put in .streamlit/secrets.toml)
# # auth_secret = "a-very-long-random-string"
# # users_json = '[{"username":"admin","password":"123","role":"admin"}]'
# AUTH_SECRET      = st.secrets.get("auth_secret", "change-me")

# # Dates
# DATE_FMT         = "%Y-%m-%d %H:%M:%S"

# # ============================
# # PAGE CONFIG
# # ============================
# st.set_page_config(
#     page_title="Tracking Inventory System",
#     page_icon=ICON_FILE if os.path.exists(ICON_FILE) else LOGO_ALT_EMOJI,
#     layout="wide",
#     initial_sidebar_state="collapsed",
# )

# # ============================
# # GLOBAL CSS
# # ============================
# st.markdown(f"""
# <style>
# html, body, .stApp, .stApp * {{
#   font-family: "{FONT_FAMILY}", Times, serif !important;
# }}
# [data-testid="stSidebar"] {{ display: none !important; }}
# .block-container {{ padding-top:{TOP_PADDING_REM}rem; max-width:{MAX_CONTENT_W}px; }}
# .brand-title {{ font-weight:700; font-size:{TITLE_SIZE_PX}px; margin:0; line-height:1.1; }}
# .brand-tag {{ margin:2px 0 0; color:#64748b; font-weight:400; font-size:{TAGLINE_SIZE_PX}px; }}
# .header-divider {{ height:1px; background:#e5e7eb; margin:10px 0 {GAP_BELOW_HEADER_PX}px; }}
# .logout-row {{ margin-top:{LOGOUT_ROW_TOP_MARG}px; }}
# .stButton > button {{ height:38px; padding:0 .9rem; border-radius:8px; font-weight:600; }}
# .logout-col .stButton > button {{ background:#f3f4f6; color:#111827; border:1px solid #e5e7eb; }}
# .logout-col .stButton > button:hover {{ background:#e5e7eb; }}
# .stTabs {{ margin-top:6px; }}
# section[tabindex="0"] h2 {{ margin-top:8px; }}
# #MainMenu, footer {{ visibility: hidden; }}
# </style>
# """, unsafe_allow_html=True)

# # ============================
# # SESSION DEFAULTS
# # ============================
# st.session_state.setdefault("authenticated", False)
# st.session_state.setdefault("role", None)
# st.session_state.setdefault("username", "")
# st.session_state.setdefault("__jump_to_tab__", None)

# # ============================
# # USERS (from secrets)
# # ============================
# try:
#     USERS = json.loads(st.secrets["users_json"])
# except Exception:
#     st.error("Missing `users_json` in secrets. Example: "
#              '`[{"username":"admin","password":"123","role":"admin"}]`')
#     st.stop()

# def get_user_role(username: str):
#     for u in USERS:
#         if u.get("username") == username:
#             return u.get("role")
#     return None

# # ============================
# # URL TOKEN (persistent login)
# # ============================
# def make_token(username: str) -> str:
#     return hmac.new(AUTH_SECRET.encode("utf-8"), msg=username.encode("utf-8"),
#                     digestmod=hashlib.sha256).hexdigest()

# def set_auth_query_params(username: str):
#     st.query_params.clear()
#     st.query_params.update({"u": username, "t": make_token(username)})

# def clear_auth_query_params():
#     st.query_params.clear()

# def try_auto_login_from_url():
#     if st.session_state.get("authenticated"):
#         return
#     params = st.query_params
#     u = params.get("u")
#     t = params.get("t")
#     if not u or not t:
#         return
#     if hmac.compare_digest(t, make_token(u)):
#         role = get_user_role(u)
#         if role:
#             st.session_state["authenticated"] = True
#             st.session_state["username"] = u
#             st.session_state["role"] = role

# try_auto_login_from_url()

# # ============================
# # UTILS
# # ============================
# def img_to_base64(path: str) -> str | None:
#     if os.path.exists(path):
#         with open(path, "rb") as f:
#             return base64.b64encode(f.read()).decode("utf-8")
#     return None

# def logo_html(src_path: str, width_px: int, height_px: int | None, alt_emoji: str) -> str:
#     b64 = img_to_base64(src_path)
#     if not b64:
#         return f"<div style='font-size:{int(width_px*0.7)}px;line-height:1'>{alt_emoji}</div>"
#     h_style = f"height:{height_px}px;" if height_px else ""
#     return f"<img src='data:image/png;base64,{b64}' alt='logo' style='width:{width_px}px;{h_style}display:block;'/>"

# def for_display(df: pd.DataFrame) -> pd.DataFrame:
#     """Format date-like columns and remove NaT/NaN for safe display."""
#     if df is None or df.empty:
#         return df
#     out = df.copy()
#     for col in out.columns:
#         try:
#             if np.issubdtype(out[col].dtype, np.datetime64) or ("date" in col.lower()):
#                 s = pd.to_datetime(out[col], errors="coerce")
#                 out[col] = s.dt.strftime(DATE_FMT)
#         except Exception:
#             pass
#     out = out.replace({np.nan: ""})
#     for col in out.columns:
#         out[col] = out[col].astype(str).replace({"NaT": "", "nan": "", "NaN": ""})
#     return out

# def _switch_to_tab_by_text(partial_label: str):
#     """Client-side: click a tab by visible text (used after saving)."""
#     components.html(
#         f"""
#         <script>
#         const wanted = {json.dumps(partial_label)};
#         function clickTab() {{
#           const root = window.parent.document;
#           const tabs = root.querySelectorAll('button[role="tab"]');
#           for (const t of tabs) {{
#             if ((t.innerText || "").trim().includes(wanted)) {{ t.click(); return; }}
#           }}
#           setTimeout(clickTab, 60);
#         }}
#         clickTab();
#         </script>
#         """,
#         height=0,
#     )

# # ============================
# # HEADER
# # ============================
# def show_header():
#     c_logo, c_text = st.columns([0.16, 0.84])
#     with c_logo:
#         st.markdown(logo_html(LOGO_FILE, LOGO_WIDTH_PX, LOGO_HEIGHT_PX, LOGO_ALT_EMOJI),
#                     unsafe_allow_html=True)
#     with c_text:
#         st.markdown(
#             f"<h1 class='brand-title'>{APP_TITLE}</h1>"
#             f"<div class='brand-tag'>{APP_TAGLINE}</div>",
#             unsafe_allow_html=True
#         )
#     _, btn = st.columns([0.85, 0.15])
#     with btn:
#         st.markdown("<div class='logout-col logout-row'>", unsafe_allow_html=True)
#         if st.session_state.get("authenticated"):
#             if st.button("Logout", use_container_width=True, key="logout_btn"):
#                 st.session_state["authenticated"] = False
#                 st.session_state["role"] = None
#                 st.session_state["username"] = ""
#                 clear_auth_query_params()
#                 st.rerun()
#         st.markdown("</div>", unsafe_allow_html=True)
#     st.markdown('<div class="header-divider"></div>', unsafe_allow_html=True)

# show_header()

# # ============================
# # FILES & HELPERS
# # ============================
# INVENTORY_FILE         = "truckinventory.xlsx"
# TRANSFER_LOG_PRIMARY   = "transferlog.xlsx"
# TRANSFER_LOG_ALT       = "transferlogin.xlsx"
# TRANSFER_LOG_FILE      = TRANSFER_LOG_PRIMARY if os.path.exists(TRANSFER_LOG_PRIMARY) else (
#                          TRANSFER_LOG_ALT if os.path.exists(TRANSFER_LOG_ALT) else TRANSFER_LOG_PRIMARY)

# BACKUP_FOLDER          = "backups"
# os.makedirs(BACKUP_FOLDER, exist_ok=True)

# HW_COLUMNS = [
#     "Serial Number", "Device Type", "Brand", "Model", "CPU",
#     "Hard Drive 1", "Hard Drive 2", "Memory", "GPU", "Screen Size"
# ]
# META_COLUMNS = ["USER", "Previous User", "TO", "Date issued", "Registered by"]
# ALL_INVENTORY_COLUMNS = HW_COLUMNS + META_COLUMNS

# def backup_file(file_path):
#     if os.path.exists(file_path):
#         base = os.path.basename(file_path).split(".")[0]
#         ts = datetime.now().strftime("%Y%m%d_%H%M%S")
#         shutil.copy(file_path, f"{BACKUP_FOLDER}/{base}_{ts}.xlsx")

# @st.cache_data(show_spinner=False)
# def _read_inventory_file(path: str) -> pd.DataFrame:
#     if not os.path.exists(path):
#         pd.DataFrame(columns=ALL_INVENTORY_COLUMNS).to_excel(path, index=False)
#     df = pd.read_excel(path)
#     for col in ALL_INVENTORY_COLUMNS:
#         if col not in df.columns:
#             df[col] = ""
#     ordered = [c for c in ALL_INVENTORY_COLUMNS if c in df.columns] + \
#               [c for c in df.columns if c not in ALL_INVENTORY_COLUMNS]
#     return df[ordered]

# def bust_inventory_cache():
#     _read_inventory_file.clear()

# def load_inventory() -> pd.DataFrame:
#     return _read_inventory_file(INVENTORY_FILE)

# @st.cache_data(show_spinner=False)
# def _read_transfer_log_file(path: str) -> pd.DataFrame:
#     if not os.path.exists(path):
#         pd.DataFrame(columns=["Device Type","Serial Number","From owner","To owner","Date issued","Registered by"])\
#           .to_excel(path, index=False)
#     return pd.read_excel(path)

# def bust_transfer_log_cache():
#     _read_transfer_log_file.clear()

# def load_transfer_log() -> pd.DataFrame:
#     return _read_transfer_log_file(TRANSFER_LOG_FILE)

# # -------- Atomic Excel write (always .xlsx suffix) --------
# def _atomic_write_excel(df: pd.DataFrame, path: str) -> None:
#     """
#     Write DataFrame to a temporary .xlsx next to `path`, then atomically replace `path`.
#     Avoids 'Invalid extension for engine ... tmp' errors.
#     """
#     target_dir = os.path.dirname(os.path.abspath(path)) or "."
#     os.makedirs(target_dir, exist_ok=True)

#     fd, tmp_path = tempfile.mkstemp(
#         prefix=os.path.basename(path) + ".",   # e.g., truckinventory.xlsx.abc123
#         suffix=".tmp.xlsx",                    # ends with .xlsx (required by openpyxl)
#         dir=target_dir
#     )
#     os.close(fd)
#     try:
#         with pd.ExcelWriter(tmp_path, engine="openpyxl") as writer:
#             df.to_excel(writer, index=False)
#         os.replace(tmp_path, path)  # atomic replace
#     finally:
#         if os.path.exists(tmp_path):
#             try:
#                 os.remove(tmp_path)
#             except Exception:
#                 pass

# def save_inventory(df: pd.DataFrame):
#     backup_file(INVENTORY_FILE)
#     _atomic_write_excel(df, INVENTORY_FILE)
#     bust_inventory_cache()

# def save_transfer_log(df: pd.DataFrame):
#     backup_file(TRANSFER_LOG_FILE)
#     _atomic_write_excel(df, TRANSFER_LOG_FILE)
#     bust_transfer_log_cache()

# def add_inventory_item(item: dict) -> tuple[bool, str]:
#     inv = load_inventory()
#     serial = str(item.get("Serial Number", "")).strip()
#     if not serial:
#         return False, "Serial Number is required."
#     if serial in inv["Serial Number"].astype(str).values:
#         return False, f"Serial Number '{serial}' already exists."
#     for col in ALL_INVENTORY_COLUMNS:
#         item.setdefault(col, "")
#     inv = pd.concat([inv, pd.DataFrame([item])], ignore_index=True)
#     save_inventory(inv)
#     return True, "Saved to main inventory."

# # ============================
# # AUTH (login card)
# # ============================
# if not st.session_state.get("authenticated", False):
#     st.subheader("Sign in")
#     in_user = st.text_input("Username", placeholder="your.username")
#     in_pass = st.text_input("Password", type="password", placeholder="••••••••")
#     if st.button("Login", type="primary"):
#         role = None
#         for u in USERS:
#             if u.get("username") == in_user and u.get("password") == in_pass:
#                 role = u.get("role")
#                 break
#         if role:
#             st.session_state["authenticated"] = True
#             st.session_state["role"] = role
#             st.session_state["username"] = in_user
#             set_auth_query_params(in_user)
#             st.success(f"✅ Logged in as {in_user} ({role})")
#             st.rerun()
#         else:
#             st.error("❌ Invalid username or password")
#     st.stop()

# # ============================
# # TABS
# # ============================
# tabs = ["📝 Register Inventory", "📦 View Inventory", "🔄 Transfer Device", "📜 View Transfer Log"]
# if st.session_state.get("role") == "admin":
#     tabs.append("⬇ Export Files")
# tab_objects = st.tabs(tabs)

# # Handle auto-jump (after save)
# _target = st.session_state.pop("__jump_to_tab__", None)
# if _target:
#     _switch_to_tab_by_text(_target)

# # TAB 1 – Register
# with tab_objects[0]:
#     st.subheader("Register New Inventory Item")
#     with st.form("register_inventory_form", clear_on_submit=False):
#         c1, c2 = st.columns(2)
#         with c1:
#             r_serial = st.text_input("Serial Number *")
#             r_device = st.text_input("Device Type *")
#             r_brand  = st.text_input("Brand")
#             r_model  = st.text_input("Model")
#             r_cpu    = st.text_input("CPU")
#         with c2:
#             r_hdd1   = st.text_input("Hard Drive 1")
#             r_hdd2   = st.text_input("Hard Drive 2")
#             r_mem    = st.text_input("Memory")
#             r_gpu    = st.text_input("GPU")
#             r_screen = st.text_input("Screen Size")
#         submitted = st.form_submit_button("Save Item")
#     if submitted:
#         item = {
#             "Serial Number": r_serial.strip(),
#             "Device Type":   r_device.strip(),
#             "Brand":         r_brand.strip(),
#             "Model":         r_model.strip(),
#             "CPU":           r_cpu.strip(),
#             "Hard Drive 1":  r_hdd1.strip(),
#             "Hard Drive 2":  r_hdd2.strip(),
#             "Memory":        r_mem.strip(),
#             "GPU":           r_gpu.strip(),
#             "Screen Size":   r_screen.strip(),
#             "USER":          "",
#             "Previous User": "",
#             "TO":            "",
#             "Date issued":   datetime.now().strftime(DATE_FMT),
#             "Registered by": st.session_state.get("username",""),
#         }
#         ok, msg = add_inventory_item(item)
#         if ok:
#             st.success("✅ Inventory item saved to main inventory.")
#             st.session_state["__jump_to_tab__"] = "View Inventory"
#             st.rerun()
#         else:
#             st.error(f"❌ {msg}")

# # TAB 2 – View Inventory
# with tab_objects[1]:
#     st.subheader("Current Inventory")
#     df_inventory = load_inventory()
#     if st.session_state.get("role") == "admin":
#         st.dataframe(for_display(df_inventory), use_container_width=True)
#     else:
#         st.table(for_display(df_inventory))

# # TAB 3 – Transfer Device (SAFE lookups)
# with tab_objects[2]:
#     st.subheader("Register Ownership Transfer")

#     df_inventory = load_inventory()
#     serial_options = sorted(df_inventory["Serial Number"].astype(str).dropna().unique().tolist())
#     SERIAL_SENTINEL = "— Select Serial Number —"
#     serial_choice = st.selectbox(
#         "Serial Number",
#         [SERIAL_SENTINEL] + serial_options,
#         help="Start typing to filter the list and avoid typos."
#     )
#     serial_number = None if serial_choice == SERIAL_SENTINEL else serial_choice

#     # Safe hint (guard against empty match)
#     if serial_number:
#         match = df_inventory[df_inventory["Serial Number"].astype(str).str.strip()
#                              == str(serial_number).strip()]
#         if not match.empty:
#             row = match.iloc[0]
#             hint = (
#                 f"Device: {row.get('Device Type','')} • "
#                 f"Brand: {row.get('Brand','')} • "
#                 f"Model: {row.get('Model','')} • "
#                 f"CPU: {row.get('CPU','')}"
#             )
#             st.caption(hint)
#         else:
#             st.warning("Selected serial not found in inventory. Try refreshing or check for extra spaces.")

#     new_owner = st.text_input("Enter NEW Owner's Name")
#     registered_by = st.session_state.get("username", "")
#     transfer_disabled = not (serial_number and new_owner.strip())

#     if st.button("Transfer Now", type="primary", disabled=transfer_disabled):
#         df_log = load_transfer_log()

#         # Safe index lookup
#         mask = df_inventory["Serial Number"].astype(str).str.strip() == str(serial_number).strip()
#         matches = df_inventory.index[mask]

#         if len(matches) == 0:
#             st.error(f"Device with Serial Number {serial_number} not found!")
#         else:
#             idx = matches[0]
#             from_owner  = df_inventory.loc[idx, "USER"] if "USER" in df_inventory.columns else ""
#             device_type = df_inventory.loc[idx, "Device Type"] if "Device Type" in df_inventory.columns else ""

#             if "Previous User" in df_inventory.columns:
#                 df_inventory.loc[idx, "Previous User"] = from_owner
#             if "USER" in df_inventory.columns:
#                 df_inventory.loc[idx, "USER"] = new_owner
#             if "TO" in df_inventory.columns:
#                 df_inventory.loc[idx, "TO"]  = new_owner
#             if "Date issued" in df_inventory.columns:
#                 df_inventory.loc[idx, "Date issued"] = datetime.now().strftime(DATE_FMT)
#             if "Registered by" in df_inventory.columns:
#                 df_inventory.loc[idx, "Registered by"] = registered_by

#             log_entry = {
#                 "Device Type": device_type,
#                 "Serial Number": serial_number,
#                 "From owner": from_owner,
#                 "To owner": new_owner,
#                 "Date issued": datetime.now().strftime(DATE_FMT),
#                 "Registered by": registered_by
#             }
#             df_log = pd.concat([df_log, pd.DataFrame([log_entry])], ignore_index=True)

#             save_inventory(df_inventory)
#             save_transfer_log(df_log)
#             st.success(f"✅ Transfer logged: {from_owner} → {new_owner}")

# # TAB 4 – Transfer Log
# with tab_objects[3]:
#     st.subheader("Transfer Log History")
#     df_log = load_transfer_log()
#     if st.session_state.get("role") == "admin":
#         st.dataframe(for_display(df_log), use_container_width=True)
#     else:
#         st.table(for_display(df_log))

# # TAB 5 – Export (Admins only)
# if st.session_state.get("role") == "admin" and len(tab_objects) > 4:
#     with tab_objects[4]:
#         st.subheader("Download Updated Files")

#         df_inventory = load_inventory()
#         out_inv = BytesIO()
#         with pd.ExcelWriter(out_inv, engine="openpyxl") as writer:
#             df_inventory.to_excel(writer, index=False)
#         out_inv.seek(0)
#         st.download_button(
#             label="⬇ Download Inventory",
#             data=out_inv.getvalue(),
#             file_name="truckinventory_updated.xlsx",
#             mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
#         )

#         df_log = load_transfer_log()
#         out_log = BytesIO()
#         with pd.ExcelWriter(out_log, engine="openpyxl") as writer:
#             df_log.to_excel(writer, index=False)
#         out_log.seek(0)
#         st.download_button(
#             label="⬇ Download Transfer Log",
#             data=out_log.getvalue(),
#             file_name="transferlog_updated.xlsx",
#             mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
#         )


# app.py — Tracking Inventory System (Streamlit)
# Tabs: 1) 📝 Register Inventory, 2) 📦 View Inventory, 3) 🔄 Transfer Device,
#       4) 📜 View Transfer Log, 5) ⬇ Export Files

import streamlit as st
import streamlit.components.v1 as components
import pandas as pd
import numpy as np
from datetime import datetime
from io import BytesIO
import json
import os
import shutil
import base64
import hmac
import hashlib
import tempfile

# ============================
# EASY CONTROLS
# ============================
APP_TITLE        = "Tracking Inventory Management System"
APP_TAGLINE      = "AdvancedConstruction"
FONT_FAMILY      = "Times New Roman"
TOP_PADDING_REM  = 2
MAX_CONTENT_W    = 1300

# Logo
LOGO_FILE        = "assets/company_logo.jpeg"
LOGO_WIDTH_PX    = 400
LOGO_HEIGHT_PX   = 60
LOGO_ALT_EMOJI   = "🖥️"

# Title sizes
TITLE_SIZE_PX    = 46
TAGLINE_SIZE_PX  = 16

# Spacing
GAP_BELOW_HEADER_PX = 16
LOGOUT_ROW_TOP_MARG = 8

# Favicon
ICON_FILE        = "assets/favicon.png"

# Auth (put in .streamlit/secrets.toml)
# auth_secret = "a-very-long-random-string"
# users_json = '[{"username":"admin","password":"123","role":"admin"}]'
AUTH_SECRET      = st.secrets.get("auth_secret", "change-me")

# Dates
DATE_FMT         = "%Y-%m-%d %H:%M:%S"

# ============================
# PAGE CONFIG
# ============================
st.set_page_config(
    page_title="Tracking Inventory System",
    page_icon=ICON_FILE if os.path.exists(ICON_FILE) else LOGO_ALT_EMOJI,
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ============================
# GLOBAL CSS
# ============================
st.markdown(f"""
<style>
html, body, .stApp, .stApp * {{
  font-family: "{FONT_FAMILY}", Times, serif !important;
}}
[data-testid="stSidebar"] {{ display: none !important; }}
.block-container {{ padding-top:{TOP_PADDING_REM}rem; max-width:{MAX_CONTENT_W}px; }}
.brand-title {{ font-weight:700; font-size:{TITLE_SIZE_PX}px; margin:0; line-height:1.1; }}
.brand-tag {{ margin:2px 0 0; color:#64748b; font-weight:400; font-size:{TAGLINE_SIZE_PX}px; }}
.header-divider {{ height:1px; background:#e5e7eb; margin:10px 0 {GAP_BELOW_HEADER_PX}px; }}
.logout-row {{ margin-top:{LOGOUT_ROW_TOP_MARG}px; }}
.stButton > button {{ height:38px; padding:0 .9rem; border-radius:8px; font-weight:600; }}
.logout-col .stButton > button {{ background:#f3f4f6; color:#111827; border:1px solid #e5e7eb; }}
.logout-col .stButton > button:hover {{ background:#e5e7eb; }}
.stTabs {{ margin-top:6px; }}
section[tabindex="0"] h2 {{ margin-top:8px; }}
#MainMenu, footer {{ visibility: hidden; }}
</style>
""", unsafe_allow_html=True)

# ============================
# SESSION DEFAULTS
# ============================
st.session_state.setdefault("authenticated", False)
st.session_state.setdefault("role", None)
st.session_state.setdefault("username", "")
st.session_state.setdefault("__jump_to_tab__", None)

# ============================
# USERS (from secrets)
# ============================
try:
    USERS = json.loads(st.secrets["users_json"])
except Exception:
    st.error("Missing `users_json` in secrets. Example: "
             '`[{"username":"admin","password":"123","role":"admin"}]`')
    st.stop()

def get_user_role(username: str):
    for u in USERS:
        if u.get("username") == username:
            return u.get("role")
    return None

# ============================
# URL TOKEN (persistent login)
# ============================
def make_token(username: str) -> str:
    return hmac.new(AUTH_SECRET.encode("utf-8"), msg=username.encode("utf-8"),
                    digestmod=hashlib.sha256).hexdigest()

def set_auth_query_params(username: str):
    st.query_params.clear()
    st.query_params.update({"u": username, "t": make_token(username)})

def clear_auth_query_params():
    st.query_params.clear()

def try_auto_login_from_url():
    if st.session_state.get("authenticated"):
        return
    params = st.query_params
    u = params.get("u")
    t = params.get("t")
    if not u or not t:
        return
    if hmac.compare_digest(t, make_token(u)):
        role = get_user_role(u)
        if role:
            st.session_state["authenticated"] = True
            st.session_state["username"] = u
            st.session_state["role"] = role

try_auto_login_from_url()

# ============================
# UTILS
# ============================
def img_to_base64(path: str) -> str | None:
    if os.path.exists(path):
        with open(path, "rb") as f:
            return base64.b64encode(f.read()).decode("utf-8")
    return None

def logo_html(src_path: str, width_px: int, height_px: int | None, alt_emoji: str) -> str:
    b64 = img_to_base64(src_path)
    if not b64:
        return f"<div style='font-size:{int(width_px*0.7)}px;line-height:1'>{alt_emoji}</div>"
    h_style = f"height:{height_px}px;" if height_px else ""
    return f"<img src='data:image/png;base64,{b64}' alt='logo' style='width:{width_px}px;{h_style}display:block;'/>"

def for_display(df: pd.DataFrame) -> pd.DataFrame:
    """Format date-like columns and remove NaT/NaN for safe display."""
    if df is None or df.empty:
        return df
    out = df.copy()
    for col in out.columns:
        try:
            if np.issubdtype(out[col].dtype, np.datetime64) or ("date" in col.lower()):
                s = pd.to_datetime(out[col], errors="coerce")
                out[col] = s.dt.strftime(DATE_FMT)
        except Exception:
            pass
    out = out.replace({np.nan: ""})
    for col in out.columns:
        out[col] = out[col].astype(str).replace({"NaT": "", "nan": "", "NaN": ""})
    return out

def _switch_to_tab_by_text(partial_label: str):
    """Client-side: click a tab by visible text (used after saving)."""
    components.html(
        f"""
        <script>
        const wanted = {json.dumps(partial_label)};
        function clickTab() {{
          const root = window.parent.document;
          const tabs = root.querySelectorAll('button[role="tab"]');
          for (const t of tabs) {{
            if ((t.innerText || "").trim().includes(wanted)) {{ t.click(); return; }}
          }}
          setTimeout(clickTab, 60);
        }}
        clickTab();
        </script>
        """,
        height=0,
    )

# ============================
# HEADER
# ============================
def show_header():
    c_logo, c_text = st.columns([0.16, 0.84])
    with c_logo:
        st.markdown(logo_html(LOGO_FILE, LOGO_WIDTH_PX, LOGO_HEIGHT_PX, LOGO_ALT_EMOJI),
                    unsafe_allow_html=True)
    with c_text:
        st.markdown(
            f"<h1 class='brand-title'>{APP_TITLE}</h1>"
            f"<div class='brand-tag'>{APP_TAGLINE}</div>",
            unsafe_allow_html=True
        )
    _, btn = st.columns([0.85, 0.15])
    with btn:
        st.markdown("<div class='logout-col logout-row'>", unsafe_allow_html=True)
        if st.session_state.get("authenticated"):
            if st.button("Logout", use_container_width=True, key="logout_btn"):
                st.session_state["authenticated"] = False
                st.session_state["role"] = None
                st.session_state["username"] = ""
                clear_auth_query_params()
                st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)
    st.markdown('<div class="header-divider"></div>', unsafe_allow_html=True)

show_header()

# ============================
# FILES & HELPERS
# ============================
INVENTORY_FILE         = "truckinventory.xlsx"
TRANSFER_LOG_PRIMARY   = "transferlog.xlsx"
TRANSFER_LOG_ALT       = "transferlogin.xlsx"
TRANSFER_LOG_FILE      = TRANSFER_LOG_PRIMARY if os.path.exists(TRANSFER_LOG_PRIMARY) else (
                         TRANSFER_LOG_ALT if os.path.exists(TRANSFER_LOG_ALT) else TRANSFER_LOG_PRIMARY)

BACKUP_FOLDER          = "backups"
os.makedirs(BACKUP_FOLDER, exist_ok=True)

HW_COLUMNS = [
    "Serial Number", "Device Type", "Brand", "Model", "CPU",
    "Hard Drive 1", "Hard Drive 2", "Memory", "GPU", "Screen Size"
]
META_COLUMNS = ["USER", "Previous User", "TO", "Date issued", "Registered by"]
ALL_INVENTORY_COLUMNS = HW_COLUMNS + META_COLUMNS

# Person-related columns to update on transfer (only if they already exist in Excel)
PERSON_COLS = [
    "USER",           # set to new owner
    "Department",
    "Email Address",
    "Contact Number",
    "Location",
    "Office",
    "Notes",
]

def backup_file(file_path):
    if os.path.exists(file_path):
        base = os.path.basename(file_path).split(".")[0]
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        shutil.copy(file_path, f"{BACKUP_FOLDER}/{base}_{ts}.xlsx")

@st.cache_data(show_spinner=False)
def _read_inventory_file(path: str) -> pd.DataFrame:
    if not os.path.exists(path):
        pd.DataFrame(columns=ALL_INVENTORY_COLUMNS).to_excel(path, index=False)
    df = pd.read_excel(path)
    for col in ALL_INVENTORY_COLUMNS:
        if col not in df.columns:
            df[col] = ""
    ordered = [c for c in ALL_INVENTORY_COLUMNS if c in df.columns] + \
              [c for c in df.columns if c not in ALL_INVENTORY_COLUMNS]
    return df[ordered]

def bust_inventory_cache():
    _read_inventory_file.clear()

def load_inventory() -> pd.DataFrame:
    return _read_inventory_file(INVENTORY_FILE)

@st.cache_data(show_spinner=False)
def _read_transfer_log_file(path: str) -> pd.DataFrame:
    if not os.path.exists(path):
        pd.DataFrame(columns=["Device Type","Serial Number","From owner","To owner","Date issued","Registered by"])\
          .to_excel(path, index=False)
    return pd.read_excel(path)

def bust_transfer_log_cache():
    _read_transfer_log_file.clear()

def load_transfer_log() -> pd.DataFrame:
    return _read_transfer_log_file(TRANSFER_LOG_FILE)

# -------- Atomic Excel write (always .xlsx suffix) --------
def _atomic_write_excel(df: pd.DataFrame, path: str) -> None:
    """Write DataFrame to a temporary .xlsx next to `path`, then atomically replace `path`."""
    target_dir = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(target_dir, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        prefix=os.path.basename(path) + ".",
        suffix=".tmp.xlsx",    # must end with .xlsx for openpyxl
        dir=target_dir
    )
    os.close(fd)
    try:
        with pd.ExcelWriter(tmp_path, engine="openpyxl") as writer:
            df.to_excel(writer, index=False)
        os.replace(tmp_path, path)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass

def save_inventory(df: pd.DataFrame):
    backup_file(INVENTORY_FILE)
    _atomic_write_excel(df, INVENTORY_FILE)
    bust_inventory_cache()

def save_transfer_log(df: pd.DataFrame):
    backup_file(TRANSFER_LOG_FILE)
    _atomic_write_excel(df, TRANSFER_LOG_FILE)
    bust_transfer_log_cache()

def add_inventory_item(item: dict) -> tuple[bool, str]:
    inv = load_inventory()
    serial = str(item.get("Serial Number", "")).strip()
    if not serial:
        return False, "Serial Number is required."
    if serial in inv["Serial Number"].astype(str).values:
        return False, f"Serial Number '{serial}' already exists."
    for col in ALL_INVENTORY_COLUMNS:
        item.setdefault(col, "")
    inv = pd.concat([inv, pd.DataFrame([item])], ignore_index=True)
    save_inventory(inv)
    return True, "Saved to main inventory."

# ============================
# AUTH (login card)
# ============================
if not st.session_state.get("authenticated", False):
    st.subheader("Sign in")
    in_user = st.text_input("Username", placeholder="your.username")
    in_pass = st.text_input("Password", type="password", placeholder="••••••••")
    if st.button("Login", type="primary"):
        role = None
        for u in USERS:
            if u.get("username") == in_user and u.get("password") == in_pass:
                role = u.get("role")
                break
        if role:
            st.session_state["authenticated"] = True
            st.session_state["role"] = role
            st.session_state["username"] = in_user
            set_auth_query_params(in_user)
            st.success(f"✅ Logged in as {in_user} ({role})")
            st.rerun()
        else:
            st.error("❌ Invalid username or password")
    st.stop()

# ============================
# TABS
# ============================
tabs = ["📝 Register Inventory", "📦 View Inventory", "🔄 Transfer Device", "📜 View Transfer Log"]
if st.session_state.get("role") == "admin":
    tabs.append("⬇ Export Files")
tab_objects = st.tabs(tabs)

# Handle auto-jump (after save)
_target = st.session_state.pop("__jump_to_tab__", None)
if _target:
    _switch_to_tab_by_text(_target)

# TAB 1 – Register
with tab_objects[0]:
    st.subheader("Register New Inventory Item")
    with st.form("register_inventory_form", clear_on_submit=False):
        c1, c2 = st.columns(2)
        with c1:
            r_serial = st.text_input("Serial Number *")
            r_device = st.text_input("Device Type *")
            r_brand  = st.text_input("Brand")
            r_model  = st.text_input("Model")
            r_cpu    = st.text_input("CPU")
        with c2:
            r_hdd1   = st.text_input("Hard Drive 1")
            r_hdd2   = st.text_input("Hard Drive 2")
            r_mem    = st.text_input("Memory")
            r_gpu    = st.text_input("GPU")
            r_screen = st.text_input("Screen Size")
        submitted = st.form_submit_button("Save Item")
    if submitted:
        item = {
            "Serial Number": r_serial.strip(),
            "Device Type":   r_device.strip(),
            "Brand":         r_brand.strip(),
            "Model":         r_model.strip(),
            "CPU":           r_cpu.strip(),
            "Hard Drive 1":  r_hdd1.strip(),
            "Hard Drive 2":  r_hdd2.strip(),
            "Memory":        r_mem.strip(),
            "GPU":           r_gpu.strip(),
            "Screen Size":   r_screen.strip(),
            "USER":          "",
            "Previous User": "",
            "TO":            "",
            "Date issued":   datetime.now().strftime(DATE_FMT),
            "Registered by": st.session_state.get("username",""),
        }
        ok, msg = add_inventory_item(item)
        if ok:
            st.success("✅ Inventory item saved to main inventory.")
            st.session_state["__jump_to_tab__"] = "View Inventory"
            st.rerun()
        else:
            st.error(f"❌ {msg}")

# TAB 2 – View Inventory
with tab_objects[1]:
    st.subheader("Current Inventory")
    df_inventory = load_inventory()
    if st.session_state.get("role") == "admin":
        st.dataframe(for_display(df_inventory), use_container_width=True)
    else:
        st.table(for_display(df_inventory))

# TAB 3 – Transfer Device (updates full person details)
with tab_objects[2]:
    st.subheader("Register Ownership Transfer")

    df_inventory = load_inventory()

    # Serial selection with type-to-search
    serial_options = sorted(df_inventory["Serial Number"].astype(str).dropna().unique().tolist())
    SERIAL_SENTINEL = "— Select Serial Number —"
    serial_choice = st.selectbox(
        "Serial Number",
        [SERIAL_SENTINEL] + serial_options,
        help="Start typing to filter the list and avoid typos."
    )
    serial_number = None if serial_choice == SERIAL_SENTINEL else serial_choice

    match = pd.DataFrame()
    idx = None
    if serial_number:
        mask = df_inventory["Serial Number"].astype(str).str.strip() == str(serial_number).strip()
        matches = df_inventory.index[mask]
        if len(matches) > 0:
            idx = matches[0]
            match = df_inventory.loc[[idx]]

    # Small device hint
    if not match.empty:
        row = match.iloc[0]
        st.caption(
            f"Device: {row.get('Device Type','')} • "
            f"Brand: {row.get('Brand','')} • "
            f"Model: {row.get('Model','')} • "
            f"CPU: {row.get('CPU','')}"
        )
    elif serial_number:
        st.warning("Selected serial not found in inventory. Try refreshing or check for extra spaces.")

    # Form for new owner + person details
    with st.form("transfer_form", clear_on_submit=False):
        new_owner = st.text_input(
            "New Owner (required)",
            value="" if match.empty else str(match.iloc[0].get("USER", "") or "")
        )

        st.markdown("**New owner details** (optional)")

        inputs = {}
        # Show inputs only for person columns that exist in the Excel file
        existing_person_cols = [c for c in PERSON_COLS if c != "USER" and c in df_inventory.columns]
        left, right = st.columns(2)
        for i, col in enumerate(existing_person_cols):
            label = col.replace("_", " ")
            current_val = "" if match.empty else str(match.iloc[0].get(col, "") or "")
            with (left if i % 2 == 0 else right):
                inputs[col] = st.text_input(label, value=current_val, key=f"tx_{col}")

        submitted = st.form_submit_button("Transfer Now")

    if submitted:
        if not serial_number:
            st.error("Please choose a Serial Number.")
        elif not new_owner.strip():
            st.error("New Owner is required.")
        elif match.empty:
            st.error(f"Device with Serial Number {serial_number} not found!")
        else:
            prev_user = str(df_inventory.loc[idx, "USER"]) if "USER" in df_inventory.columns else ""

            # Move USER -> Previous User
            if "Previous User" in df_inventory.columns:
                df_inventory.loc[idx, "Previous User"] = prev_user

            # Set USER & TO to new owner
            if "USER" in df_inventory.columns:
                df_inventory.loc[idx, "USER"] = new_owner.strip()
            if "TO" in df_inventory.columns:
                df_inventory.loc[idx, "TO"] = new_owner.strip()

            # Update other person details provided (only if column exists)
            for col, val in inputs.items():
                if col in df_inventory.columns:
                    df_inventory.loc[idx, col] = val.strip()

            # Timestamp + registrar
            if "Date issued" in df_inventory.columns:
                df_inventory.loc[idx, "Date issued"] = datetime.now().strftime(DATE_FMT)
            if "Registered by" in df_inventory.columns:
                df_inventory.loc[idx, "Registered by"] = st.session_state.get("username", "")

            # Add to transfer log
            df_log = load_transfer_log()
            device_type = df_inventory.loc[idx, "Device Type"] if "Device Type" in df_inventory.columns else ""
            log_entry = {
                "Device Type": device_type,
                "Serial Number": serial_number,
                "From owner": prev_user,
                "To owner": new_owner.strip(),
                "Date issued": datetime.now().strftime(DATE_FMT),
                "Registered by": st.session_state.get("username", "")
            }
            df_log = pd.concat([df_log, pd.DataFrame([log_entry])], ignore_index=True)

            # Save both files
            save_inventory(df_inventory)
            save_transfer_log(df_log)

            st.success(f"✅ Transfer saved. {prev_user or '(blank)'} → {new_owner.strip()}")

# TAB 4 – Transfer Log
with tab_objects[3]:
    st.subheader("Transfer Log History")
    df_log = load_transfer_log()
    if st.session_state.get("role") == "admin":
        st.dataframe(for_display(df_log), use_container_width=True)
    else:
        st.table(for_display(df_log))

# TAB 5 – Export (Admins only)
if st.session_state.get("role") == "admin" and len(tab_objects) > 4:
    with tab_objects[4]:
        st.subheader("Download Updated Files")

        df_inventory = load_inventory()
        out_inv = BytesIO()
        with pd.ExcelWriter(out_inv, engine="openpyxl") as writer:
            df_inventory.to_excel(writer, index=False)
        out_inv.seek(0)
        st.download_button(
            label="⬇ Download Inventory",
            data=out_inv.getvalue(),
            file_name="truckinventory_updated.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )

        df_log = load_transfer_log()
        out_log = BytesIO()
        with pd.ExcelWriter(out_log, engine="openpyxl") as writer:
            df_log.to_excel(writer, index=False)
        out_log.seek(0)
        st.download_button(
            label="⬇ Download Transfer Log",
            data=out_log.getvalue(),
            file_name="transferlog_updated.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
