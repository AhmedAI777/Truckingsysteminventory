# import streamlit as st
# import pandas as pd
# from datetime import datetime
# from io import BytesIO

# # ========================
# # File Paths
# # ========================
# INVENTORY_FILE = "truckinventory.xlsx"
# TRANSFER_LOG_FILE = "transferlog.xlsx"

# # ========================
# # Load Data
# # ========================
# def load_inventory():
#     return pd.read_excel(INVENTORY_FILE)

# def load_transfer_log():
#     try:
#         return pd.read_excel(TRANSFER_LOG_FILE)
#     except FileNotFoundError:
#         df = pd.DataFrame(columns=[
#             "Device Type", "Serial Number", "From owner", "To owner",
#             "Date issued", "Registered by"
#         ])
#         df.to_excel(TRANSFER_LOG_FILE, index=False)
#         return df

# def save_inventory(df):
#     df.to_excel(INVENTORY_FILE, index=False)

# def save_transfer_log(df):
#     df.to_excel(TRANSFER_LOG_FILE, index=False)

# # ========================
# # Streamlit App
# # ========================
# st.set_page_config(page_title="Trucking Inventory System", page_icon="🚚", layout="wide")
# st.title("🚚 Trucking Inventory Management System")

# tab1, tab2, tab3, tab4 = st.tabs([
#     "📦 View Inventory", 
#     "🔄 Transfer Device", 
#     "📜 View Transfer Log", 
#     "⬇ Export Files"
# ])

# # TAB 1 – View Inventory
# with tab1:
#     st.subheader("Current Inventory")
#     df_inventory = load_inventory()
#     st.dataframe(df_inventory)

# # TAB 2 – Transfer Device
# with tab2:
#     st.subheader("Register Ownership Transfer")

#     serial_number = st.text_input("Enter Serial Number")
#     new_owner = st.text_input("Enter NEW Owner's Name")
#     registered_by = st.text_input("Registered By (IT Staff)")

#     if st.button("Transfer Now"):
#         df_inventory = load_inventory()
#         df_log = load_transfer_log()

#         if serial_number not in df_inventory["Serial Number"].values:
#             st.error(f"Device with Serial Number {serial_number} not found!")
#         else:
#             idx = df_inventory[df_inventory["Serial Number"] == serial_number].index[0]
            
#             # ✅ FIX: Remember last transfer
#             previous_transfers = df_log[df_log["Serial Number"] == serial_number]
#             if not previous_transfers.empty:
#                 from_owner = previous_transfers.iloc[-1]["To owner"]
#             else:
#                 from_owner = df_inventory.loc[idx, "USER"]

#             device_type = df_inventory.loc[idx, "Device Type"]

#             # Update inventory
#             df_inventory.loc[idx, "From owner"] = from_owner
#             df_inventory.loc[idx, "To owner"] = new_owner
#             df_inventory.loc[idx, "Date issued"] = datetime.now().strftime("%m/%d/%Y %H:%M:%S")
#             df_inventory.loc[idx, "Registered by"] = registered_by

#             # Append to transfer log
#             log_entry = {
#                 "Device Type": device_type,
#                 "Serial Number": serial_number,
#                 "From owner": from_owner,
#                 "To owner": new_owner,
#                 "Date issued": datetime.now().strftime("%m/%d/%Y %H:%M:%S"),
#                 "Registered by": registered_by
#             }
#             df_log = pd.concat([df_log, pd.DataFrame([log_entry])], ignore_index=True)

#             # Save both files
#             save_inventory(df_inventory)
#             save_transfer_log(df_log)

#             st.success(f"✅ Transfer logged: {from_owner} → {new_owner}")

# # TAB 3 – View Transfer Log
# with tab3:
#     st.subheader("Transfer Log History")
#     df_log = load_transfer_log()
#     st.dataframe(df_log)

# # TAB 4 – Export Files
# with tab4:
#     st.subheader("Download Updated Files")

#     # Export inventory
#     output_inv = BytesIO()
#     with pd.ExcelWriter(output_inv, engine="openpyxl") as writer:
#         df_inventory.to_excel(writer, index=False)
#     st.download_button(
#         label="⬇ Download Inventory",
#         data=output_inv.getvalue(),
#         file_name="truckinventory_updated.xlsx",
#         mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
#     )

#     # Export transfer log
#     df_log = load_transfer_log()
#     output_log = BytesIO()
#     with pd.ExcelWriter(output_log, engine="openpyxl") as writer:
#         df_log.to_excel(writer, index=False)
#     st.download_button(
#         label="⬇ Download Transfer Log",
#         data=output_log.getvalue(),
#         file_name="transferlog_updated.xlsx",
#         mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
#     )

# import streamlit as st
# import pandas as pd
# from datetime import datetime
# from io import BytesIO
# import os
# import shutil

# # ========================
# # SECURITY: Simple password login
# # ========================
# PASSWORD = st.secrets.get("app_password", "admin123")  # set in secrets.toml

# st.set_page_config(page_title="Trucking Inventory System", page_icon="🚚", layout="wide")
# st.title("🚚 Trucking Inventory Management System")

# if "authenticated" not in st.session_state:
#     st.session_state.authenticated = False

# if not st.session_state.authenticated:
#     entered_password = st.text_input("Enter system password", type="password")
#     if st.button("Login"):
#         if entered_password == PASSWORD:
#             st.session_state.authenticated = True
#             st.rerun()
#         else:
#             st.error("❌ Incorrect password")
#     st.stop()

# # ========================
# # File Paths
# # ========================
# INVENTORY_FILE = "truckinventory.xlsx"
# TRANSFER_LOG_FILE = "transferlog.xlsx"
# BACKUP_FOLDER = "backups"
# os.makedirs(BACKUP_FOLDER, exist_ok=True)

# # ========================
# # Helper Functions
# # ========================
# def backup_file(file_path):
#     """Create timestamped backup of a file."""
#     if os.path.exists(file_path):
#         backup_name = f"{BACKUP_FOLDER}/{os.path.basename(file_path).split('.')[0]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
#         shutil.copy(file_path, backup_name)

# def load_inventory():
#     return pd.read_excel(INVENTORY_FILE)

# def load_transfer_log():
#     try:
#         return pd.read_excel(TRANSFER_LOG_FILE)
#     except FileNotFoundError:
#         df = pd.DataFrame(columns=[
#             "Device Type", "Serial Number", "From owner", "To owner",
#             "Date issued", "Registered by"
#         ])
#         df.to_excel(TRANSFER_LOG_FILE, index=False)
#         return df

# def save_inventory(df):
#     backup_file(INVENTORY_FILE)
#     df.to_excel(INVENTORY_FILE, index=False)

# def save_transfer_log(df):
#     backup_file(TRANSFER_LOG_FILE)
#     df.to_excel(TRANSFER_LOG_FILE, index=False)

# # ========================
# # Streamlit Tabs
# # ========================
# tab1, tab2, tab3, tab4 = st.tabs([
#     "📦 View Inventory", 
#     "🔄 Transfer Device", 
#     "📜 View Transfer Log", 
#     "⬇ Export Files"
# ])

# # TAB 1 – View Inventory
# with tab1:
#     st.subheader("Current Inventory")
#     df_inventory = load_inventory()
#     st.dataframe(df_inventory)

# # TAB 2 – Transfer Device
# with tab2:
#     st.subheader("Register Ownership Transfer")

#     serial_number = st.text_input("Enter Serial Number")
#     new_owner = st.text_input("Enter NEW Owner's Name")
#     registered_by = st.text_input("Registered By (IT Staff)")

#     if st.button("Transfer Now"):
#         if not serial_number.strip() or not new_owner.strip() or not registered_by.strip():
#             st.error("⚠ All fields are required.")
#             st.stop()

#         df_inventory = load_inventory()
#         df_log = load_transfer_log()

#         if serial_number not in df_inventory["Serial Number"].values:
#             st.error(f"Device with Serial Number {serial_number} not found!")
#         else:
#             idx = df_inventory[df_inventory["Serial Number"] == serial_number].index[0]
#             from_owner = df_inventory.loc[idx, "From owner"] if "From owner" in df_inventory.columns else df_inventory.loc[idx, "USER"]
#             device_type = df_inventory.loc[idx, "Device Type"]

#             # Update inventory
#             df_inventory.loc[idx, "From owner"] = from_owner
#             df_inventory.loc[idx, "To owner"] = new_owner
#             df_inventory.loc[idx, "Date issued"] = datetime.now().strftime("%m/%d/%Y %H:%M:%S")
#             df_inventory.loc[idx, "Registered by"] = registered_by

#             # Append to transfer log
#             log_entry = {
#                 "Device Type": device_type,
#                 "Serial Number": serial_number,
#                 "From owner": from_owner,
#                 "To owner": new_owner,
#                 "Date issued": datetime.now().strftime("%m/%d/%Y %H:%M:%S"),
#                 "Registered by": registered_by
#             }
#             df_log = pd.concat([df_log, pd.DataFrame([log_entry])], ignore_index=True)

#             # Save updated files
#             save_inventory(df_inventory)
#             save_transfer_log(df_log)

#             st.success(f"✅ Transfer logged: {from_owner} → {new_owner}")

# # TAB 3 – View Transfer Log
# with tab3:
#     st.subheader("Transfer Log History")
#     df_log = load_transfer_log()
#     st.dataframe(df_log)

# # TAB 4 – Export Files
# with tab4:
#     st.subheader("Download Updated Files")

#     # Inventory download
#     output_inv = BytesIO()
#     with pd.ExcelWriter(output_inv, engine="openpyxl") as writer:
#         df_inventory.to_excel(writer, index=False)
#     st.download_button(
#         label="⬇ Download Inventory",
#         data=output_inv.getvalue(),
#         file_name="truckinventory_updated.xlsx",
#         mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
#     )

#     # Transfer log download
#     df_log = load_transfer_log()
#     output_log = BytesIO()
#     with pd.ExcelWriter(output_log, engine="openpyxl") as writer:
#         df_log.to_excel(writer, index=False)
#     st.download_button(
#         label="⬇ Download Transfer Log",
#         data=output_log.getvalue(),
#         file_name="transferlog_updated.xlsx",
#         mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
#     )



# import streamlit as st
# import pandas as pd
# from datetime import datetime
# from io import BytesIO
# import os
# import shutil

# # ========================
# # SECURITY: Role-based login
# # ========================
# USERS = st.secrets.get("users", {
#     "admin": {"password": "admin123", "role": "admin"},
#     "viewer": {"password": "viewer123", "role": "viewer"}
# })

# st.set_page_config(page_title="Trucking Inventory System", page_icon="🚚", layout="wide")
# st.title("🚚 Trucking Inventory Management System")

# if "authenticated" not in st.session_state:
#     st.session_state.authenticated = False
#     st.session_state.role = None

# if not st.session_state.authenticated:
#     username = st.text_input("Username")
#     password = st.text_input("Password", type="password")

#     if st.button("Login"):
#         if username in USERS and USERS[username]["password"] == password:
#             st.session_state.authenticated = True
#             st.session_state.role = USERS[username]["role"]
#             st.rerun()
#         else:
#             st.error("❌ Incorrect username or password")
#     st.stop()

# role = st.session_state.role
# st.info(f"Logged in as **{role.upper()}**")

# # ========================
# # File Paths
# # ========================
# INVENTORY_FILE = "truckinventory.xlsx"
# TRANSFER_LOG_FILE = "transferlog.xlsx"
# BACKUP_FOLDER = "backups"
# os.makedirs(BACKUP_FOLDER, exist_ok=True)

# # ========================
# # Helper Functions
# # ========================
# def backup_file(file_path):
#     """Create timestamped backup of a file."""
#     if os.path.exists(file_path):
#         backup_name = f"{BACKUP_FOLDER}/{os.path.basename(file_path).split('.')[0]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
#         shutil.copy(file_path, backup_name)

# def load_inventory():
#     return pd.read_excel(INVENTORY_FILE)

# def load_transfer_log():
#     try:
#         return pd.read_excel(TRANSFER_LOG_FILE)
#     except FileNotFoundError:
#         df = pd.DataFrame(columns=[
#             "Device Type", "Serial Number", "From owner", "To owner",
#             "Date issued", "Registered by"
#         ])
#         df.to_excel(TRANSFER_LOG_FILE, index=False)
#         return df

# def save_inventory(df):
#     backup_file(INVENTORY_FILE)
#     df.to_excel(INVENTORY_FILE, index=False)

# def save_transfer_log(df):
#     backup_file(TRANSFER_LOG_FILE)
#     df.to_excel(TRANSFER_LOG_FILE, index=False)

# # ========================
# # Streamlit Tabs
# # ========================
# if role == "admin":
#     tab1, tab2, tab3, tab4 = st.tabs([
#         "📦 View Inventory", 
#         "🔄 Transfer Device", 
#         "📜 View Transfer Log", 
#         "⬇ Export Files"
#     ])
# else:
#     tab1, tab3 = st.tabs([
#         "📦 View Inventory", 
#         "📜 View Transfer Log"
#     ])

# # TAB 1 – View Inventory
# with tab1:
#     st.subheader("Current Inventory")
#     df_inventory = load_inventory()
#     st.dataframe(df_inventory)

# # TAB 2 – Transfer Device (Admins only)
# if role == "admin":
#     with tab2:
#         st.subheader("Register Ownership Transfer")

#         serial_number = st.text_input("Enter Serial Number")
#         new_owner = st.text_input("Enter NEW Owner's Name")
#         registered_by = st.text_input("Registered By (IT Staff)")

#         if st.button("Transfer Now"):
#             if not serial_number.strip() or not new_owner.strip() or not registered_by.strip():
#                 st.error("⚠ All fields are required.")
#                 st.stop()

#             df_inventory = load_inventory()
#             df_log = load_transfer_log()

#             if serial_number not in df_inventory["Serial Number"].values:
#                 st.error(f"Device with Serial Number {serial_number} not found!")
#             else:
#                 idx = df_inventory[df_inventory["Serial Number"] == serial_number].index[0]
#                 from_owner = df_inventory.loc[idx, "From owner"] if "From owner" in df_inventory.columns else df_inventory.loc[idx, "USER"]
#                 device_type = df_inventory.loc[idx, "Device Type"]

#                 # Update inventory
#                 df_inventory.loc[idx, "From owner"] = from_owner
#                 df_inventory.loc[idx, "To owner"] = new_owner
#                 df_inventory.loc[idx, "Date issued"] = datetime.now().strftime("%m/%d/%Y %H:%M:%S")
#                 df_inventory.loc[idx, "Registered by"] = registered_by

#                 # Append to transfer log
#                 log_entry = {
#                     "Device Type": device_type,
#                     "Serial Number": serial_number,
#                     "From owner": from_owner,
#                     "To owner": new_owner,
#                     "Date issued": datetime.now().strftime("%m/%d/%Y %H:%M:%S"),
#                     "Registered by": registered_by
#                 }
#                 df_log = pd.concat([df_log, pd.DataFrame([log_entry])], ignore_index=True)

#                 # Save updated files
#                 save_inventory(df_inventory)
#                 save_transfer_log(df_log)

#                 st.success(f"✅ Transfer logged: {from_owner} → {new_owner}")

# # TAB 3 – View Transfer Log
# with tab3:
#     st.subheader("Transfer Log History")
#     df_log = load_transfer_log()
#     st.dataframe(df_log)

# # TAB 4 – Export Files (Admins only)
# if role == "admin":
#     with tab4:
#         st.subheader("Download Updated Files")

#         # Inventory download
#         output_inv = BytesIO()
#         with pd.ExcelWriter(output_inv, engine="openpyxl") as writer:
#             df_inventory.to_excel(writer, index=False)
#         st.download_button(
#             label="⬇ Download Inventory",
#             data=output_inv.getvalue(),
#             file_name="truckinventory_updated.xlsx",
#             mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
#         )

#         # Transfer log download
#         df_log = load_transfer_log()
#         output_log = BytesIO()
#         with pd.ExcelWriter(output_log, engine="openpyxl") as writer:
#             df_log.to_excel(writer, index=False)
#         st.download_button(
#             label="⬇ Download Transfer Log",
#             data=output_log.getvalue(),
#             file_name="transferlog_updated.xlsx",
#             mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
#         )

# import streamlit as st
# import pandas as pd
# from datetime import datetime
# from io import BytesIO
# import os
# import shutil

# # ========================
# # SECURITY: Role-based login
# # ========================
# USERS = st.secrets.get("users", {})

# st.set_page_config(page_title="Trucking Inventory System", page_icon="🚚", layout="wide")
# st.title("🚚 Trucking Inventory Management System")

# if "authenticated" not in st.session_state:
#     st.session_state.authenticated = False
#     st.session_state.role = None

# if not st.session_state.authenticated:
#     username = st.text_input("Username")
#     entered_password = st.text_input("Password", type="password")
#     if st.button("Login"):
#         if username in USERS and entered_password == USERS[username]["password"]:
#             st.session_state.authenticated = True
#             st.session_state.role = USERS[username]["role"]
#             st.rerun()
#         else:
#             st.error("❌ Invalid username or password")
#     st.stop()

# role = st.session_state.role
# st.write(f"**Logged in as:** {role.upper()}")

# # ========================
# # File Paths
# # ========================
# INVENTORY_FILE = "truckinventory.xlsx"
# TRANSFER_LOG_FILE = "transferlog.xlsx"
# BACKUP_FOLDER = "backups"
# os.makedirs(BACKUP_FOLDER, exist_ok=True)

# # ========================
# # Helper Functions
# # ========================
# def backup_file(file_path):
#     """Create timestamped backup of a file."""
#     if os.path.exists(file_path):
#         backup_name = f"{BACKUP_FOLDER}/{os.path.basename(file_path).split('.')[0]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
#         shutil.copy(file_path, backup_name)

# def load_inventory():
#     return pd.read_excel(INVENTORY_FILE)

# def load_transfer_log():
#     try:
#         return pd.read_excel(TRANSFER_LOG_FILE)
#     except FileNotFoundError:
#         df = pd.DataFrame(columns=[
#             "Device Type", "Serial Number", "From owner", "To owner",
#             "Date issued", "Registered by"
#         ])
#         df.to_excel(TRANSFER_LOG_FILE, index=False)
#         return df

# def save_inventory(df):
#     backup_file(INVENTORY_FILE)
#     df.to_excel(INVENTORY_FILE, index=False)

# def save_transfer_log(df):
#     backup_file(TRANSFER_LOG_FILE)
#     df.to_excel(TRANSFER_LOG_FILE, index=False)

# # ========================
# # Tabs based on role
# # ========================
# if role == "admin":
#     tabs = ["📦 View Inventory", "🔄 Transfer Device", "📜 View Transfer Log", "⬇ Export Files"]
# elif role == "staff":
#     tabs = ["📦 View Inventory", "🔄 Transfer Device", "📜 View Transfer Log"]

# tab_objects = st.tabs(tabs)

# # TAB 1 – View Inventory
# with tab_objects[0]:
#     st.subheader("Current Inventory")
#     df_inventory = load_inventory()
#     st.dataframe(df_inventory)

# # TAB 2 – Transfer Device
# with tab_objects[1]:
#     st.subheader("Register Ownership Transfer")

#     serial_number = st.text_input("Enter Serial Number")
#     new_owner = st.text_input("Enter NEW Owner's Name")
#     registered_by = st.text_input("Registered By (IT Staff)")

#     if st.button("Transfer Now"):
#         if not serial_number.strip() or not new_owner.strip() or not registered_by.strip():
#             st.error("⚠ All fields are required.")
#             st.stop()

#         df_inventory = load_inventory()
#         df_log = load_transfer_log()

#         if serial_number not in df_inventory["Serial Number"].values:
#             st.error(f"Device with Serial Number {serial_number} not found!")
#         else:
#             idx = df_inventory[df_inventory["Serial Number"] == serial_number].index[0]
#             from_owner = df_inventory.loc[idx, "From owner"] if "From owner" in df_inventory.columns else df_inventory.loc[idx, "USER"]
#             device_type = df_inventory.loc[idx, "Device Type"]

#             # Update inventory
#             df_inventory.loc[idx, "From owner"] = from_owner
#             df_inventory.loc[idx, "To owner"] = new_owner
#             df_inventory.loc[idx, "Date issued"] = datetime.now().strftime("%m/%d/%Y %H:%M:%S")
#             df_inventory.loc[idx, "Registered by"] = registered_by

#             # Append to transfer log
#             log_entry = {
#                 "Device Type": device_type,
#                 "Serial Number": serial_number,
#                 "From owner": from_owner,
#                 "To owner": new_owner,
#                 "Date issued": datetime.now().strftime("%m/%d/%Y %H:%M:%S"),
#                 "Registered by": registered_by
#             }
#             df_log = pd.concat([df_log, pd.DataFrame([log_entry])], ignore_index=True)

#             # Save updated files
#             save_inventory(df_inventory)
#             save_transfer_log(df_log)

#             st.success(f"✅ Transfer logged: {from_owner} → {new_owner}")

# # TAB 3 – View Transfer Log
# with tab_objects[2]:
#     st.subheader("Transfer Log History")
#     df_log = load_transfer_log()
#     st.dataframe(df_log)

# # TAB 4 – Export Files (Admin Only)
# if role == "admin" and len(tab_objects) > 3:
#     with tab_objects[3]:
#         st.subheader("Download Updated Files")

#         # Inventory download
#         output_inv = BytesIO()
#         with pd.ExcelWriter(output_inv, engine="openpyxl") as writer:
#             df_inventory.to_excel(writer, index=False)
#         st.download_button(
#             label="⬇ Download Inventory",
#             data=output_inv.getvalue(),
#             file_name="truckinventory_updated.xlsx",
#             mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
#         )

#         # Transfer log download
#         df_log = load_transfer_log()
#         output_log = BytesIO()
#         with pd.ExcelWriter(output_log, engine="openpyxl") as writer:
#             df_log.to_excel(writer, index=False)
#         st.download_button(
#             label="⬇ Download Transfer Log",
#             data=output_log.getvalue(),
#             file_name="transferlog_updated.xlsx",
#             mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
#         )




import streamlit as st
import pandas as pd
from datetime import datetime
from io import BytesIO
import bcrypt
import json
import os
import shutil

# ========================
# Load Users from Secrets
# ========================
USERS = json.loads(st.secrets["users_json"])

# ========================
# File Paths
# ========================
INVENTORY_FILE = "truckinventory.xlsx"
TRANSFER_LOG_FILE = "transferlog.xlsx"
BACKUP_FOLDER = "backups"
os.makedirs(BACKUP_FOLDER, exist_ok=True)

# ========================
# Helper Functions
# ========================
def backup_file(file_path):
    """Create timestamped backup of a file."""
    if os.path.exists(file_path):
        backup_name = f"{BACKUP_FOLDER}/{os.path.basename(file_path).split('.')[0]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        shutil.copy(file_path, backup_name)

def load_inventory():
    return pd.read_excel(INVENTORY_FILE)

def load_transfer_log():
    try:
        return pd.read_excel(TRANSFER_LOG_FILE)
    except FileNotFoundError:
        df = pd.DataFrame(columns=[
            "Device Type", "Serial Number", "From owner", "To owner",
            "Date issued", "Registered by"
        ])
        df.to_excel(TRANSFER_LOG_FILE, index=False)
        return df

def save_inventory(df):
    backup_file(INVENTORY_FILE)
    df.to_excel(INVENTORY_FILE, index=False)

def save_transfer_log(df):
    backup_file(TRANSFER_LOG_FILE)
    df.to_excel(TRANSFER_LOG_FILE, index=False)

def check_credentials(username, password):
    """Verify username and password."""
    for user in USERS:
        if user["username"] == username:
            if bcrypt.checkpw(password.encode(), user["password"].encode()):
                return user["role"]
    return None

# ========================
# Streamlit App Config
# ========================
st.set_page_config(page_title="Trucking Inventory System", page_icon="🚚", layout="wide")
st.title("🚚 Trucking Inventory Management System")

# ========================
# Login
# ========================
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
    st.session_state.role = None

if not st.session_state.authenticated:
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        role = check_credentials(username, password)
        if role:
            st.session_state.authenticated = True
            st.session_state.role = role
            st.success(f"✅ Logged in as {username} ({role})")
            st.rerun()
        else:
            st.error("❌ Invalid username or password")
    st.stop()

# ========================
# Tabs
# ========================
tabs = ["📦 View Inventory", "🔄 Transfer Device", "📜 View Transfer Log"]
if st.session_state.role == "admin":
    tabs.append("⚙ Manage Users")
tabs.append("⬇ Export Files")

tab_objects = st.tabs(tabs)

# TAB 1 – View Inventory
with tab_objects[0]:
    st.subheader("Current Inventory")
    df_inventory = load_inventory()
    st.dataframe(df_inventory)

# TAB 2 – Transfer Device
with tab_objects[1]:
    st.subheader("Register Ownership Transfer")

    serial_number = st.text_input("Enter Serial Number")
    new_owner = st.text_input("Enter NEW Owner's Name")
    registered_by = st.text_input("Registered By (IT Staff)")

    if st.button("Transfer Now"):
        if not serial_number.strip() or not new_owner.strip() or not registered_by.strip():
            st.error("⚠ All fields are required.")
            st.stop()

        df_inventory = load_inventory()
        df_log = load_transfer_log()

        if serial_number not in df_inventory["Serial Number"].values:
            st.error(f"Device with Serial Number {serial_number} not found!")
        else:
            idx = df_inventory[df_inventory["Serial Number"] == serial_number].index[0]
            from_owner = df_inventory.loc[idx, "From owner"] if "From owner" in df_inventory.columns else df_inventory.loc[idx, "USER"]
            device_type = df_inventory.loc[idx, "Device Type"]

            # Update inventory
            df_inventory.loc[idx, "From owner"] = from_owner
            df_inventory.loc[idx, "To owner"] = new_owner
            df_inventory.loc[idx, "Date issued"] = datetime.now().strftime("%m/%d/%Y %H:%M:%S")
            df_inventory.loc[idx, "Registered by"] = registered_by

            # Append to transfer log
            log_entry = {
                "Device Type": device_type,
                "Serial Number": serial_number,
                "From owner": from_owner,
                "To owner": new_owner,
                "Date issued": datetime.now().strftime("%m/%d/%Y %H:%M:%S"),
                "Registered by": registered_by
            }
            df_log = pd.concat([df_log, pd.DataFrame([log_entry])], ignore_index=True)

            # Save updated files
            save_inventory(df_inventory)
            save_transfer_log(df_log)

            st.success(f"✅ Transfer logged: {from_owner} → {new_owner}")

# TAB 3 – View Transfer Log
with tab_objects[2]:
    st.subheader("Transfer Log History")
    df_log = load_transfer_log()
    st.dataframe(df_log)

# TAB 4 – Manage Users (Admin only)
if st.session_state.role == "admin":
    with tab_objects[3]:
        st.subheader("User Management")
        st.info("Coming soon: Admin tools for adding/removing users")

# Last Tab – Export Files
export_tab_index = -1 if st.session_state.role != "admin" else -1
with tab_objects[export_tab_index]:
    st.subheader("Download Updated Files")

    # Inventory
    output_inv = BytesIO()
    with pd.ExcelWriter(output_inv, engine="openpyxl") as writer:
        df_inventory.to_excel(writer, index=False)
    st.download_button(
        label="⬇ Download Inventory",
        data=output_inv.getvalue(),
        file_name="truckinventory_updated.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

    # Transfer Log
    df_log = load_transfer_log()
    output_log = BytesIO()
    with pd.ExcelWriter(output_log, engine="openpyxl") as writer:
        df_log.to_excel(writer, index=False)
    st.download_button(
        label="⬇ Download Transfer Log",
        data=output_log.getvalue(),
        file_name="transferlog_updated.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )
