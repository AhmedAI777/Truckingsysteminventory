import streamlit as st
import pandas as pd
import os
from datetime import datetime

# ===== Load Secrets =====
USERNAME = st.secrets["USERNAME"]
PASSWORD = st.secrets["PASSWORD"]

# ===== Trucking System Class =====
class TruckingSystem:
    def __init__(self, inventory_path, transfer_log_path):
        self.inventory_path = inventory_path
        self.transfer_log_path = transfer_log_path

        # Load inventory
        self.inventory_df = pd.read_excel(inventory_path)

        # Load transfer log
        self.transfer_log = pd.read_excel(transfer_log_path)

    def register_transfer(self, serial_number, new_owner, user=None):
        matched = self.inventory_df[self.inventory_df["Serial Number"] == serial_number]
        if matched.empty:
            st.error(f"Device with Serial Number '{serial_number}' not found.")
            return

        from_owner = matched["USER"].values[0]
        device_type = matched["Device Type"].values[0]

        self.inventory_df.loc[self.inventory_df["Serial Number"] == serial_number, "Previous User"] = from_owner
        self.inventory_df.loc[self.inventory_df["Serial Number"] == serial_number, "USER"] = new_owner
        self.inventory_df.loc[self.inventory_df["Serial Number"] == serial_number, "TO"] = new_owner

        log_entry = {
            "Device Type": device_type,
            "Serial Number": serial_number,
            "From owner": from_owner,
            "To owner": new_owner,
            "Date issued": pd.Timestamp.now(),
            "Registered by": user or "IT Engineer"
        }

        self.transfer_log = pd.concat([self.transfer_log, pd.DataFrame([log_entry])], ignore_index=True)
        st.success("✅ Transfer Successful!")

    def save_files(self):
        self.inventory_df.to_excel(self.inventory_path, index=False)
        self.transfer_log.to_excel(self.transfer_log_path, index=False)
        st.info("Files saved successfully!")

# ===== Login Page =====
def login():
    st.title("🔑 Trucking Inventory Login")
    username_input = st.text_input("Username")
    password_input = st.text_input("Password", type="password")

    if st.button("Login"):
        if username_input == USERNAME and password_input == PASSWORD:
            st.session_state["logged_in"] = True
            st.experimental_rerun()
        else:
            st.error("❌ Invalid username or password")

# ===== Main App =====
def main_app():
    st.title("🚚 Trucking Inventory Management")

    inventory_path = "truckinventory.xlsx"
    transfer_log_path = "transferlogin.xlsx"

    system = TruckingSystem(inventory_path, transfer_log_path)

    st.subheader("Register a Transfer")
    serial_number = st.text_input("Enter Serial Number")
    new_owner = st.text_input("Enter NEW Owner")
    registered_by = st.text_input("Registered By", value="IT Engineer")

    if st.button("Submit Transfer"):
        system.register_transfer(serial_number, new_owner, registered_by)

    if st.button("Save Changes"):
        system.save_files()

    st.subheader("Current Inventory")
    st.dataframe(system.inventory_df)

    st.subheader("Transfer Log")
    st.dataframe(system.transfer_log)

# ===== Page Routing =====
if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False

if st.session_state["logged_in"]:
    main_app()
else:
    login()
