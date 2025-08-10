import streamlit as st
import gspread
from google.oauth2.service_account import Credentials
import pandas as pd

# ----------------------------
# GOOGLE SHEETS AUTHENTICATION
# ----------------------------
# Load credentials from Streamlit secrets (set in App settings > Secrets)
creds = Credentials.from_service_account_info(st.secrets["gcp_service_account"])
client = gspread.authorize(creds)

# Open your sheet
SHEET_NAME = "truckinventory"  # <-- Change to the exact name of your Google Sheet
worksheet = client.open(SHEET_NAME).sheet1


# ----------------------------
# FUNCTIONS
# ----------------------------
def load_inventory():
    """Load inventory from Google Sheets into DataFrame."""
    data = worksheet.get_all_records()
    if not data:
        return pd.DataFrame()
    return pd.DataFrame(data)


def save_inventory(df):
    """Save DataFrame to Google Sheets."""
    worksheet.clear()
    worksheet.update([df.columns.tolist()] + df.values.tolist())


# ----------------------------
# STREAMLIT UI
# ----------------------------
st.set_page_config(page_title="Trucking Inventory", layout="wide")
st.title("🚚 Trucking Inventory System")

# Load data
df = load_inventory()

if df.empty:
    st.warning("No inventory data found in Google Sheets.")
else:
    st.subheader("Current Inventory")
    edited_df = st.data_editor(df, num_rows="dynamic")

    if st.button("Save Changes to Google Sheets"):
        save_inventory(edited_df)
        st.success("✅ Inventory saved successfully to Google Sheets!")


# ----------------------------
# ADD NEW TRANSFER RECORD
# ----------------------------
st.subheader("Add Transfer Log")
with st.form("transfer_form"):
    serial_number = st.selectbox("Select Serial Number", df["Serial Number"] if not df.empty else [])
    new_owner = st.text_input("Enter New Owner")
    registered_by = st.text_input("Registered By")
    submitted = st.form_submit_button("Submit Transfer")

    if submitted:
        import datetime
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        new_row = {
            "Serial Number": serial_number,
            "To owner": new_owner,
            "Registered By": registered_by,
            "Date issued": now
        }
        df = pd.concat([df, pd.DataFrame([new_row])], ignore_index=True)
        save_inventory(df)
        st.success("✅ Transfer logged successfully!")
