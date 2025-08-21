import streamlit as st
from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive
import json

# Load credentials from secrets.toml
try:
    gauth_settings = json.loads(st.secrets["google_drive_credentials"])
except KeyError:
    st.error("Google Drive credentials not found in secrets.toml.")
    st.stop()

# Authenticate with Google Drive
gauth = GoogleAuth(settings=gauth_settings)
drive = GoogleDrive(gauth)

# Example: List files in a specific folder (replace with your folder ID)
folder_id = 'YOUR_GOOGLE_DRIVE_FOLDER_ID'
file_list = drive.ListFile({'q': f"'{folder_id}' in parents and trashed=false"}).GetList()

st.write("Files in Google Drive folder:")
for file in file_list:
    st.write(f"- {file['title']} (ID: {file['id']})")

# Example: Download a specific file
# file_id = 'YOUR_FILE_ID'
# file = drive.CreateFile({'id': file_id})
# file.GetContentFile('downloaded_file.txt')
# st.write("File downloaded successfully!")
