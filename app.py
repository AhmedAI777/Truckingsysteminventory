import streamlit as st
import pandas as pd
import sqlite3
from pathlib import Path
from datetime import datetime

# ------------------ CONFIG ------------------
st.set_page_config(page_title="Trucking Inventory System", page_icon="🚚")

DB_FILE = Path(__file__).parent / "trucking_inventory.db"

# ------------------ USER LOGIN CONFIG ------------------
USERS = {
    "admin": {"password": "admin123", "role": "admin"},
    "it_engineer": {"password": "itpass", "role": "editor"},
    "viewer": {"password": "viewpass", "role": "viewer"}
}

# ------------------ DATABASE FUNCTIONS ------------------
def connect_db():
    conn = sqlite3.connect(DB_FILE)
    return conn

def init_db():
    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS inventory (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        serial_number TEXT UNIQUE,
        device_type TEXT,
        previous_user TEXT,
        current_user TEXT,
        to_user TEXT,
        date_issued TEXT,
        registered_by TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS transfer_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        serial_number TEXT,
        device_type TEXT,
        from_owner TEXT,
        to_owner TEXT,
        date_issued TEXT,
        registered_by TEXT
    )
    """)

    conn.commit()
    conn.close()

def load_inventory():
    conn = connect_db()
    df = pd.read_sql("SELECT * FROM inventory", conn)
    conn.close()
    return df

def save_inventory(df):
    conn = connect_db()
    cursor = conn.cursor()

    for _, row in df.iterrows():
        cursor.execute("""
        INSERT OR REPLACE INTO inventory
        (id, serial_number, device_type, previous_user, current_user, to_user, date_issued, registered_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, tuple(row))
    conn.commit()
    conn.close()

def register_transfer(serial_number, new_owner, registered_by):
    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM inventory WHERE serial_number=?", (serial_number,))
    device = cursor.fetchone()

    if not device:
        st.error(f"Device with Serial Number '{serial_number}' not found!")
        conn.close()
        return

    _, sn, device_type, prev_user, curr_user, _, _, _ = device

    cursor.execute("""
    UPDATE inventory
    SET previous_user = ?,
        current_user = ?,
        to_user = ?,
        date_issued = ?,
        registered_by = ?
    WHERE serial_number = ?
    """, (curr_user, new_owner, new_owner, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), registered_by, serial_number))

    cursor.execute("""
    INSERT INTO transfer_log (serial_number, device_type, from_owner, to_owner, date_issued, registered_by)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (serial_number, device_type, curr_user, new_owner, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), registered_by))

    conn.commit()
    conn.close()
    st.success(f"Transfer successful: {curr_user} → {new_owner}")

def load_transfer_log():
    conn = connect_db()
    df = pd.read_sql("SELECT * FROM transfer_log", conn)
    conn.close()
    return df

# ------------------ LOGIN ------------------
def login():
    st.title("🔑 Trucking Inventory Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username in USERS and USERS[username]["password"] == password:
            st.session_state.logged_in = True
            st.session_state.username = username
            st.session_state.role = USERS[username]["role"]
            st.success("Login successful!")
            st.experimental_rerun()
        else:
            st.error("Invalid username or password")

# ------------------ MAIN APP ------------------
def main_app():
    st.sidebar.success(f"Logged in as: {st.session_state.username} ({st.session_state.role})")
    if st.sidebar.button("🚪 Logout"):
        st.session_state.clear()
        st.experimental_rerun()

    st.title("🚚 Trucking Inventory Transfer System")

    init_db()

    tab1, tab2, tab3 = st.tabs(["📋 Inventory", "🔄 Transfer", "📜 Transfer Log"])

    with tab1:
        st.subheader("Inventory Overview & Editing")
        inventory_df = load_inventory()

        if st.session_state.role in ["admin", "editor"]:
            edited_df = st.data_editor(
                inventory_df,
                disabled=["id", "serial_number", "date_issued", "registered_by"],
                num_rows="dynamic",
                key="inventory_table"
            )

            if st.button("💾 Save Inventory Changes"):
                save_inventory(edited_df)
                st.success("Inventory updated successfully!")
        else:
            st.dataframe(inventory_df)

    with tab2:
        if st.session_state.role in ["admin", "editor"]:
            st.subheader("Register a New Transfer")
            serial_number = st.text_input("Serial Number")
            new_owner = st.text_input("New Owner")
            registered_by = st.session_state.username

            if st.button("✅ Perform Transfer"):
                if serial_number and new_owner:
                    register_transfer(serial_number, new_owner, registered_by)
                else:
                    st.error("Please fill in all fields!")
        else:
            st.warning("You do not have permission to perform transfers.")

    with tab3:
        st.subheader("Full Transfer History")
        transfer_log_df = load_transfer_log()
        st.dataframe(transfer_log_df)

        st.download_button(
            label="⬇️ Download Transfer Log (CSV)",
            data=transfer_log_df.to_csv(index=False),
            file_name="transfer_log.csv",
            mime="text/csv"
        )

# ------------------ RUN APP ------------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if not st.session_state.logged_in:
    login()
else:
    main_app()
