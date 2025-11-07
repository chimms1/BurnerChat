import sqlite3
import os
import sys

print("Setting up cryptographic environment (SQLite)...")

# --- Configuration ---
PEER_IDS = ['yash', 'rigved']
DATABASE_FILE = 'chat_keys.db'

# --- 1. Create the SQLite Database and Table ---
print(f"Creating/Updating SQLite database at '{DATABASE_FILE}'...")
try:
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    
    # Create the table.
    # id: 'peer_A', 'peer_B', etc.
    # public_key: The PEM-formatted RSA public key (as TEXT)
    # master_key: The raw derived ECDHE key (as BLOB), NULLable
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS peers (
        id TEXT PRIMARY KEY NOT NULL,
        public_key TEXT NOT NULL,
        master_key BLOB
    )
    ''')
    print("  Database table 'peers' created or already exists.")

    # --- 2. Load Public Keys from .pem files ---
    for peer_id in PEER_IDS:
        pub_key_filename = f"{peer_id}_pub.pem"
        print(f"  Looking for '{pub_key_filename}' for {peer_id}...")
        
        if not os.path.exists(pub_key_filename):
            print(f"  [!] ERROR: Public key file not found: {pub_key_filename}")
            continue

        try:
            # Read the public key file content as text
            with open(pub_key_filename, 'r') as f:
                public_key_pem = f.read()

            # Insert or Replace the peer's public key into the database
            # The master_key will be NULL by default
            cursor.execute('''
            INSERT OR REPLACE INTO peers (id, public_key)
            VALUES (?, ?)
            ''', (peer_id, public_key_pem))
            
            print(f"    Successfully loaded and stored public key for {peer_id}.")

        except Exception as e:
            print(f"    [!] FAILED to load or insert key for {peer_id}: {e}")

    # Commit changes and close
    conn.commit()
    conn.close()
    
    print("\nSQLite database setup complete.")
    print("You can now run the secure_chat.py script.")
    print("Example:")
    print("  Terminal 1: python secure_chat.py peer_A")
    print("  Terminal 2: python secure_chat.py peer_B")

except sqlite3.Error as e:
    print(f"[!] CRITICAL: An error occurred with the SQLite database: {e}")
    sys.exit(1)