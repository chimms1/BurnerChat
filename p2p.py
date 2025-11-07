import socket
import threading
import queue
import sys
import time
import json
import base64
import os
import sqlite3

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature

# --- Configuration ---
MY_PORT = 42069
INACTIVITY_TIMEOUT = 60.0
DATABASE_FILE = 'chat_keys.db'


AES_KEY_SIZE = 16  # 16 bytes = 128 bits
IV_SIZE = 16       # AES block size

connection_requests = queue.Queue() # for incoming connection requests

stop_chat_thread = threading.Event()


def load_my_private_key(myid):
    
    filename = f"{myid}.pem"
    
    try:
        with open(filename, "rb") as key_file:
            
            return serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
            
    except FileNotFoundError:
        print(f"!! =>  CRITICAL: Private key file not found: {filename}")
        sys.exit(1)

def load_peer_public_key(peerid):
    
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT public_key FROM peers WHERE id = ?", (peerid,))
        row = cursor.fetchone()
        conn.close()
        
        if row and row[0]:
            # Key is stored as text, so encode to bytes
            pem_public = row[0].encode('utf-8')
            
            return serialization.load_pem_public_key(
                pem_public,
                backend=default_backend()
            )
            
        else:
            print(f"!! =>  No public key found in database for ID: {peerid}")
            return None
            
    except sqlite3.Error as e:
        print(f"!! =>  SQLite error while loading public key: {e}")
        return None
    except KeyError:
        print(f"!! =>  No public key found in database for ID: {peerid}")
        return None

def sign_data(privatekey, data):
    
    return privatekey.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

def verify_signature(publickey, signature, data):
    
    try:
        publickey.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
        
    except InvalidSignature:
        return False

def derive_session_key(masterkey):
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,  # 16 bytes for AES-128
        salt=None,
        info=b'p2p-chat-session-key',
        backend=default_backend()
    )
    return hkdf.derive(masterkey)

def encrypt_message(session_key, message_str):
    
    iv = os.urandom(IV_SIZE)
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad the message to be a multiple of the block size
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message_str.encode('utf-8')) + padder.finalize()
    
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    # Prepend the IV to the ciphertext. The receiver needs it.
    return iv + ciphertext

def decrypt_message(session_key, iv_and_ciphertext):
    """Decrypts an AES-128-CBC message (IV + Ciphertext)."""
    # Extract the IV from the front
    iv = iv_and_ciphertext[:IV_SIZE]
    ciphertext = iv_and_ciphertext[IV_SIZE:]
    
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Unpad the message
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    return data.decode('utf-8')

# --- 2. SECURE SOCKET HELPERS (Length-Prefixed) ---

def send_secure_message(sock, payload_bytes):
    """Prefixes a message with its 4-byte length and sends it."""
    try:
        msg_len = len(payload_bytes).to_bytes(4, 'big')
        sock.sendall(msg_len + payload_bytes)
    except (OSError, ConnectionResetError) as e:
        print(f"!! =>  Error sending message: {e}")
        raise # Re-raise to be caught by the chat loop

def recv_secure_message(sock):
    """Reads a 4-byte length prefix, then receives a full message."""
    try:
        # Read the 4-byte length prefix
        len_bytes = sock.recv(4)
        if not len_bytes:
            return None  # Connection closed
        
        msg_len = int.from_bytes(len_bytes, 'big')
        
        # Read the full message payload
        return sock.recv(msg_len)
    
    except (OSError, ConnectionResetError):
        return None # Connection closed
        
# --- 3. HANDSHAKE LOGIC ---
# 
# This is our custom "TLS-like" handshake

def perform_handshake_initiator(sock, my_id, my_private_key, peer_id):
    """Initiator side of the handshake."""
    print(f"--- Initiating handshake with {peer_id} ---")
    
    # 1. Check if we already have a master key
    masterkey = None
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT master_key FROM peers WHERE id = ?", (peer_id,))
        row = cursor.fetchone()
        conn.close()
        if row and row[0]:
            masterkey = row[0] # This will be BLOB (bytes) or None
    except sqlite3.Error as e:
        print(f"!! =>  SQLite error reading master key: {e}")

    # --- CASE 1: RESUME SESSION ---
    if masterkey:
        print("  Found existing master key. Attempting session resumption...")
        nonce = os.urandom(32)
        data_to_sign = my_id.encode() + nonce
        signature = sign_data(my_private_key, data_to_sign)
        
        handshake_msg = {
            'type': 'resume_1',
            'id': my_id,
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'sig': base64.b64encode(signature).decode('utf-8')
        }
        send_secure_message(sock, json.dumps(handshake_msg).encode())
        
        # Wait for resume_2
        response_bytes = recv_secure_message(sock)
        if not response_bytes:
            print("  Peer disconnected during resume.")
            return None
        
        response = json.loads(response_bytes.decode())
        
        if response.get('type') == 'resume_2':
            peer_rsa_pub = load_peer_public_key(peer_id)
            sig_data = response['id'].encode() + base64.b64decode(response['nonce'])
            if verify_signature(peer_rsa_pub, base64.b64decode(response['sig']), sig_data):
                print("[+] Session Resumed!")
                return derive_session_key(masterkey)
            else:
                print("!! =>  Resume ACK signature invalid! Aborting.")
                return None
        else:
            print(f"  Resume failed (peer responded with {response.get('type')}).")
            # Fall through to full handshake if peer didn't have key
            pass

    # --- CASE 2: FULL HANDSHAKE ---
    print("  Performing full ECDHE handshake...")
    # 1. Generate ephemeral ECDHE keys
    ec_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    ec_public_key = ec_private_key.public_key()
    ec_pub_bytes = ec_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # 2. Sign our ID + ephemeral public key
    data_to_sign = my_id.encode() + ec_pub_bytes
    signature = sign_data(my_private_key, data_to_sign)
    
    # 3. Send handshake_1
    handshake_1 = {
        'type': 'handshake_1',
        'id': my_id,
        'ec_pub_key': base64.b64encode(ec_pub_bytes).decode('utf-8'),
        'sig': base64.b64encode(signature).decode('utf-8')
    }
    send_secure_message(sock, json.dumps(handshake_1).encode())
    
    # 4. Wait for handshake_2
    response_bytes = recv_secure_message(sock)
    if not response_bytes:
        print("  Peer disconnected during handshake.")
        return None
        
    response = json.loads(response_bytes.decode())
    
    if response.get('type') != 'handshake_2' or response.get('id') != peer_id:
        print("!! =>  Invalid handshake_2 response. Aborting.")
        return None
        
    # 5. Verify peer's signature
    peer_ec_pub_bytes = base64.b64decode(response['ec_pub_key'])
    peer_sig = base64.b64decode(response['sig'])
    peer_rsa_pub = load_peer_public_key(peer_id)
    
    data_to_verify = response['id'].encode() + peer_ec_pub_bytes
    
    if not verify_signature(peer_rsa_pub, peer_sig, data_to_verify):
        print("!! =>  Peer's handshake signature is INVALID! Aborting.")
        return None
        
    print("  Peer signature verified.")
    
    # 6. Compute shared secret (Master Key)
    peer_ec_pub_key = serialization.load_pem_public_key(peer_ec_pub_bytes, default_backend())
    masterkey = ec_private_key.exchange(ec.ECDH(), peer_ec_pub_key)
    
    # 7. Store master key in our DB
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        # masterkey is bytes, which SQLite will store as BLOB
        cursor.execute("UPDATE peers SET master_key = ? WHERE id = ?", (masterkey, peer_id))
        conn.commit()
        conn.close()
        print("  New Master Key computed and stored.")
    except sqlite3.Error as e:
        print(f"!! =>  SQLite error storing master key: {e}")
    
    # 8. Derive session key
    return derive_session_key(masterkey)


def perform_handshake_receiver(sock, my_id, my_private_key):
    """Receiver side of the handshake."""
    print("--- Awaiting handshake ---")
    
    # 1. Receive initiator's first message
    msg_bytes = recv_secure_message(sock)
    if not msg_bytes:
        print("  Peer disconnected before handshake.")
        return None, None
        
    msg = json.loads(msg_bytes.decode())
    peer_id = msg.get('id')
    
    if not peer_id:
        print("!! =>  Handshake message has no ID. Aborting.")
        return None, None
        
    print(f"  Handshake attempt from {peer_id}.")
    peer_rsa_pub = load_peer_public_key(peer_id)
    if not peer_rsa_pub:
        print(f"!! =>  Unknown peer ID: {peer_id}. Aborting.")
        return None, None
        
    masterkey = None
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT master_key FROM peers WHERE id = ?", (peer_id,))
        row = cursor.fetchone()
        conn.close()
        if row and row[0]:
            masterkey = row[0]
    except sqlite3.Error as e:
        print(f"!! =>  SQLite error reading master key: {e}")


    # --- CASE 1: RESUME SESSION ---
    if msg.get('type') == 'resume_1':
        print(f"  Processing 'resume_1' from {peer_id}...")
        if not masterkey:
            print("  Peer wants to resume, but we have no key. Sending fail.")
            fail_msg = {'type': 'resume_fail_no_key'}
            send_secure_message(sock, json.dumps(fail_msg).encode())
            return None, None # Force them to start a full handshake
            
        # Verify their signature
        nonce = base64.b64decode(msg['nonce'])
        sig = base64.b64decode(msg['sig'])
        data_to_verify = peer_id.encode() + nonce
        
        if not verify_signature(peer_rsa_pub, sig, data_to_verify):
            print("!! =>  Peer's resume signature is INVALID! Aborting.")
            return None, None
            
        print("  Peer signature verified. Sending resume_2 ACK.")
        # Send our own ACK
        my_nonce = os.urandom(32)
        my_data_to_sign = my_id.encode() + my_nonce
        my_signature = sign_data(my_private_key, my_data_to_sign)
        
        resume_2 = {
            'type': 'resume_2',
            'id': my_id,
            'nonce': base64.b64encode(my_nonce).decode('utf-8'),
            'sig': base64.b64encode(my_signature).decode('utf-8')
        }
        send_secure_message(sock, json.dumps(resume_2).encode())
        print("[+] Session Resumed!")
        return derive_session_key(masterkey), peer_id

    # --- CASE 2: FULL HANDSHAKE ---
    elif msg.get('type') == 'handshake_1':
        print(f"  Processing 'handshake_1' from {peer_id}...")
        
        # 1. Verify peer's signature
        peer_ec_pub_bytes = base64.b64decode(msg['ec_pub_key'])
        peer_sig = base64.b64decode(msg['sig'])
        data_to_verify = peer_id.encode() + peer_ec_pub_bytes
        
        if not verify_signature(peer_rsa_pub, peer_sig, data_to_verify):
            print("!! =>  Peer's handshake signature is INVALID! Aborting.")
            return None, None
        
        print("  Peer signature verified.")
        
        # 2. Generate *our* ephemeral ECDHE keys
        ec_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        ec_public_key = ec_private_key.public_key()
        ec_pub_bytes = ec_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # 3. Compute shared secret (Master Key)
        peer_ec_pub_key = serialization.load_pem_public_key(peer_ec_pub_bytes, default_backend())
    masterkey = ec_private_key.exchange(ec.ECDH(), peer_ec_pub_key)
        
    # 4. Store master key in our DB
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute("UPDATE peers SET master_key = ? WHERE id = ?", (masterkey, peer_id))
        conn.commit()
        conn.close()
        print("  New Master Key computed and stored.")
    except sqlite3.Error as e:
        print(f"!! =>  SQLite error storing master key: {e}")
        
    # 5. Sign our ID + ephemeral public key
        data_to_sign = my_id.encode() + ec_pub_bytes
        signature = sign_data(my_private_key, data_to_sign)
        
        # 6. Send handshake_2
        handshake_2 = {
            'type': 'handshake_2',
            'id': my_id,
            'ec_pub_key': base64.b64encode(ec_pub_bytes).decode('utf-8'),
            'sig': base64.b64encode(signature).decode('utf-8')
        }
        send_secure_message(sock, json.dumps(handshake_2).encode())
        print("  Sent handshake_2.")
        
        # 7. Derive session key
        return derive_session_key(masterkey), peer_id
        
    else:
        print(f"!! =>  Unknown handshake message type: {msg.get('type')}")
        return None, None


# --- 4. The Listener Thread (Unchanged) ---

def start_listener(my_ip, my_port):
    """Listens for incoming connections and puts them in a queue."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        s.bind((my_ip, my_port))
        s.listen(5)
        print(f"[*] Listening on {my_ip}:{my_port}")

        while True:
            conn, addr = s.accept()
            print(f"\n!! =>  Incoming connection from {addr[0]}")
            connection_requests.put((conn, addr))
            
    except OSError as e:
        print(f"!! =>  Listener socket error: {e}")
    finally:
        s.close()
        
# --- 5. The Chat Session (Now with encryption) ---

def receive_messages(sock, session_key):
    """Target function for the receive thread."""
    global stop_chat_thread
    sock.settimeout(INACTIVITY_TIMEOUT)
    
    while not stop_chat_thread.is_set():
        try:
            # Use our secure (length-prefixed) receiver
            iv_and_ciphertext = recv_secure_message(sock)
            
            if not iv_and_ciphertext:
                # Connection closed by peer
                print("\n!! =>  Peer disconnected.")
                break
            
            # Decrypt the message
            message = decrypt_message(session_key, iv_and_ciphertext)
            print(f"\rPeer: {message}      \nYou: ", end="")

        except socket.timeout:
            print(f"\n!! =>  Chat timed out after {INACTIVITY_TIMEOUT}s of inactivity.")
            break
        except (OSError, ConnectionResetError):
            if not stop_chat_thread.is_set():
                print("\n!! =>  Connection error in receive thread.")
            break
        except Exception as e:
            print(f"\n!! =>  Decryption error: {e}. Possible key mismatch or tampered message.")
            break
            
    stop_chat_thread.set()
    try:
        sock.close()
    except OSError:
        pass 

def start_chat_session(conn, session_key):
    """Manages an active 1-on-1 ENCRYPTED chat."""
    global stop_chat_thread
    stop_chat_thread.clear()
    print("\n--- SECURE Chat Started! Type 'exit' to end. ---")

    receiver = threading.Thread(
        target=receive_messages, 
        args=(conn, session_key), 
        daemon=True
    )
    receiver.start()

    while not stop_chat_thread.is_set():
        try:
            message = input("You: ")
            
            if stop_chat_thread.is_set():
                print("!! =>  Connection is closed. Cannot send message.")
                break
                
            if message.lower() == 'exit':
                break

            # Encrypt the message
            iv_and_ciphertext = encrypt_message(session_key, message)
            
            # Send securely (with length prefix)
            send_secure_message(conn, iv_and_ciphertext)
            
        except (EOFError, KeyboardInterrupt):
            break
        except (OSError, ConnectionResetError):
            print("!! =>  Connection closed.")
            break
            
    stop_chat_thread.set()
    print("--- Chat Ended ---")
    
    if receiver.is_alive():
        receiver.join(1.0)
        
    if conn.fileno() != -1:
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        conn.close()

# --- 6. The Main (UI) Thread (Modified for handshake) ---

def main_ui():
    """The main user-facing loop."""
    
    # --- Load user ID and keys ---
    if len(sys.argv) < 2:
        print("Usage: python secure_chat.py <your_id>")
        print("Example: python secure_chat.py peer_A")
        sys.exit(1)
        
    MY_ID = sys.argv[1]
    print(f"Welcome, {MY_ID}!")
    MY_PRIVATE_KEY = load_my_private_key(MY_ID)
    print("Your RSA private key is loaded.")

    # --- Get network info ---
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        my_ip = s.getsockname()[0]
        s.close()
    except Exception:
        my_ip = "127.0.0.1"
    print(f"Your IP appears to be: {my_ip}")

    # --- Start listener thread ---
    listener = threading.Thread(
        target=start_listener, 
        args=('0.0.0.0', MY_PORT), 
        daemon=True
    )
    listener.start()

    while True:
        print("\n--- Main Menu ---")
        print("1. Connect to a peer")
        print("2. Check for incoming connections")
        print("3. Quit")
        choice = input("Enter your choice (1-3): ")

        if choice == '1':
            # --- Initiate a connection ---
            target_ip = input("Enter peer's IP address: ")
            target_id = input(f"Enter peer's ID (e.g., peer_B): ")
            
            if load_peer_public_key(target_id) is None:
                print(f"Cannot connect: No public key found for {target_id}.")
                continue

            try:
                print(f"Connecting to {target_ip}:{MY_PORT}...")
                client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_sock.connect((target_ip, MY_PORT))
                
                # --- Perform handshake ---
                session_key = perform_handshake_initiator(
                    client_sock, 
                    MY_ID, 
                    MY_PRIVATE_KEY, 
                    target_id
                )
                
                if session_key:
                    print("[+] Handshake successful!")
                    start_chat_session(client_sock, session_key)
                else:
                    print("[-] Handshake failed. Connection closed.")
                    client_sock.close()
                    
            except (socket.error, ConnectionRefusedError) as e:
                print(f"!! =>  Connection failed: {e}")
            except Exception as e:
                print(f"!! =>  An error occurred during connection: {e}")
                if 'client_sock' in locals():
                    client_sock.close()

        elif choice == '2':
            # --- Check for pending connections ---
            if connection_requests.empty():
                print("No pending connection requests.")
            else:
                conn, addr = connection_requests.get()
                print(f"\nProcessing incoming request from {addr[0]}...")
                
                try:
                    # --- Perform handshake as receiver ---
                    session_key, peer_id = perform_handshake_receiver(
                        conn, 
                        MY_ID, 
                        MY_PRIVATE_KEY
                    )
                    
                    if session_key and peer_id:
                        print(f"[+] Handshake with {peer_id} successful!")
                        start_chat_session(conn, session_key)
                        # We only handle one chat at a time
                        break 
                    else:
                        print("[-] Handshake failed. Closing connection.")
                        conn.close()
                
                except Exception as e:
                    print(f"!! =>  An error occurred during handshake: {e}")
                    conn.close()
            
        elif choice == '3':
            print("Cleaning up and exiting...")
            # No shelve files to close anymore
            print("Goodbye.")
            sys.exit(0)
            
        else:
            print("Invalid choice.")

# --- Run the application ---
if __name__ == "__main__":
    try:
        main_ui()
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)