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
REKEY_AFTER_MESSAGES = 10 # Re-key after 10 messages total (send/recv)

# --- AES-128 Configuration ---
AES_KEY_SIZE = 16
IV_SIZE = 16

# Thread-safe queue for incoming connection requests
connection_requests = queue.Queue()

# --- 1. CRYPTOGRAPHIC HELPERS ---

def load_my_private_key(my_id):
    """Loads this user's RSA private key from their .pem file."""
    filename = f"{my_id}.pem"
    try:
        with open(filename, "rb") as key_file:
            return serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
    except FileNotFoundError:
        print(f"[!] CRITICAL: Private key file not found: {filename}")
        print("    Did you run setup_keys.py first? Or generate keys manually?")
        sys.exit(1)

def load_peer_public_key(peer_id):
    """Loads a peer's RSA public key from the SQLite 'database'."""
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT public_key FROM peers WHERE id = ?", (peer_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row and row[0]:
            pem_public = row[0].encode('utf-8')
            return serialization.load_pem_public_key(
                pem_public,
                backend=default_backend()
            )
        else:
            print(f"[!] No public key found in database for ID: {peer_id}")
            return None
            
    except sqlite3.Error as e:
        print(f"[!] SQLite error while loading public key: {e}")
        return None
    except KeyError:
        print(f"[!] No public key found in database for ID: {peer_id}")
        return None

def sign_data(private_key, data):
    """Signs data with our RSA private key."""
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verify_signature(public_key, signature, data):
    """Verifies a signature using a peer's RSA public key."""
    try:
        public_key.verify(
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

def derive_session_key(master_key, epoch):
    """
    Derives a 128-bit (16-byte) session key from the master key
    for a specific epoch.
    """
    # We use the epoch in the 'info' field to ensure each derived key is unique
    info_str = f'p2p-chat-epoch-{epoch}'.encode()
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=None,
        info=info_str,
        backend=default_backend()
    )
    return hkdf.derive(master_key)

def encrypt_message(session_key, message_str):
    """Encrypts a string with AES-128-CBC."""
    iv = os.urandom(IV_SIZE)
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message_str.encode('utf-8')) + padder.finalize()
    
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def decrypt_message(session_key, iv_and_ciphertext):
    """Decrypts an AES-128-CBC message (IV + Ciphertext)."""
    iv = iv_and_ciphertext[:IV_SIZE]
    ciphertext = iv_and_ciphertext[IV_SIZE:]
    
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
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
        print(f"[!] Error sending message: {e}")
        raise 

def recv_secure_message(sock):
    """Reads a 4-byte length prefix, then receives a full message."""
    try:
        len_bytes = sock.recv(4)
        if not len_bytes:
            return None
        
        msg_len = int.from_bytes(len_bytes, 'big')
        
        return sock.recv(msg_len)
    
    except (OSError, ConnectionResetError):
        return None
        
# --- 3. HANDSHAKE LOGIC ---

def perform_handshake_initiator(sock, my_id, my_private_key, peer_id):
    """Initiator side of the handshake."""
    print(f"--- Initiating handshake with {peer_id} ---")
    
    # --- We no longer check for an existing key. We ALWAYS do a full handshake. ---
    
    print("  Performing full ECDHE handshake...")
    ec_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    ec_public_key = ec_private_key.public_key()
    ec_pub_bytes = ec_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    data_to_sign = my_id.encode() + ec_pub_bytes
    signature = sign_data(my_private_key, data_to_sign)
    
    handshake_1 = {
        'type': 'handshake_1',
        'id': my_id,
        'ec_pub_key': base64.b64encode(ec_pub_bytes).decode('utf-8'),
        'sig': base64.b64encode(signature).decode('utf-8')
    }
    send_secure_message(sock, json.dumps(handshake_1).encode())
    
    response_bytes = recv_secure_message(sock)
    if not response_bytes:
        print("  Peer disconnected during handshake.")
        return None
        
    response = json.loads(response_bytes.decode())
    
    if response.get('type') != 'handshake_2' or response.get('id') != peer_id:
        print("[!] Invalid handshake_2 response. Aborting.")
        return None
        
    peer_ec_pub_bytes = base64.b64decode(response['ec_pub_key'])
    peer_sig = base64.b64decode(response['sig'])
    peer_rsa_pub = load_peer_public_key(peer_id)
    
    data_to_verify = response['id'].encode() + peer_ec_pub_bytes
    
    if not verify_signature(peer_rsa_pub, peer_sig, data_to_verify):
        print("[!] Peer's handshake signature is INVALID! Aborting.")
        return None
        
    print("  Peer signature verified.")
    
    peer_ec_pub_key = serialization.load_pem_public_key(peer_ec_pub_bytes, default_backend())
    master_key = ec_private_key.exchange(ec.ECDH(), peer_ec_pub_key)
    
    # --- We no longer store the master_key in the database ---
    print("  New Master Key computed (in memory only).")
    
    return master_key # <-- RETURN MASTER KEY


def perform_handshake_receiver(sock, my_id, my_private_key):
    """Receiver side of the handshake."""
    print("--- Awaiting handshake ---")
    
    msg_bytes = recv_secure_message(sock)
    if not msg_bytes:
        print("  Peer disconnected before handshake.")
        return None, None
        
    msg = json.loads(msg_bytes.decode())
    peer_id = msg.get('id')
    
    if not peer_id:
        print("[!] Handshake message has no ID. Aborting.")
        return None, None
        
    print(f"  Handshake attempt from {peer_id}.")
    peer_rsa_pub = load_peer_public_key(peer_id)
    if not peer_rsa_pub:
        print(f"[!] Unknown peer ID: {peer_id}. Aborting.")
        return None, None
        
    # --- We no longer check for an existing key. ---
    
    # --- CASE 1: RESUME SESSION (REMOVED) ---
    
    # --- CASE 2: FULL HANDSHAKE ---
    if msg.get('type') == 'handshake_1':
        print(f"  Processing 'handshake_1' from {peer_id}...")
        
        peer_ec_pub_bytes = base64.b64decode(msg['ec_pub_key'])
        peer_sig = base64.b64decode(msg['sig'])
        data_to_verify = peer_id.encode() + peer_ec_pub_bytes
        
        if not verify_signature(peer_rsa_pub, peer_sig, data_to_verify):
            print("[!] Peer's handshake signature is INVALID! Aborting.")
            return None, None
        
        print("  Peer signature verified.")
        
        ec_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        ec_public_key = ec_private_key.public_key()
        ec_pub_bytes = ec_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        peer_ec_pub_key = serialization.load_pem_public_key(peer_ec_pub_bytes, default_backend())
        master_key = ec_private_key.exchange(ec.ECDH(), peer_ec_pub_key)
        
        # --- We no longer store the master_key in the database ---
        print("  New Master Key computed (in memory only).")
        
        data_to_sign = my_id.encode() + ec_pub_bytes
        signature = sign_data(my_private_key, data_to_sign)
        
        handshake_2 = {
            'type': 'handshake_2',
            'id': my_id,
            'ec_pub_key': base64.b64encode(ec_pub_bytes).decode('utf-8'),
            'sig': base64.b64encode(signature).decode('utf-8')
        }
        send_secure_message(sock, json.dumps(handshake_2).encode())
        print("  Sent handshake_2.")
        
        return master_key, peer_id # <-- RETURN MASTER KEY
        
    else:
        print(f"[!] Unknown handshake message type: {msg.get('type')}")
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
            print(f"\n[!] Incoming connection from {addr[0]}")
            connection_requests.put((conn, addr))
            
    except OSError as e:
        print(f"[!] Listener socket error: {e}")
    finally:
        s.close()
        
# --- 5. The Chat Session (NOW Encrypted, Signed, AND Ratcheting) ---

stop_chat_thread = threading.Event()

def receive_messages(sock, chat_state, peer_public_key):
    """
    Target function for the receive thread.
    Decrypts messages, verifies signatures, and handles re-keying.
    """
    global stop_chat_thread
    sock.settimeout(INACTIVITY_TIMEOUT)
    
    while not stop_chat_thread.is_set():
        try:
            # 1. Receive the length-prefixed, encrypted payload
            iv_and_ciphertext = recv_secure_message(sock)
            
            if not iv_and_ciphertext:
                print("\n[!] Peer disconnected.")
                break

            # 2. Get the current key and state *atomically*
            current_key_to_use = None
            with chat_state['lock']:
                # Increment shared counter
                chat_state['count'] += 1
                
                # Check if it's time to re-key
                if chat_state['count'] > REKEY_AFTER_MESSAGES:
                    print(f"\n[!] ({REKEY_AFTER_MESSAGES} messages passed) RE-KEYING SESSION (Receive)...")
                    chat_state['epoch'] += 1
                    chat_state['session_key'] = derive_session_key(
                        chat_state['master_key'], chat_state['epoch']
                    )
                    chat_state['count'] = 1 # This is message 1 of the new epoch
                    print(f"[!] New session key for epoch {chat_state['epoch']} derived.")

                current_key_to_use = chat_state['session_key']
            
            # 3. Decrypt the payload to get the JSON string
            message_json_str = decrypt_message(current_key_to_use, iv_and_ciphertext)
            
            # 4. Unpack the JSON
            payload = json.loads(message_json_str)
            message_text = payload['msg']
            signature_b64 = payload['sig']
            
            # 5. Verify the signature
            signature_bytes = base64.b64decode(signature_b64)
            data_to_verify = message_text.encode('utf-8')
            
            if verify_signature(peer_public_key, signature_bytes, data_to_verify):
                # 6. Display if valid
                print(f"\rPeer: {message_text}      \nYou: ", end="")
            else:
                # 6. Show error if invalid
                print(f"\n[!] INVALID SIGNATURE received for message: '{message_text}'")
                print("You: ", end="") # Re-draw prompt

        except socket.timeout:
            print(f"\n[!] Chat timed out after {INACTIVITY_TIMEOUT}s of inactivity.")
            break
        except (OSError, ConnectionResetError):
            if not stop_chat_thread.is_set():
                print("\n[!] Connection error in receive thread.")
            break
        except json.JSONDecodeError:
            print("\n[!] Received malformed (non-JSON) message. Tampering suspected.")
            break
        except Exception as e:
            # This will catch decryption errors if keys go out of sync
            print(f"\n[!] Decryption/Verification error: {e}. Keys may be out of sync.")
            break
            
    stop_chat_thread.set()
    try:
        sock.close()
    except OSError:
        pass 

def start_chat_session(conn, master_key, peer_id, my_private_key):
    """
    Manages an active 1-on-1 ENCRYPTED and SIGNED chat.
    Now manages a shared state for re-keying.
    """
    global stop_chat_thread
    stop_chat_thread.clear()
    
    # Load the peer's public key once for the receive thread
    peer_public_key = load_peer_public_key(peer_id)
    if not peer_public_key:
        print(f"[!] Critical: Could not load peer's public key for {peer_id}. Cannot verify messages.")
        conn.close()
        return

    # Create the shared state object
    chat_state = {
        'lock': threading.Lock(),
        'count': 0,                     # Shared message counter
        'epoch': 1,                     # Key epoch
        'master_key': master_key,       # Unchanging master key
        'session_key': derive_session_key(master_key, 1) # Initial session key
    }

    print(f"\n--- SECURE & VERIFIED Chat Started! (Re-keys every {REKEY_AFTER_MESSAGES} msgs) ---")

    # Start the receive thread, passing it the shared state
    receiver = threading.Thread(
        target=receive_messages, 
        args=(conn, chat_state, peer_public_key), 
        daemon=True
    )
    receiver.start()

    # Use the main thread for sending
    while not stop_chat_thread.is_set():
        try:
            message_text = input("You: ")
            
            if len(message_text.strip())==0:
                continue
                
            if stop_chat_thread.is_set():
                print("[!] Connection is closed. Cannot send message.")
                break
                
            if message_text.lower() == 'exit':
                break

            current_key_to_use = None
            # Atomically update counter and get current key
            with chat_state['lock']:
                chat_state['count'] += 1
                
                if chat_state['count'] > REKEY_AFTER_MESSAGES:
                    print(f"\n[!] ({REKEY_AFTER_MESSAGES} messages passed) RE-KEYING SESSION (Send)...")
                    chat_state['epoch'] += 1
                    chat_state['session_key'] = derive_session_key(
                        chat_state['master_key'], chat_state['epoch']
                    )
                    chat_state['count'] = 1 # This is message 1 of the new epoch
                    print(f"[!] New session key for epoch {chat_state['epoch']} derived.")
                
                current_key_to_use = chat_state['session_key']

            # 1. Sign the message
            data_to_sign = message_text.encode('utf-8')
            signature = sign_data(my_private_key, data_to_sign)

            # 2. Package into JSON
            payload = {
                'msg': message_text,
                'sig': base64.b64encode(signature).decode('utf-8')
            }
            message_json_str = json.dumps(payload)

            # 3. Encrypt the JSON string using the key for this epoch
            print("Message => {} current_key => {}".format(message_json_str, current_key_to_use))
            iv_and_ciphertext = encrypt_message(current_key_to_use, message_json_str)
            
            # 4. Send securely (with length prefix)
            send_secure_message(conn, iv_and_ciphertext)
            
        except (EOFError, KeyboardInterrupt):
            break
        except (OSError, ConnectionResetError):
            print("[!] Connection closed.")
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

# --- 6. The Main (UI) Thread (Modified to pass keys) ---

def main_ui():
    """The main user-facing loop."""
    
    if len(sys.argv) < 2:
        print("Usage: python secure_chat.py <your_id>")
        print("Example: python secure_chat.py peer_A")
        sys.exit(1)
        
    MY_ID = sys.argv[1]
    print(f"Welcome, {MY_ID}!")
    MY_PRIVATE_KEY = load_my_private_key(MY_ID)
    print("Your RSA private key is loaded.")

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        my_ip = s.getsockname()[0]
        s.close()
    except Exception:
        my_ip = "127.0.0.1"
    print(f"Your IP appears to be: {my_ip}")

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
            target_ip = input("Enter peer's IP address: ")
            target_id = input(f"Enter peer's ID (e.g., peer_B): ")
            
            if load_peer_public_key(target_id) is None:
                print(f"Cannot connect: No public key found for {target_id}.")
                continue

            try:
                print(f"Connecting to {target_ip}:{MY_PORT}...")
                client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_sock.connect((target_ip, MY_PORT))
                
                # Handshake now returns the master_key
                master_key = perform_handshake_initiator(
                    client_sock, 
                    MY_ID, 
                    MY_PRIVATE_KEY, 
                    target_id
                )
                
                if master_key:
                    print("[+] Handshake successful!")
                    # Pass the master_key to start_chat_session
                    start_chat_session(client_sock, master_key, target_id, MY_PRIVATE_KEY)
                else:
                    print("[-] Handshake failed. Connection closed.")
                    client_sock.close()
                    
            except (socket.error, ConnectionRefusedError) as e:
                print(f"[!] Connection failed: {e}")
            except Exception as e:
                print(f"[!] An error occurred during connection: {e}")
                if 'client_sock' in locals():
                    client_sock.close()

        elif choice == '2':
            if connection_requests.empty():
                print("No pending connection requests.")
            else:
                conn, addr = connection_requests.get()
                print(f"\nProcessing incoming request from {addr[0]}...")
                
                try:
                    # Handshake now returns master_key and peer_id
                    master_key, peer_id = perform_handshake_receiver(
                        conn, 
                        MY_ID, 
                        MY_PRIVATE_KEY
                    )
                    
                    if master_key and peer_id:
                        print(f"[+] Handshake with {peer_id} successful!")
                        # Pass the master_key to start_chat_session
                        start_chat_session(conn, master_key, peer_id, MY_PRIVATE_KEY)
                        # No break here, allow main loop to continue after chat
                    else:
                        print("[-] Handshake failed. Closing connection.")
                        conn.close()
                
                except Exception as e:
                    print(f"[!] An error occurred during handshake: {e}")
                    conn.close()
            
        elif choice == '3':
            print("Cleaning up and exiting...")
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