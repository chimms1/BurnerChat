import socket
import threading
import queue
import sys
import time
import json
import base64
import os
import sqlite3
import hmac # <-- Import hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature

# --- Configuration ---
MY_PORT = 42069
INACTIVITY_TIMEOUT = 120.0
DATABASE_FILE = 'chat_keys.db'
REKEY_AFTER_MESSAGES = 5 # Re-key after 5 messages on each chain

# --- AES-128 + HMAC-SHA256 Configuration ---
AES_KEY_SIZE = 16
HMAC_KEY_SIZE = 32
BUNDLE_KEY_SIZE = AES_KEY_SIZE + HMAC_KEY_SIZE # 16 + 32 = 48 bytes
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

def kdf_derive_key(key_material, info_str, length):
    """
    General-purpose KDF to derive a new key of arbitrary length.
    """
    info_bytes = info_str.encode()
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info_bytes,
        backend=default_backend()
    )
    return hkdf.derive(key_material)

def generate_hmac(hmac_key, data):
    """Generates a HMAC-SHA256 tag."""
    # The fix is changing hashes.SHA256() to the string "sha256"
    h = hmac.new(hmac_key, data, "sha256")
    return h.digest()

def verify_hmac(hmac_key, tag, data):
    """Verifies a HMAC-SHA256 tag in constant time."""
    try:
        # The fix is changing hashes.SHA256() to the string "sha256"
        h = hmac.new(hmac_key, data, "sha256")
        h.verify(tag)
        return True
    except InvalidSignature:
        return False

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
        
# --- 3. HANDSHAKE LOGIC (Modified to return DH keys) ---
def perform_handshake_initiator(sock, my_id, my_private_key, peer_id):
    """
    Initiator side of the handshake.
    Returns: (master_key, my_ec_private_key, peer_ec_public_key) or (None, None, None)
    """
    print(f"--- Initiating handshake with {peer_id} ---")
    
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
        return None, None, None
        
    response = json.loads(response_bytes.decode())
    
    if response.get('type') != 'handshake_2' or response.get('id') != peer_id:
        print("[!] Invalid handshake_2 response. Aborting.")
        return None, None, None
        
    peer_ec_pub_bytes = base64.b64decode(response['ec_pub_key'])
    peer_sig = base64.b64decode(response['sig'])
    peer_rsa_pub = load_peer_public_key(peer_id)
    
    data_to_verify = response['id'].encode() + peer_ec_pub_bytes
    
    if not verify_signature(peer_rsa_pub, peer_sig, data_to_verify):
        print("[!] Peer's handshake signature is INVALID! Aborting.")
        return None, None, None
        
    print("  Peer signature verified.")
    
    peer_ec_pub_key = serialization.load_pem_public_key(peer_ec_pub_bytes, default_backend())
    master_key = ec_private_key.exchange(ec.ECDH(), peer_ec_pub_key)
    
    print("  New Master Key computed (in memory only).")
    
    # RETURN a tuple of all 3 critical items
    return master_key, ec_private_key, peer_ec_pub_key

def perform_handshake_receiver(sock, my_id, my_private_key):
    """
    Receiver side of the handshake.
    Returns: (master_key, peer_id, my_ec_private_key, peer_ec_public_key) or (None, None, None, None)
    """
    print("--- Awaiting handshake ---")
    
    msg_bytes = recv_secure_message(sock)
    if not msg_bytes:
        print("  Peer disconnected before handshake.")
        return None, None, None, None
        
    msg = json.loads(msg_bytes.decode())
    peer_id = msg.get('id')
    
    if not peer_id:
        print("[!] Handshake message has no ID. Aborting.")
        return None, None, None, None
        
    print(f"  Handshake attempt from {peer_id}.")
    peer_rsa_pub = load_peer_public_key(peer_id)
    if not peer_rsa_pub:
        print(f"[!] Unknown peer ID: {peer_id}. Aborting.")
        return None, None, None, None
        
    if msg.get('type') == 'handshake_1':
        print(f"  Processing 'handshake_1' from {peer_id}...")
        
        peer_ec_pub_bytes = base64.b64decode(msg['ec_pub_key'])
        peer_sig = base64.b64decode(msg['sig'])
        data_to_verify = peer_id.encode() + peer_ec_pub_bytes
        
        if not verify_signature(peer_rsa_pub, peer_sig, data_to_verify):
            print("[!] Peer's handshake signature is INVALID! Aborting.")
            return None, None, None, None
        
        print("  Peer signature verified.")
        
        ec_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        ec_public_key = ec_private_key.public_key()
        ec_pub_bytes = ec_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        peer_ec_pub_key = serialization.load_pem_public_key(peer_ec_pub_bytes, default_backend())
        master_key = ec_private_key.exchange(ec.ECDH(), peer_ec_pub_key)
        
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
        
        # RETURN a tuple of all 4 critical items
        return master_key, peer_id, ec_private_key, peer_ec_pub_key
        
    else:
        print(f"[!] Unknown handshake message type: {msg.get('type')}")
        return None, None, None, None

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
            
# --- 5. The Chat Session (Dual Ratchet Logic) ---
stop_chat_thread = threading.Event()
def receive_messages(sock, chat_state):
    """
    Target function for the receive thread.
    Manages the RECEIVING chain key and DH ratchet updates.
    """
    global stop_chat_thread
    sock.settimeout(INACTIVITY_TIMEOUT)
    
    while not stop_chat_thread.is_set():
        try:
            iv_and_ciphertext = recv_secure_message(sock)
            
            if not iv_and_ciphertext:
                print("\n[!] Peer disconnected.")
                break
            
            # 1. Get current receiving key bundle
            with chat_state['lock']:
                current_key_bundle = chat_state['receiving_key']
            
            aes_key = current_key_bundle[:AES_KEY_SIZE]
            hmac_key = current_key_bundle[AES_KEY_SIZE:]
            
            # 2. Decrypt the outer message
            final_json_str = decrypt_message(aes_key, iv_and_ciphertext)
            final_payload = json.loads(final_json_str)
            
            payload_json_str = final_payload['p']
            hmac_b64 = final_payload['hmac']
            hmac_tag = base64.b64decode(hmac_b64)
            
            # 3. Verify HMAC
            if not verify_hmac(hmac_key, hmac_tag, payload_json_str.encode('utf-8')):
                print("\n[!] INVALID HMAC! Message discarded. Tampering suspected.")
                print("You: ", end="") # Re-draw prompt
                continue
                
            # 4. HMAC is valid. Process the inner payload.
            payload = json.loads(payload_json_str)
            message_text = payload['msg']
            msg_num = payload['msg_num']
            peer_dh_pub_key_b64 = payload.get('dh_pub_key') # This will be present on re-key
            
            # 5. Acquire lock to update state
            with chat_state['lock']:
                # Check for out-of-order messages
                if msg_num <= chat_state['receiving_msg_num']:
                    print(f"\n[!] Received out-of-order message (Num: {msg_num}). Discarding.")
                    print("You: ", end="") # Re-draw prompt
                    continue
                    
                chat_state['receiving_msg_num'] = msg_num
                
                # Check if this message is triggering a DH ratchet step
                if peer_dh_pub_key_b64:
                    print(f"\n[!] ({REKEY_AFTER_MESSAGES} msgs received) RE-KEYING (DH Ratchet)...")
                    
                    # Load the peer's new public key
                    peer_dh_pub_bytes = base64.b64decode(peer_dh_pub_key_b64)
                    peer_dh_pub_key = serialization.load_pem_public_key(peer_dh_pub_bytes, default_backend())
                    
                    # Get our *current* private key
                    my_dh_key = chat_state['my_dh_key']
                    
                    # Calculate the new root key
                    new_root_key = my_dh_key.exchange(ec.ECDH(), peer_dh_pub_key)
                    
                    # Update state
                    chat_state['root_key'] = new_root_key
                    chat_state['peer_dh_pub_key'] = peer_dh_pub_key # Update peer's key
                    # Note: We don't update my_dh_key here, the *sender* does.
                    
                    # Derive new chain keys
                    send_info = chat_state['send_info']
                    recv_info = chat_state['recv_info']
                    
                    chat_state['sending_key'] = kdf_derive_key(new_root_key, send_info, BUNDLE_KEY_SIZE)
                    chat_state['receiving_key'] = kdf_derive_key(new_root_key, recv_info, BUNDLE_KEY_SIZE)
                    
                    # Reset counters
                    chat_state['sending_msg_num'] = 0
                    chat_state['receiving_msg_num'] = 0 # This message was #5 (or #10, etc)
                    
                    print(f"[!] New Root Key and Chain Keys derived.")
                
            # 6. Finally, print the message
            print(f"\rPeer: {message_text}      \nYou: ", end="")
            
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
def start_chat_session(conn, master_key, my_dh_key, peer_dh_pub_key, am_i_initiator):
    """
    Manages an active chat with separate send/receive ratchets.
    """
    global stop_chat_thread
    stop_chat_thread.clear()
    
    # Determine roles for key derivation
    send_info, recv_info = "", ""
    if am_i_initiator:
        send_info = "initiator-sends"
        recv_info = "receiver-sends"
    else:
        send_info = "receiver-sends"
        recv_info = "initiator-sends"
        
    # Derive initial chain keys from the master key
    initial_sending_key = kdf_derive_key(master_key, send_info, BUNDLE_KEY_SIZE)
    initial_receiving_key = kdf_derive_key(master_key, recv_info, BUNDLE_KEY_SIZE)
    
    # Create the shared state object for both chains
    chat_state = {
        'lock': threading.Lock(),
        'root_key': master_key,
        'my_dh_key': my_dh_key,         # Our *current* private key for DH
        'peer_dh_pub_key': peer_dh_pub_key, # Peer's *current* public key for DH
        
        'sending_key': initial_sending_key,     # 48-byte bundle (AES+HMAC)
        'sending_msg_num': 0,
        'receiving_key': initial_receiving_key, # 48-byte bundle (AES+HMAC)
        'receiving_msg_num': 0,
        
        'send_info': send_info, # Store for re-keying
        'recv_info': recv_info  # Store for re-keying
    }
    
    print(f"\n--- SECURE Ratchet Chat Started! (Re-keys every {REKEY_AFTER_MESSAGES} msgs) ---")
    
    # Start the receive thread
    receiver = threading.Thread(
        target=receive_messages, 
        args=(conn, chat_state), 
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
            
            current_send_bundle = None
            current_msg_num = 0
            dh_pub_bytes_to_send = None
            
            # Atomically update counter and check for re-key
            with chat_state['lock']:
                chat_state['sending_msg_num'] += 1
                current_msg_num = chat_state['sending_msg_num']
                
                # Check if it's time to re-key the SENDING chain
                if current_msg_num == REKEY_AFTER_MESSAGES:
                    print(f"\n[!] ({REKEY_AFTER_MESSAGES} msgs sent) RE-KEYING (DH Ratchet)...")
                    
                    # 1. Generate our *new* DH key pair
                    new_my_dh_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
                    new_my_dh_pub = new_my_dh_key.public_key()
                    dh_pub_bytes_to_send = new_my_dh_pub.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                    
                    # 2. Get peer's *current* public key
                    current_peer_dh_pub = chat_state['peer_dh_pub_key']
                    
                    # 3. Calculate new root key
                    new_root_key = new_my_dh_key.exchange(ec.ECDH(), current_peer_dh_pub)
                    
                    # 4. Update state *immediately*
                    chat_state['root_key'] = new_root_key
                    chat_state['my_dh_key'] = new_my_dh_key # Our private key is updated
                    # Note: peer_dh_pub_key is NOT updated yet.
                    
                    # 5. Derive new chain keys
                    chat_state['sending_key'] = kdf_derive_key(new_root_key, send_info, BUNDLE_KEY_SIZE)
                    chat_state['receiving_key'] = kdf_derive_key(new_root_key, recv_info, BUNDLE_KEY_SIZE)
                    
                    # 6. Reset counters
                    chat_state['sending_msg_num'] = 0
                    chat_state['receiving_msg_num'] = 0
                    
                    print(f"[!] New Root Key and Chain Keys derived. Attaching new PubKey to message.")
                
                # Get the key to use for *this* message
                # Note: If we re-keyed, we use the *old* key for this message
                # This is "Encrypt-then-Ratchet"
                # ... actually, that's complex. Let's use the new key right away.
                # The logic above already updated chat_state['sending_key']
                
                # Re-reading... no, the logic above ONLY runs if msg_num == REKEY...
                # Let's re-think. This is the race condition.
                
                # --- Let's try the "Ratchet-then-Encrypt" model ---
                # The logic in the lock is fine. If we rekeyed, chat_state['sending_key']
                # is *already* the new key.
                
                # Let's fix the counter.
                if current_msg_num > REKEY_AFTER_MESSAGES:
                    # This is message #6. It needs to be message #1.
                    chat_state['sending_msg_num'] = 1
                    current_msg_num = 1
                    
                    print(f"\n[!] ({REKEY_AFTER_MESSAGES} msgs sent) RE-KEYING (DH Ratchet)...")
                    new_my_dh_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
                    new_my_dh_pub = new_my_dh_key.public_key()
                    dh_pub_bytes_to_send = new_my_dh_pub.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                    
                    current_peer_dh_pub = chat_state['peer_dh_pub_key']
                    new_root_key = new_my_dh_key.exchange(ec.ECDH(), current_peer_dh_pub)
                    
                    chat_state['root_key'] = new_root_key
                    chat_state['my_dh_key'] = new_my_dh_key
                    
                    chat_state['sending_key'] = kdf_derive_key(new_root_key, send_info, BUNDLE_KEY_SIZE)
                    chat_state['receiving_key'] = kdf_derive_key(new_root_key, recv_info, BUNDLE_KEY_SIZE)
                    
                    chat_state['receiving_msg_num'] = 0 # Reset receiving counter
                    print(f"[!] New Root Key and Chain Keys derived. Attaching new PubKey to message.")
                
                current_send_bundle = chat_state['sending_key']
            
            # --- End of lock ---
            
            # 1. Split the key bundle
            aes_key = current_send_bundle[:AES_KEY_SIZE]
            hmac_key = current_send_bundle[AES_KEY_SIZE:]
            
            # 2. Package inner payload
            payload = {
                'msg': message_text,
                'msg_num': current_msg_num
            }
            if dh_pub_bytes_to_send:
                payload['dh_pub_key'] = base64.b64encode(dh_pub_bytes_to_send).decode('utf-8')
                
            payload_json_str = json.dumps(payload)
            
            # 3. Create HMAC
            hmac_tag = generate_hmac(hmac_key, payload_json_str.encode('utf-8'))
            
            # 4. Package outer payload
            final_payload = {
                'p': payload_json_str, # 'p' for payload
                'hmac': base64.b64encode(hmac_tag).decode('utf-8')
            }
            final_json_str = json.dumps(final_payload)
            
            # 5. Encrypt the outer payload
            iv_and_ciphertext = encrypt_message(aes_key, final_json_str)
            
            # 6. Send securely
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

# --- 6. The Main (UI) Thread (Modified to pass DH keys) ---
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
            # This is the INITIATOR
            target_ip = input("Enter peer's IP address: ")
            target_id = input(f"Enter peer's ID (e.g., peer_B): ")
            
            if load_peer_public_key(target_id) is None:
                print(f"Cannot connect: No public key found for {target_id}.")
                continue
            try:
                print(f"Connecting to {target_ip}:{MY_PORT}...")
                client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_sock.connect((target_ip, MY_PORT))
                
                # Perform handshake, now getting DH keys back
                master_key, my_dh_key, peer_dh_pub_key = perform_handshake_initiator(
                    client_sock, 
                    MY_ID, 
                    MY_PRIVATE_KEY, 
                    target_id
                )
                
                if master_key:
                    print("[+] Handshake successful! Starting ratchet session...")
                    start_chat_session(
                        client_sock, 
                        master_key,
                        my_dh_key,
                        peer_dh_pub_key,
                        am_i_initiator=True # This client is the initiator
                    )
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
            # This is the RECEIVER
            if connection_requests.empty():
                print("No pending connection requests.")
            else:
                conn, addr = connection_requests.get()
                print(f"\nProcessing incoming request from {addr[0]}...")
                
                try:
                    # Perform handshake, now getting DH keys back
                    master_key, peer_id, my_dh_key, peer_dh_pub_key = perform_handshake_receiver(
                        conn, 
                        MY_ID, 
                        MY_PRIVATE_KEY
                    )
                    
                    if master_key and peer_id:
                        print(f"[+] Handshake with {peer_id} successful! Starting ratchet session...")
                        start_chat_session(
                            conn, 
                            master_key,
                            my_dh_key,
                            peer_dh_pub_key,
                            am_i_initiator=False # This client is the receiver
                        )
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