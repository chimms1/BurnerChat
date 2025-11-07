import socket
import threading
import queue
import sys
import time

# --- Configuration ---
MY_PORT = 42069
INACTIVITY_TIMEOUT = 60.0  # 60 seconds

# Thread-safe queue to hold incoming connection requests
connection_requests = queue.Queue()

# --- 1. The Listener Thread ---

def start_listener(my_ip, my_port):
    """
    Listens for incoming connections and puts them in a queue.
    """
    # Create a TCP socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Allow port reuse
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        s.bind((my_ip, my_port))
        s.listen(5)  # Listen for up to 5 queued connections
        print(f"[*] Listening on {my_ip}:{my_port}")

        while True:
            # Block until a connection arrives
            conn, addr = s.accept()
            # A new connection! Put it in the queue for the main thread
            print(f"\n[!] Incoming connection from {addr[0]}")
            connection_requests.put((conn, addr))
            
    except OSError as e:
        print(f"[!] Listener socket error: {e}")
    finally:
        s.close()
        
# --- 2. The Chat Session (Send/Receive) ---

# This flag will be used to signal the receive_thread to stop
stop_chat_thread = threading.Event()

def receive_messages(sock):
    """
    Target function for the receive thread.
    Receives messages and handles timeouts.
    """
    global stop_chat_thread
    sock.settimeout(INACTIVITY_TIMEOUT)
    
    while not stop_chat_thread.is_set():
        try:
            # Block and wait for a message
            data = sock.recv(1024)
            if not data:
                # Connection closed by peer
                print("\n[!] Peer disconnected.")
                break
            
            # \r moves cursor to start of line,
            # end="" prevents a new line
            print(f"\rPeer: {data.decode()}      \nYou: ", end="")

        except socket.timeout:
            print(f"\n[!] Chat timed out after {INACTIVITY_TIMEOUT}s of inactivity.")
            break
        except (OSError, ConnectionResetError):
            if not stop_chat_thread.is_set():
                print("\n[!] Connection error in receive thread.")
            break
            
    # Signal the main (sending) thread that we're done
    stop_chat_thread.set()
    try:
        sock.close()
    except OSError:
        pass # Socket might already be closed

def start_chat_session(conn):
    """
    Manages an active 1-on-1 chat.
    Spawns a receive_thread and uses the main thread for sending.
    """
    global stop_chat_thread
    stop_chat_thread.clear()  # Reset the event for this new chat
    print("\n--- Chat Started! Type 'exit' to end. ---")

    # Start the receive thread
    receiver = threading.Thread(target=receive_messages, args=(conn,), daemon=True)
    receiver.start()

    # Use the main thread for sending
    while not stop_chat_thread.is_set():
        try:
            # input() will block, but the receive_thread is running
            message = input("You: ")
            
            if stop_chat_thread.is_set():
                # receive_thread must have died (timeout, disconnect)
                print("[!] Connection is closed. Cannot send message.")
                break
                
            if message.lower() == 'exit':
                break

            conn.send(message.encode())
            
        except (EOFError, KeyboardInterrupt):
            # User pressed Ctrl+C or Ctrl+D
            break
        except (OSError, ConnectionResetError):
            # This will trigger if the socket is closed by the
            # receive_thread (e.g., on timeout)
            print("[!] Connection closed.")
            break
            
    # --- Chat session is ending ---
    stop_chat_thread.set()  # Tell the receive_thread to stop
    
    print("--- Chat Ended ---")
    
    # Clean up
    if receiver.is_alive():
        # Give the receiver a moment to die gracefully
        receiver.join(1.0)
        
    if conn.fileno() != -1: # Check if socket is still valid
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass # Socket might already be closed
        conn.close()

# --- 3. The Main (UI) Thread ---

def main_ui():
    """
    The main user-facing loop.
    """
    print("Welcome to P2P Chat!")
    # Get local IP
    my_hostname = socket.gethostname()
    my_ip = socket.gethostbyname(my_hostname)
    print(f"Your local IP is: {my_ip} (Use this for local testing)")
    print("Finding public IP... (This can take a moment)")
    
    try:
        # Connect to Google's DNS to find our "public" IP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            public_ip = s.getsockname()[0]
        print(f"Your 'public' (outbound) IP is: {public_ip}")
        print("Note: This may not work if you are behind a strict NAT.")
    except Exception as e:
        print(f"Could not determine public-facing IP: {e}")
        public_ip = "127.0.0.1"
    
    # Start the listener thread using '0.0.0.0' to listen on all interfaces
    listener = threading.Thread(
        target=start_listener, 
        args=('0.0.0.0', MY_PORT), 
        daemon=True # daemon=True means thread will exit when main app exits
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
            try:
                print(f"Connecting to {target_ip}:{MY_PORT}...")
                # Create a new socket to connect
                client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_sock.connect((target_ip, MY_PORT))
                
                print("Connection request sent. Waiting for acceptance...")
                
                # Wait for the 'ACCEPT' or 'REJECT'
                response = client_sock.recv(1024).decode()
                
                if response == 'ACCEPT':
                    print("[+] Connection accepted!")
                    start_chat_session(client_sock)
                else:
                    print("[-] Connection rejected by peer.")
                    client_sock.close()
                    
            except (socket.error, ConnectionRefusedError) as e:
                print(f"[!] Connection failed: {e}")
            except Exception as e:
                print(f"[!] An error occurred: {e}")
                if 'client_sock' in locals():
                    client_sock.close()

        elif choice == '2':
            # --- Check for pending connections ---
            if connection_requests.empty():
                print("No pending connection requests.")
            else:
                while not connection_requests.empty():
                    # Get the oldest request
                    conn, addr = connection_requests.get()
                    print(f"\nIncoming request from {addr[0]}")
                    accept = input("Accept? (y/n): ").lower().strip()
                    
                    if accept == 'y':
                        # Send acceptance and start chat
                        conn.send(b'ACCEPT')
                        start_chat_session(conn)
                        # We only handle one chat at a time, so
                        # break and return to main menu after
                        break 
                    else:
                        # Send rejection and close
                        conn.send(b'REJECT')
                        conn.close()
                        print("Connection rejected.")
            
        elif choice == '3':
            print("Exiting...")
            sys.exit(0)
            
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

# --- Run the application ---
if __name__ == "__main__":
    try:
        main_ui()
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)