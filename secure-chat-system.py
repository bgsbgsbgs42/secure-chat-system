# Secure Chat System
# This project implements a secure client-server chat system with
# - User registration and login with salted password hashing
# - Diffie-Hellman key exchange
# - AES-128 CBC encryption for messages

import socket
import threading
import json
import os
import hashlib
import base64
import uuid
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ----------------- Utility Functions -----------------

def generate_salt():
    """Generate a random salt for password hashing"""
    return os.urandom(16)

def hash_password(password, salt):
    """Hash a password with a given salt using SHA-256"""
    password_bytes = password.encode('utf-8')
    hash_obj = hashlib.sha256(salt + password_bytes)
    return hash_obj.hexdigest()

def encrypt_message(message, key):
    """Encrypt a message using AES-128 CBC mode"""
    # Generate a random IV
    iv = os.urandom(16)
    
    # Pad the message to be a multiple of 16 bytes (AES block size)
    padded_message = pad_message(message.encode('utf-8'))
    
    # Create an encryptor object
    cipher = Cipher(algorithms.AES(key[:16]), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Encrypt the padded message
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    
    # Return the IV and ciphertext
    return base64.b64encode(iv + ciphertext).decode('utf-8')

def decrypt_message(encrypted_message, key):
    """Decrypt a message using AES-128 CBC mode"""
    # Decode from base64
    encrypted_data = base64.b64decode(encrypted_message.encode('utf-8'))
    
    # Extract the IV (first 16 bytes)
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    
    # Create a decryptor object
    cipher = Cipher(algorithms.AES(key[:16]), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt the ciphertext
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove padding and return
    return unpad_message(padded_plaintext).decode('utf-8')

def pad_message(message):
    """Pad the message to be a multiple of 16 bytes (AES block size)"""
    padding_length = 16 - (len(message) % 16)
    padding = bytes([padding_length]) * padding_length
    return message + padding

def unpad_message(padded_message):
    """Remove padding from the decrypted message"""
    padding_length = padded_message[-1]
    return padded_message[:-padding_length]

# ----------------- Server Implementation -----------------

class SecureChatServer:
    def __init__(self, host='127.0.0.1', port=9999):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.clients = {}  # Dictionary to store client connections {username: (socket, session_key)}
        self.credentials_file = "server_credentials.json"
        self.user_credentials = self.load_credentials()
        
        # DH parameters
        self.parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    
    def load_credentials(self):
        """Load user credentials from file"""
        if os.path.exists(self.credentials_file):
            with open(self.credentials_file, 'r') as file:
                return json.load(file)
        return {}
    
    def save_credentials(self):
        """Save user credentials to file"""
        with open(self.credentials_file, 'w') as file:
            json.dump(self.user_credentials, file)
    
    def register_user(self, username, password):
        """Register a new user with salted and hashed password"""
        if username in self.user_credentials:
            return False, "Username already exists"
        
        salt = generate_salt()
        hashed_password = hash_password(password, salt)
        
        self.user_credentials[username] = {
            "salt": base64.b64encode(salt).decode('utf-8'),
            "hash": hashed_password
        }
        
        self.save_credentials()
        return True, "Registration successful"
    
    def authenticate_user(self, username, password):
        """Authenticate a user with their credentials"""
        if username not in self.user_credentials:
            return False, "Username not found"
        
        user_data = self.user_credentials[username]
        salt = base64.b64decode(user_data["salt"].encode('utf-8'))
        stored_hash = user_data["hash"]
        
        if hash_password(password, salt) == stored_hash:
            return True, "Authentication successful"
        else:
            return False, "Invalid password"
    
    def start(self):
        """Start the server"""
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Server started on {self.host}:{self.port}")
        
        try:
            while True:
                client_socket, client_address = self.server_socket.accept()
                print(f"Connection from {client_address}")
                
                # Start a new thread to handle this client
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
                client_thread.daemon = True
                client_thread.start()
        except KeyboardInterrupt:
            print("\nServer shutting down...")
        finally:
            self.server_socket.close()
    
    def broadcast(self, message, sender):
        """Broadcast a message to all connected clients except the sender"""
        for username, (client_socket, session_key) in list(self.clients.items()):
            if username != sender:
                try:
                    encrypted_message = encrypt_message(f"{sender}: {message}", session_key)
                    client_socket.send(json.dumps({"type": "message", "data": encrypted_message}).encode('utf-8'))
                except:
                    # If sending fails, remove the client
                    self.clients.pop(username, None)
    
    def handle_client(self, client_socket):
        """Handle communication with a client"""
        username = None
        session_key = None
        
        try:
            # Initial handshake
            while username is None:
                data = client_socket.recv(4096).decode('utf-8')
                if not data:
                    return
                
                message = json.loads(data)
                message_type = message.get("type")
                
                if message_type == "register":
                    username_attempt = message["username"]
                    password = message["password"]
                    success, response = self.register_user(username_attempt, password)
                    
                    client_socket.send(json.dumps({
                        "type": "register_response",
                        "success": success,
                        "message": response
                    }).encode('utf-8'))
                
                elif message_type == "login":
                    username_attempt = message["username"]
                    password = message["password"]
                    success, response = self.authenticate_user(username_attempt, password)
                    
                    if success:
                        # Generate DH parameters for key exchange
                        server_private_key = self.parameters.generate_private_key()
                        server_public_key = server_private_key.public_key()
                        
                        # Serialize the public key and parameters to send to client
                        param_bytes = self.parameters.parameter_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.ParameterFormat.PKCS3
                        )
                        
                        public_bytes = server_public_key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        )
                        
                        # Send the DH parameters and public key to the client
                        client_socket.send(json.dumps({
                            "type": "login_response",
                            "success": True,
                            "message": response,
                            "dh_params": base64.b64encode(param_bytes).decode('utf-8'),
                            "public_key": base64.b64encode(public_bytes).decode('utf-8')
                        }).encode('utf-8'))
                        
                        # Wait for the client's public key
                        key_data = client_socket.recv(4096).decode('utf-8')
                        key_message = json.loads(key_data)
                        
                        if key_message["type"] == "dh_key":
                            # Deserialize the client's public key
                            client_public_key_bytes = base64.b64decode(key_message["public_key"].encode('utf-8'))
                            loaded_params = serialization.load_pem_parameters(param_bytes, backend=default_backend())
                            client_public_key = serialization.load_pem_public_key(
                                client_public_key_bytes, 
                                backend=default_backend()
                            )
                            
                            # Generate the shared key
                            shared_key = server_private_key.exchange(client_public_key)
                            
                            # Derive a session key using HKDF
                            derived_key = HKDF(
                                algorithm=hashes.SHA256(),
                                length=32,
                                salt=None,
                                info=b'handshake data',
                                backend=default_backend()
                            ).derive(shared_key)
                            
                            session_key = derived_key
                            username = username_attempt
                            
                            # Add the client to the clients dictionary
                            self.clients[username] = (client_socket, session_key)
                            
                            # Notify all clients about the new user
                            for client_username, (client_sock, client_key) in list(self.clients.items()):
                                if client_username != username:
                                    try:
                                        encrypted_notification = encrypt_message(f"User {username} has joined the chat", client_key)
                                        client_sock.send(json.dumps({
                                            "type": "message", 
                                            "data": encrypted_notification
                                        }).encode('utf-8'))
                                    except:
                                        self.clients.pop(client_username, None)
                    else:
                        client_socket.send(json.dumps({
                            "type": "login_response",
                            "success": False,
                            "message": response
                        }).encode('utf-8'))
            
            # Chat loop
            while True:
                data = client_socket.recv(4096).decode('utf-8')
                if not data:
                    break
                
                message = json.loads(data)
                
                if message["type"] == "message":
                    encrypted_message = message["data"]
                    decrypted_message = decrypt_message(encrypted_message, session_key)
                    self.broadcast(decrypted_message, username)
        
        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            # Remove the client from the clients dictionary
            if username in self.clients:
                self.clients.pop(username)
                
                # Notify all clients about the user leaving
                for client_username, (client_sock, client_key) in list(self.clients.items()):
                    try:
                        encrypted_notification = encrypt_message(f"User {username} has left the chat", client_key)
                        client_sock.send(json.dumps({
                            "type": "message", 
                            "data": encrypted_notification
                        }).encode('utf-8'))
                    except:
                        self.clients.pop(client_username, None)
            
            # Close the client socket
            client_socket.close()

# ----------------- Client Implementation -----------------

class SecureChatClient:
    def __init__(self, host='127.0.0.1', port=9999):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.username = None
        self.session_key = None
        self.running = False
    
    def connect(self):
        """Connect to the server"""
        try:
            self.socket.connect((self.host, self.port))
            return True
        except Exception as e:
            print(f"Error connecting to server: {e}")
            return False
    
    def register(self, username, password):
        """Register a new user"""
        message = {
            "type": "register",
            "username": username,
            "password": password
        }
        
        self.socket.send(json.dumps(message).encode('utf-8'))
        response = json.loads(self.socket.recv(4096).decode('utf-8'))
        
        return response["success"], response["message"]
    
    def login(self, username, password):
        """Login with credentials and perform key exchange"""
        message = {
            "type": "login",
            "username": username,
            "password": password
        }
        
        self.socket.send(json.dumps(message).encode('utf-8'))
        response = json.loads(self.socket.recv(4096).decode('utf-8'))
        
        if response["success"]:
            # DH key exchange
            dh_params_bytes = base64.b64decode(response["dh_params"].encode('utf-8'))
            server_public_key_bytes = base64.b64decode(response["public_key"].encode('utf-8'))
            
            # Load the parameters and server's public key
            parameters = serialization.load_pem_parameters(dh_params_bytes, backend=default_backend())
            server_public_key = serialization.load_pem_public_key(
                server_public_key_bytes, 
                backend=default_backend()
            )
            
            # Generate our own private and public keys
            private_key = parameters.generate_private_key()
            public_key = private_key.public_key()
            
            # Serialize our public key to send to the server
            public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Send our public key to the server
            key_message = {
                "type": "dh_key",
                "public_key": base64.b64encode(public_bytes).decode('utf-8')
            }
            
            self.socket.send(json.dumps(key_message).encode('utf-8'))
            
            # Generate the shared key
            shared_key = private_key.exchange(server_public_key)
            
            # Derive a session key using HKDF
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
                backend=default_backend()
            ).derive(shared_key)
            
            self.session_key = derived_key
            self.username = username
            
            return True, response["message"]
        else:
            return False, response["message"]
    
    def send_message(self, message):
        """Send an encrypted message to the server"""
        if not self.session_key:
            return False, "Not logged in"
        
        encrypted_message = encrypt_message(message, self.session_key)
        message_data = {
            "type": "message",
            "data": encrypted_message
        }
        
        try:
            self.socket.send(json.dumps(message_data).encode('utf-8'))
            return True, "Message sent"
        except Exception as e:
            return False, f"Error sending message: {e}"
    
    def receive_messages(self):
        """Continuously receive and decrypt messages from the server"""
        self.running = True
        
        while self.running:
            try:
                data = self.socket.recv(4096).decode('utf-8')
                if not data:
                    print("Disconnected from server")
                    self.running = False
                    break
                
                message = json.loads(data)
                
                if message["type"] == "message":
                    encrypted_message = message["data"]
                    decrypted_message = decrypt_message(encrypted_message, self.session_key)
                    print(decrypted_message)
            
            except Exception as e:
                print(f"Error receiving message: {e}")
                self.running = False
                break
    
    def start_receiving(self):
        """Start a thread to receive messages"""
        receive_thread = threading.Thread(target=self.receive_messages)
        receive_thread.daemon = True
        receive_thread.start()
    
    def close(self):
        """Close the connection"""
        self.running = False
        self.socket.close()

# ----------------- Main Functions -----------------

def run_server():
    """Run the chat server"""
    server = SecureChatServer()
    server.start()

def run_client():
    """Run the chat client"""
    client = SecureChatClient()
    
    if not client.connect():
        print("Failed to connect to server")
        return
    
    while True:
        print("\n1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Choose an option: ")
        
        if choice == "1":
            username = input("Enter username: ")
            password = input("Enter password: ")
            success, message = client.register(username, password)
            print(message)
        
        elif choice == "2":
            username = input("Enter username: ")
            password = input("Enter password: ")
            success, message = client.login(username, password)
            print(message)
            
            if success:
                client.start_receiving()
                print("Type 'exit' to quit")
                
                while True:
                    message = input()
                    if message.lower() == 'exit':
                        break
                    
                    client.send_message(message)
                
                break
        
        elif choice == "3":
            break
        
        else:
            print("Invalid choice")
    
    client.close()

if __name__ == "__main__":
    print("1. Run Server")
    print("2. Run Client")
    choice = input("Choose an option: ")
    
    if choice == "1":
        run_server()
    elif choice == "2":
        run_client()
    else:
        print("Invalid choice")
