# Secure Chat System

A Python-based client-server chat application with robust security features, developed as part of a Cybersecurity course project. This system ensures confidential communication through modern encryption techniques and secure user authentication.

![Security](https://img.shields.io/badge/Security-Enhanced-green)
![Python](https://img.shields.io/badge/Python-3.6+-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)

## 🔒 Key Security Features

### User Authentication
- **Secure Registration**: Create accounts with unique usernames
- **Password Protection**: All passwords are salted and hashed using SHA-256
- **Credential Storage**: User information securely stored in a structured JSON file

### Encrypted Communication
- **Diffie-Hellman Key Exchange**: Securely establish shared session keys between clients and server
- **AES-128 CBC Mode Encryption**: All messages are encrypted in transit
- **Message Integrity**: Proper implementation of initialization vectors (IV) and padding

## 📋 Technical Implementation

- **Client-Server Architecture**: Multi-threaded design to handle multiple simultaneous connections
- **Symmetric Encryption**: AES implementation for message confidentiality
- **Key Derivation**: HKDF for generating strong cryptographic keys
- **Networking**: TCP sockets for reliable communication

## 🔧 Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/secure-chat-system.git
   cd secure-chat-system
   ```

2. Install required dependencies:
   ```
   pip install cryptography
   ```

3. No additional configuration needed - the system is ready to run!

## 🚀 Usage

### Running the Server

1. Start the script:
   ```
   python secure_chat.py
   ```

2. Select option `1` to run the server
3. The server will begin listening for incoming connections

### Connecting as a Client

1. Start the script in a new terminal:
   ```
   python secure_chat.py
   ```

2. Select option `2` to run as a client
3. Choose whether to register a new account or login with existing credentials
4. Once logged in, you can send and receive encrypted messages

### Commands

- Type your message and press Enter to send
- Type `exit` to disconnect from the chat

## 🔍 Security Analysis

This implementation protects against several common attacks:

- **Eavesdropping**: All traffic is encrypted using AES-128
- **Password Attacks**: Salted hashing prevents rainbow table and dictionary attacks
- **Man-in-the-Middle**: Diffie-Hellman key exchange helps secure the initial connection
- **Replay Attacks**: Unique IVs for each message prevent message replay

You can verify the security of this system using tools like Wireshark to observe that message content remains confidential during transmission.

## 📝 Project Structure

```
secure_chat.py       # Main application file containing both server and client code
server_credentials.json  # Generated credentials storage file (created on first run)
```

### Key Components:

- **SecureChatServer**: Handles client connections, authentication, and message broadcasting
- **SecureChatClient**: Manages user interface, encryption, and communication with the server
- **Utility Functions**: Password hashing, encryption/decryption, and other security operations

## 🧪 Testing

Verify the application's security features:

1. **Password Security**: Check that passwords are properly salted and hashed in the credentials file
2. **Network Security**: Use Wireshark to capture and analyze traffic between clients and server
3. **Key Exchange**: Confirm the use of Diffie-Hellman by observing the handshake process

## 📚 Learning Outcomes

This project demonstrates understanding of:

- Cryptographic principles and their practical application
- Secure coding practices in networked applications
- Authentication and authorization systems
- Threat modeling and security analysis

## 🔜 Future Enhancements

Potential improvements for this system:

- Certificate-based authentication for server verification
- Perfect Forward Secrecy with ephemeral keys
- Message signing for non-repudiation
- Group chat encryption using broadcast encryption techniques

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.


---

*Note: This application is designed for educational purposes to demonstrate cryptographic principles. For production use, consider additional security reviews and hardening.*
