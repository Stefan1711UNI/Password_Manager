## Password Manager

A user-friendly password manager with:

- **Custom AES Encryption** 
- **AI-Powered Natural-Language Passphrase Generator**  
- **Tkinter GUI** for cross-platform ease (Windows, macOS, Linux)

---

## Features

- 🔒 **Encrypted Vault**:  
  - Derive a 32-byte key via `SHA-256(master_password)`.  
  - AES-GCM with 12-byte nonce + 16-byte tag, in-place file encryption. 

- 🤖 **Passphrase Generator**:  
  - AI suggests a 3 word, ~50 bits entropy passphrase  

- 🗄️ **Local Storage**:  
  - Single encrypted SQL-lite database(no cloud)

---
