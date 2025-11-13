# Decentralized Identity Vault - Setup Guide

## 📋 Requirements

- Python
- ipfs
- Flask==3.0.0
- flask-cors==4.0.0
- cryptography==41.0.7
- ipfshttpclient==0.8.0a2

## 🚀 Installation Steps

### 1. Clone Project Directory
```bash
git clone https://github.com/prajingn/encryptic.git
cd encryptic
```

### 2. Create Virtual Environment
```bash
python -m venv venv

# Activate on Windows:
venv\Scripts\activate

# Activate on Mac/Linux:
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Application
```bash
python app.py
```

The application will start on `http://localhost:5000`

## 🎯 Features Implemented

### ✅ Core Features
- **Decentralized Identifiers (DIDs)**: Unique blockchain-anchored identities
- **Verifiable Credentials**: Issue and manage digital credentials
- **Cryptographic Security**: RSA key pairs for signing and verification
- **DID Registry**: Blockchain-like registry for DID documents
- **Credential Verification**: Cryptographic proof verification
- **Selective Disclosure**: Share only necessary credential data
- **Revocation System**: Ability to revoke credentials
- **IPFS**: Decentralized storage system

### 🔐 Security Features
- Password hashing (SHA-256)
- RSA 2048-bit encryption
- Digital signatures for credentials
- Session management
- Secure key storage

### 📊 Database Schema
- **Users**: Store user accounts and DIDs
- **DID Registry**: Track all registered DIDs
- **Credentials**: Store verifiable credentials
- **Verification Logs**: Audit trail of verifications
- **Revocations**: Track revoked credentials

## 🎮 How to Use

### 1. Register a New User
- Enter username and password
- System generates DID and cryptographic keys
- DID is automatically registered on the blockchain

### 2. Issue Credentials
- Select credential type (Aadhaar, PAN, Education, etc.)
- Enter document details
- Add additional data in JSON format
- Credential is cryptographically signed and stored

### 3. Verify Credentials
- Enter credential ID
- System verifies cryptographic signature
- Shows validation result

### 4. Resolve DIDs
- Enter any DID
- View DID document with public key and metadata

## 🔧 Advanced Configuration

### IPFS Integration
To enable IPFS storage:

1. Install IPFS Desktop or IPFS daemon
2. Start IPFS: `ipfs daemon`
3. The app will connect to `http://localhost:5001`

### Database Customization
The SQLite database (`identity_vault.db`) is created automatically. To reset:
```bash
rm identity_vault.db
python app.py
```

## 🌐 API Endpoints

### Authentication
- `POST /register` - Register new user
- `POST /login` - Login user
- `POST /logout` - Logout user

### Credentials
- `POST /issue-credential` - Issue new credential
- `GET /my-credentials` - Get user's credentials
- `POST /verify-credential` - Verify credential

### DID Management
- `GET /resolve-did/<did>` - Resolve DID document

## 📚 Technology Stack

- **Backend**: Python Flask
- **Database**: SQLite (development)
- **Cryptography**: RSA-2048, SHA-256
- **Standards**: W3C DID, Verifiable Credentials
- **Storage**: IPFS (optional)

## 🎨 Credential Types Supported

1. **Aadhaar Card** - Indian national ID
2. **PAN Card** - Permanent Account Number
3. **Educational Certificates** - Academic credentials
4. **Driving License** - Driving credentials
5. **Passport** - International travel documents

## 🔄 Future Enhancements

- [ ] Zero-knowledge proofs for selective disclosure
- [ ] Multi-signature support
- [ ] Biometric authentication
- [ ] Mobile app integration
- [ ] QR code credential sharing
- [ ] Smart contract integration
- [ ] DID recovery mechanisms
- [ ] Multi-language support

## 🐛 Troubleshooting

### Database Locked Error
```bash
# Close all connections and restart
rm identity_vault.db
python app.py
```

### IPFS Connection Error
- Ensure IPFS daemon is running
- Check firewall settings
- Verify IPFS API endpoint

### Cryptography Errors
```bash
# Reinstall cryptography
pip uninstall cryptography
pip install cryptography
```

## 📄 License

This project implements W3C standards and is built for educational and demonstration purposes.

---

**Built with ❤️ for PixelGenesis Hackathon**