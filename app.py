from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_cors import CORS
import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta
import json
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import ipfshttpclient
import uuid
import os

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
CORS(app)

DB_PATH = 'identity_vault.db'
IPFS_ADDR = os.environ.get('IPFS_API_ADDR', '/ip4/127.0.0.1/tcp/5001/http')

# Database initialization
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        did TEXT UNIQUE NOT NULL,
        public_key TEXT NOT NULL,
        private_key_encrypted TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    # DIDs registry
    c.execute('''CREATE TABLE IF NOT EXISTS did_registry (
        did TEXT PRIMARY KEY,
        public_key TEXT NOT NULL,
        controller TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        status TEXT DEFAULT 'active'
    )''')

    # Verifiable Credentials (note ipfs_hash column present)
    c.execute('''CREATE TABLE IF NOT EXISTS credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        credential_id TEXT UNIQUE NOT NULL,
        user_did TEXT NOT NULL,
        issuer_did TEXT NOT NULL,
        credential_type TEXT NOT NULL,
        credential_data TEXT NOT NULL,
        ipfs_hash TEXT,
        issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP,
        status TEXT DEFAULT 'active',
        FOREIGN KEY (user_did) REFERENCES did_registry(did)
    )''')

    # Verification logs
    c.execute('''CREATE TABLE IF NOT EXISTS verification_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        credential_id TEXT NOT NULL,
        verifier_did TEXT NOT NULL,
        verified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        verification_result TEXT NOT NULL,
        FOREIGN KEY (credential_id) REFERENCES credentials(credential_id)
    )''')

    # Revocation registry
    c.execute('''CREATE TABLE IF NOT EXISTS revocations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        credential_id TEXT NOT NULL,
        revoked_by TEXT NOT NULL,
        revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        reason TEXT,
        FOREIGN KEY (credential_id) REFERENCES credentials(credential_id)
    )''')

    conn.commit()
    conn.close()

# ----------------
# IPFS utilities
# ----------------
def get_ipfs_client():
    """
    Returns a connected ipfshttpclient client or None if connection fails.
    By default connects to local IPFS daemon at /ip4/127.0.0.1/tcp/5001/http,
    but you may override by setting environment variable IPFS_API_ADDR.
    """
    try:
        client = ipfshttpclient.connect(IPFS_ADDR)
        return client
    except Exception as e:
        # IPFS unavailable; return None to allow graceful fallback
        print(f"[IPFS] connection failed: {e}")
        return None

def ipfs_add_json(obj):
    """
    Adds a JSON-serializable Python object to IPFS and returns the CID (string).
    Returns (cid, None) on success, or (None, error_message) on failure.
    """
    client = get_ipfs_client()
    if client is None:
        return None, "IPFS daemon not available"

    try:
        # ipfshttpclient expects bytes; we'll encode JSON
        data = json.dumps(obj, sort_keys=True).encode('utf-8')
        res = client.add_bytes(data)
        # res is the CID (string)
        return res, None
    except Exception as e:
        return None, str(e)

def ipfs_cat_json(cid):
    """
    Fetches bytes from IPFS for given CID and decodes JSON.
    Returns (obj, None) on success, or (None, error_message) on failure.
    """
    client = get_ipfs_client()
    if client is None:
        return None, "IPFS daemon not available"

    try:
        raw = client.cat(cid)
        # raw is bytes
        obj = json.loads(raw.decode('utf-8'))
        return obj, None
    except Exception as e:
        return None, str(e)

# ----------------
# Cryptographic utilities
# ----------------
class CryptoUtils:
    @staticmethod
    def generate_keypair():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return private_pem.decode(), public_pem.decode()

    @staticmethod
    def sign_data(private_key_pem, data):
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None,
            backend=default_backend()
        )

        signature = private_key.sign(
            data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return base64.b64encode(signature).decode()

    @staticmethod
    def verify_signature(public_key_pem, data, signature):
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode(),
                backend=default_backend()
            )

            public_key.verify(
                base64.b64decode(signature),
                data.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

# ----------------
# DID Management
# ----------------
class DIDManager:
    @staticmethod
    def generate_did(public_key):
        key_hash = hashlib.sha256(public_key.encode()).hexdigest()
        return f"did:pixelgenesis:{key_hash[:32]}"

    @staticmethod
    def create_did_document(did, public_key):
        return {
            "@context": "https://www.w3.org/ns/did/v1",
            "id": did,
            "publicKey": [{
                "id": f"{did}#keys-1",
                "type": "RsaVerificationKey2018",
                "controller": did,
                "publicKeyPem": public_key
            }],
            "authentication": [f"{did}#keys-1"],
            "created": datetime.utcnow().isoformat(),
            "updated": datetime.utcnow().isoformat()
        }

    @staticmethod
    def register_did(did, public_key, controller):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        try:
            c.execute('''INSERT INTO did_registry (did, public_key, controller) 
                         VALUES (?, ?, ?)''', (did, public_key, controller))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()

    @staticmethod
    def resolve_did(did):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT did, public_key, controller, created_at, updated_at, status FROM did_registry WHERE did = ? AND status = "active"', (did,))
        result = c.fetchone()
        conn.close()

        if result:
            return {
                'did': result[0],
                'public_key': result[1],
                'controller': result[2],
                'created_at': result[3],
                'updated_at': result[4],
                'status': result[5]
            }
        return None

# ----------------
# Verifiable Credentials
# ----------------
class VCManager:
    @staticmethod
    def issue_credential(user_did, issuer_did, credential_type, credential_data, private_key):
        credential_id = f"vc:{uuid.uuid4()}"

        credential = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "id": credential_id,
            "type": ["VerifiableCredential", credential_type],
            "issuer": issuer_did,
            "issuanceDate": datetime.utcnow().isoformat(),
            "credentialSubject": {
                "id": user_did,
                **credential_data
            }
        }

        # Sign the credential (over canonicalized JSON string)
        credential_json = json.dumps(credential, sort_keys=True)
        signature = CryptoUtils.sign_data(private_key, credential_json)

        credential["proof"] = {
            "type": "RsaSignature2018",
            "created": datetime.utcnow().isoformat(),
            "proofPurpose": "assertionMethod",
            "verificationMethod": f"{issuer_did}#keys-1",
            "jws": signature
        }

        # Try adding credential JSON to IPFS
        ipfs_hash = None
        cid, err = ipfs_add_json(credential)
        if cid:
            ipfs_hash = cid
        else:
            # If IPFS not available, continue but notify
            print(f"[IPFS] failed to add credential: {err}")

        # Store in database (include ipfs_hash if available)
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''INSERT INTO credentials 
                     (credential_id, user_did, issuer_did, credential_type, credential_data, ipfs_hash)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                  (credential_id, user_did, issuer_did, credential_type, json.dumps(credential), ipfs_hash))
        conn.commit()
        conn.close()

        # Return credential object along with ipfs status
        return {
            "credential": credential,
            "ipfs_hash": ipfs_hash
        }

    @staticmethod
    def verify_credential(credential_id):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT credential_data, issuer_did, ipfs_hash, status FROM credentials WHERE credential_id = ?', 
                  (credential_id,))
        result = c.fetchone()
        conn.close()

        if not result:
            return False, "Credential not found"

        credential_json_text = result[0]
        issuer_did = result[1]
        ipfs_hash = result[2]
        status = result[3]

        if status == "revoked":
            return False, "Credential revoked"

        # If there's an ipfs_hash, try to fetch the canonical JSON from IPFS and use that
        credential_obj = None
        if ipfs_hash:
            fetched, err = ipfs_cat_json(ipfs_hash)
            if fetched:
                credential_obj = fetched
            else:
                # If IPFS fetch fails, fall back to DB-stored credential
                print(f"[IPFS] failed to fetch credential {ipfs_hash}: {err}")

        if not credential_obj:
            credential_obj = json.loads(credential_json_text)

        # Resolve issuer's DID to get public key
        issuer_info = DIDManager.resolve_did(issuer_did)
        if not issuer_info:
            return False, "Issuer DID not found"

        # Extract proof and verify signature over the credential without 'proof'
        proof = credential_obj.pop("proof", None)
        if not proof:
            return False, "Credential missing proof"

        credential_json_canonical = json.dumps(credential_obj, sort_keys=True)

        is_valid = CryptoUtils.verify_signature(
            issuer_info['public_key'],
            credential_json_canonical,
            proof.get('jws')
        )

        # Put proof back (to avoid modifying stored data)
        credential_obj['proof'] = proof

        return is_valid, "Valid credential" if is_valid else "Invalid signature"

    @staticmethod
    def revoke_credential(credential_id, revoker_did, reason):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('UPDATE credentials SET status = "revoked" WHERE credential_id = ?', 
                  (credential_id,))
        c.execute('INSERT INTO revocations (credential_id, revoked_by, reason) VALUES (?, ?, ?)',
                  (credential_id, revoker_did, reason))
        conn.commit()
        conn.close()

    @staticmethod
    def push_credential_to_ipfs(credential_id):
        """
        Utility to re-push an existing DB credential to IPFS (returns new CID).
        """
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT credential_data FROM credentials WHERE credential_id = ?', (credential_id,))
        row = c.fetchone()
        conn.close()

        if not row:
            return None, "Credential not found"

        credential_obj = json.loads(row[0])
        cid, err = ipfs_add_json(credential_obj)
        if cid:
            # update DB
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute('UPDATE credentials SET ipfs_hash = ? WHERE credential_id = ?', (cid, credential_id))
            conn.commit()
            conn.close()
            return cid, None
        else:
            return None, err

# ----------------
# Routes
# ----------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    # Generate keypair
    private_key, public_key = CryptoUtils.generate_keypair()

    # Generate DID
    did = DIDManager.generate_did(public_key)

    # Hash password
    password_hash = hashlib.sha256(password.encode()).hexdigest()

    # Register DID
    if not DIDManager.register_did(did, public_key, did):
        return jsonify({'error': 'DID registration failed'}), 400

    # Create user
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute('''INSERT INTO users 
                     (username, password_hash, did, public_key, private_key_encrypted)
                     VALUES (?, ?, ?, ?, ?)''',
                  (username, password_hash, did, public_key, private_key))
        conn.commit()

        return jsonify({
            'success': True,
            'did': did,
            'message': 'User registered successfully'
        })
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 400
    finally:
        conn.close()

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    password_hash = hashlib.sha256(password.encode()).hexdigest()

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT did, username FROM users WHERE username = ? AND password_hash = ?',
              (username, password_hash))
    result = c.fetchone()
    conn.close()

    if result:
        session['did'] = result[0]
        session['username'] = result[1]
        return jsonify({'success': True, 'did': result[0]})

    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/issue-credential', methods=['POST'])
def issue_credential():
    if 'did' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.json
    credential_type = data.get('credential_type')
    credential_data = data.get('credential_data')

    # Get user's private key
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT private_key_encrypted FROM users WHERE did = ?', (session['did'],))
    result = c.fetchone()
    conn.close()

    if not result:
        return jsonify({'error': 'User not found'}), 404

    private_key = result[0]

    # Issue credential (self-issued for demo)
    res = VCManager.issue_credential(
        session['did'],
        session['did'],
        credential_type,
        credential_data,
        private_key
    )

    return jsonify({
        'success': True,
        'credential': res['credential'],
        'ipfs_hash': res.get('ipfs_hash')
    })

@app.route('/my-credentials', methods=['GET'])
def get_my_credentials():
    if 'did' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''SELECT credential_id, credential_type, issued_at, status, ipfs_hash
                 FROM credentials WHERE user_did = ?''', (session['did'],))
    credentials = c.fetchall()
    conn.close()

    return jsonify({
        'credentials': [{
            'credential_id': cred[0],
            'credential_type': cred[1],
            'issued_at': cred[2],
            'status': cred[3],
            'ipfs_hash': cred[4]
        } for cred in credentials]
    })

@app.route('/verify-credential', methods=['POST'])
def verify_credential():
    data = request.json
    credential_id = data.get('credential_id')

    is_valid, message = VCManager.verify_credential(credential_id)

    # Log verification
    if 'did' in session:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''INSERT INTO verification_logs 
                     (credential_id, verifier_did, verification_result)
                     VALUES (?, ?, ?)''',
                  (credential_id, session['did'], message))
        conn.commit()
        conn.close()

    return jsonify({
        'valid': is_valid,
        'message': message
    })

@app.route('/resolve-did/<did>', methods=['GET'])
def resolve_did(did):
    did_document = DIDManager.resolve_did(did)

    if did_document:
        return jsonify(did_document)

    return jsonify({'error': 'DID not found'}), 404

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})

# Additional IPFS endpoints -------------------------------------------------
@app.route('/credential/<credential_id>/ipfs', methods=['GET'])
def get_credential_ipfs(credential_id):
    """
    Fetch credential JSON from IPFS if ipfs_hash exists for this credential.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT ipfs_hash FROM credentials WHERE credential_id = ?', (credential_id,))
    row = c.fetchone()
    conn.close()

    if not row:
        return jsonify({'error': 'Credential not found'}), 404

    ipfs_hash = row[0]
    if not ipfs_hash:
        return jsonify({'error': 'Credential has no ipfs_hash'}), 404

    obj, err = ipfs_cat_json(ipfs_hash)
    if obj:
        return jsonify({'ipfs_hash': ipfs_hash, 'credential': obj})
    else:
        return jsonify({'error': f'Failed to fetch from IPFS: {err}'}), 500

@app.route('/credential/<credential_id>/push-to-ipfs', methods=['POST'])
def push_credential_to_ipfs(credential_id):
    """
    Re-push a DB credential to IPFS (useful if you restored DB but lost IPFS).
    """
    cid, err = VCManager.push_credential_to_ipfs(credential_id)
    if cid:
        return jsonify({'success': True, 'ipfs_hash': cid})
    else:
        return jsonify({'error': f'Failed to push to IPFS: {err}'}), 500

# --------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    print("🚀 Decentralized Identity Vault starting...")
    print("📊 Database initialized")
    print("🔐 DID system ready")
    print(f"🌐 IPFS API: {IPFS_ADDR}")
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
