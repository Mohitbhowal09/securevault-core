#!/usr/bin/env python3
import sys
import os
import json
import struct
import time
import base64

# Ensure imports work from core
# Ensure imports work from core
current_dir = os.path.dirname(os.path.abspath(__file__))
core_dir = os.path.dirname(current_dir)
sys.path.append(core_dir)

# --- VENV AUTO-ACTIVATION ---
# Chrome launches this script with system python. We need to use the venv if dependencies like 'cryptography' are missing.
try:
    import cryptography
except ImportError:
    # Look for venv
    venv_python = os.path.join(core_dir, "venv", "bin", "python3")
    if os.path.exists(venv_python):
        # Prevent infinite loop if venv is broken
        if sys.executable != venv_python:
            # Re-execute this script with the venv python
            os.execv(venv_python, [venv_python] + sys.argv)
    else:
        # Fallback: maybe it's in a different location or deps are global. 
        # We proceed and let the try/except in main catch the inevitable crash.
        pass

from app.vault import Vault, VaultError
from app.webauthn_util import WebAuthnUtil

# Secrets persistence for Passkey Wrapper
# NOTE: In a real prod app, use Keychain/DPAPI. 
# Here we simulate obfuscated storage in a dotfile.
PASSKEY_SECRET_FILE = os.path.join(core_dir, ".passkey_secret")

# Protocol Constants
# Protocol Constants
MAX_MSG_SIZE = 1024 * 1024 # 1MB

def read_exact(stream, num_bytes):
    """Read exactly num_bytes from stream, blocking until available."""
    data = b''
    while len(data) < num_bytes:
        chunk = stream.read(num_bytes - len(data))
        if not chunk:
            return None # EOF
        data += chunk
    return data

def read_message():
    """Read a message from stdin (length prefixed)."""
    raw_length = read_exact(sys.stdin.buffer, 4)
    if not raw_length:
        return None
        
    message_length = struct.unpack('@I', raw_length)[0]
    
    # Sanity check length
    if message_length > MAX_MSG_SIZE:
        raise ValueError(f"Message too large: {message_length}")
        
    message_data = read_exact(sys.stdin.buffer, message_length)
    if not message_data:
        raise ValueError("Unexpected EOF reading message body")
        
    return json.loads(message_data.decode('utf-8'))

def send_message(content):
    """Send a message to stdout (length prefixed)."""
    encoded_content = json.dumps(content).encode('utf-8')
    encoded_length = struct.pack('@I', len(encoded_content))
    sys.stdout.buffer.write(encoded_length)
    sys.stdout.buffer.write(encoded_content)
    sys.stdout.buffer.flush()

def main():
    try:
        # Initialize Vault (locked initially)
        vault_path = os.path.join(core_dir, "secure_vault.dat")
        vault = Vault(vault_path)
        
        while True:
            try:
                msg = read_message()
                if not msg:
                    break
                    
                msg_type = msg.get('type')
                
                if msg_type == 'PING':
                    send_message({"type": "PONG", "payload": "Host is alive"})
                    
                elif msg_type == 'UNLOCK_VAULT':
                    password = msg.get('password')
                    try:
                        vault.unlock(password)
                        send_message({"type": "UNLOCK_SUCCESS", "payload": "Vault unlocked"})
                    except Exception as e:
                        send_message({"type": "ERROR", "payload": str(e)})

                elif msg_type == 'GET_CREDENTIALS':
                    if not vault.is_unlocked():
                        send_message({"type": "VAULT_LOCKED", "payload": "Vault is locked"})
                        continue
                        
                    domain = msg.get('domain')
                    results = []
                    for item in vault.list_items():
                        # If domain is provided, filter. If None/Empty, return all (for Desktop App).
                        if not domain or domain in item.site:
                            results.append(item.to_dict())
                    
                    send_message({"type": "CREDENTIALS_FOUND", "payload": results})
    
                # --- WebAuthn Registration ---
                elif msg_type == 'PASSKEY_REG_START':
                    if not vault.is_unlocked():
                        send_message({"type": "ERROR", "payload": "Vault must be unlocked to register passkey."})
                        continue
                    
                    challenge = WebAuthnUtil.generate_challenge()
                    vault.current_challenge = challenge 
                    
                    send_message({"type": "PASSKEY_REG_APP_START", "challenge": challenge})

                elif msg_type == 'PASSKEY_REG_FINISH':
                    try:
                        cred_id = msg.get('id')
                        # Phase 4 Simplification (Simulation)
                        pub_key_pem = msg.get('public_key_pem')
                        if not pub_key_pem:
                             # Should log or handle missing key
                             pass

                        passkey_secret = vault.register_passkey(cred_id, pub_key_pem, "user_handle")
                        
                        with open(PASSKEY_SECRET_FILE, 'wb') as f:
                            f.write(passkey_secret)
                            
                        send_message({"type": "PASSKEY_REG_SUCCESS", "payload": "Passkey registered"})
                    except Exception as e:
                        send_message({"type": "ERROR", "payload": str(e)})

                # --- WebAuthn Authentication ---
                elif msg_type == 'PASSKEY_AUTH_START':
                    # Reload passkeys from disk if needed (handles locked state listing public keys)
                    if not vault.passkeys and os.path.exists(vault.store.file_path):
                        try:
                            with open(vault.store.file_path, 'r') as f:
                                raw = json.load(f)
                                vault.passkeys = raw.get('passkeys', [])
                        except:
                            pass
                    
                    if not vault.passkeys:
                        send_message({"type": "ERROR", "payload": "No passkeys registered."})
                        continue

                    challenge = WebAuthnUtil.generate_challenge()
                    vault.current_challenge = challenge
                    
                    allow_list = [{"type": "public-key", "id": pk['id']} for pk in vault.passkeys]
                    
                    send_message({
                        "type": "PASSKEY_AUTH_APP_START", 
                        "challenge": challenge,
                        "allowCredentials": allow_list
                    })

                elif msg_type == 'PASSKEY_AUTH_FINISH':
                    try:
                        cred_id = msg.get('id')
                        signature = base64.b64decode(msg.get('signature'))
                        auth_data = base64.b64decode(msg.get('authenticatorData'))
                        client_data_json = base64.b64decode(msg.get('clientDataJSON'))
                        
                        target_pk = next((pk for pk in vault.passkeys if pk['id'] == cred_id), None)
                        if not target_pk:
                            raise ValueError("Unknown credential")
                            
                        valid = WebAuthnUtil.verify_assertion(
                            target_pk['public_key'], 
                            signature, 
                            client_data_json, 
                            auth_data
                        )
                        
                        if valid:
                            if not os.path.exists(PASSKEY_SECRET_FILE):
                                 raise ValueError("Passkey secret missing")
                                 
                            with open(PASSKEY_SECRET_FILE, 'rb') as f:
                                 passkey_secret = f.read()
                                 
                            vault.unlock_with_passkey_secret(passkey_secret)
                            send_message({"type": "UNLOCK_SUCCESS", "payload": "Unlocked with Passkey"})
                        else:
                            send_message({"type": "ERROR", "payload": "Invalid signature"})
                            
                    except Exception as e:
                        send_message({"type": "ERROR", "payload": f"Auth failed: {e}"})

                else:
                    send_message({"type": "ERROR", "payload": "Unknown command"})
                    
            except Exception as e:
                # Catch parse errors or logic errors in loop
                send_message({"type": "FATAL_ERROR", "payload": f"Loop Error: {e}"})
                
    except Exception as e:
        # Top level crash (imports, init, etc)
        # Log to stderr so Chrome can see it
        sys.stderr.write(f"Host Crash: {e}\n")
        sys.stderr.flush()

if __name__ == '__main__':
    # Windows binary mode fix (harmless on Mac but good practice)
    try:
        import msvcrt
        msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    except ImportError:
        pass
        
    main()
