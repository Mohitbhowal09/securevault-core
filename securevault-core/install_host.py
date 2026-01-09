import os
import json
import sys
import platform

EXTENSION_ID = "knldjmfmopnpolahpmmgbagdohdnhkik" # Placeholder, we need the actual ID or allow any (dev mode)
# In Dev Mode, Chrome generates an ID based on path. 
# We usually can't predict it unless we key extensions.
# For this task, we will instruct the user to update the ID after loading.
# OR, we allow "*" for testing if Chrome permits (it usually strictly requires ID).
# Strategy: We will document that the user must update this file or we use a hardcoded ID if we pack it.
# Let's generate a JSON with a placeholder and print instructions.

HOST_NAME = "com.securevault.host"

def install():
    home = os.path.expanduser("~")
    
    if sys.platform != "darwin":
        print("This script currently supports macOS only.")
        return

    # Chrome Native Messaging Host path on macOS
    target_dir = os.path.join(home, "Library/Application Support/Google/Chrome/NativeMessagingHosts")
    os.makedirs(target_dir, exist_ok=True)
    
    target_file = os.path.join(target_dir, f"{HOST_NAME}.json")
    
    # Path to the wrapper script (more robust than direct python invocation)
    host_script_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "native_host", "run_host.sh"))
    
    # Manifest content
    manifest = {
        "name": HOST_NAME,
        "description": "SecureVault Native Messaging Host",
        "path": host_script_path,
        "type": "stdio",
        "allowed_origins": [
            f"chrome-extension://{EXTENSION_ID}/" 
        ]
    }
    
    with open(target_file, 'w') as f:
        json.dump(manifest, f, indent=2)
        
    print(f"Native Host Manifest installed to: {target_file}")
    print(f"Host script path: {host_script_path}")
    print(f"Allowed Extension ID: {EXTENSION_ID}")
    print("\nIMPORTANT: If your extension ID is different (it will be in Dev Mode), edit the JSON file manually.")

if __name__ == "__main__":
    install()
