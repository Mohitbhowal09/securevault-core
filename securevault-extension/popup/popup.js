// Popup Logic

const statusEl = document.getElementById('status');
const lockedView = document.getElementById('vault-locked');
const unlockedView = document.getElementById('vault-unlocked');
const credentialsList = document.getElementById('credentials-list');
const passwordInput = document.getElementById('password-input');
const unlockBtn = document.getElementById('unlock-btn');
const passkeyLoginBtn = document.getElementById('passkey-login-btn');
const passkeyRegisterBtn = document.getElementById('passkey-register-btn');

let currentDomain = "";
let currentChallenge = "";

// --- Utils ---
function bufferToBase64(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function base64ToBuffer(base64) {
    const binary_string = atob(base64.replace(/_/g, '/').replace(/-/g, '+')); // Handle urlsafe
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}

// Initialize
document.addEventListener('DOMContentLoaded', async () => {
    // Get current tab URL
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url) {
        try {
            const url = new URL(tab.url);
            currentDomain = url.hostname;
        } catch (e) {
            currentDomain = "";
        }
    }

    // Ping host to check status 
    requestCredentials(currentDomain);

    // Status listener
    chrome.runtime.onMessage.addListener((message) => {
        if (message.type === "HOST_RESPONSE") {
            const res = message.payload;
            handleResponse(res);
        }
    });
});

unlockBtn.addEventListener('click', () => {
    const pwd = passwordInput.value;
    if (!pwd) return;

    statusEl.textContent = "Unlocking...";
    chrome.runtime.sendMessage({
        type: "SEND_TO_HOST",
        payload: { type: "UNLOCK_VAULT", password: pwd }
    });
});

passkeyLoginBtn.addEventListener('click', () => {
    statusEl.textContent = "Starting Passkey Login...";
    chrome.runtime.sendMessage({
        type: "SEND_TO_HOST",
        payload: { type: "PASSKEY_AUTH_START" }
    });
});

passkeyRegisterBtn.addEventListener('click', () => {
    statusEl.textContent = "Requesting registration...";
    chrome.runtime.sendMessage({
        type: "SEND_TO_HOST",
        payload: { type: "PASSKEY_REG_START" }
    });
});

function requestCredentials(domain) {
    statusEl.textContent = "Checking vault...";
    chrome.runtime.sendMessage({
        type: "SEND_TO_HOST",
        payload: { type: "GET_CREDENTIALS", domain: domain }
    });
}

async function handleResponse(res) {
    console.log("Popup handling:", res);

    if (res.type === "PONG") {
        statusEl.textContent = "Host connected.";
    }
    else if (res.type === "VAULT_LOCKED") {
        showLocked();
        statusEl.textContent = "Please unlock vault.";
    }
    else if (res.type === "UNLOCK_SUCCESS") {
        passwordInput.value = "";
        statusEl.textContent = "Unlocked!";
        requestCredentials(currentDomain);
    }
    else if (res.type === "CREDENTIALS_FOUND") {
        showUnlocked();
        renderCredentials(res.payload);
        statusEl.textContent = res.payload.length > 0 ? "Credentials found." : "No credentials for this site.";
    }
    else if (res.type === "PASSKEY_REG_APP_START") {
        // Host sent challenge. Trigger WebAuthn Create.
        try {
            statusEl.textContent = "Touch your authenticator...";
            const challenge = base64ToBuffer(res.challenge);

            const credential = await navigator.credentials.create({
                publicKey: {
                    challenge: challenge,
                    rp: { name: "SecureVault Core", id: "securevault-extension" }, // RP ID is tricky for extensions. usually extension id?
                    // Actually, Chrome Extensions must use their ID as RP ID or strict subsets. 
                    // Use 'self' effectively logic? 
                    // Or don't specify rp.id to let browser default to origin `chrome-extension://...`
                    // Let's try omitting rp.id first.
                    rp: { name: "SecureVault" },
                    user: {
                        id: new Uint8Array(16), // Random user ID
                        name: "vault_owner",
                        displayName: "Vault Owner"
                    },
                    pubKeyCredParams: [{ alg: -7, type: "public-key" }], // ES256
                    timeout: 60000,
                    attestation: "direct"
                }
            });

            // Extract SPKI (Subject Public Key Info) - Requires Chrome 114+
            let spkiPem = "";
            let pubKeyBuffer = null;
            if (credential.response.getPublicKey) {
                pubKeyBuffer = credential.response.getPublicKey();
            } else if (credential.response.getPublicKeyAlgorithm) {
                // Fallback not implemented
            }

            if (pubKeyBuffer) {
                // Convert DER to PEM
                const b64 = bufferToBase64(pubKeyBuffer);
                spkiPem = `-----BEGIN PUBLIC KEY-----\n${b64}\n-----END PUBLIC KEY-----`;
            } else {
                // Mock for Phase 4 if browser too old, or rely on Host fallback
                console.warn("Could not extract SPKI from browser.");
            }

            // Send back to host
            chrome.runtime.sendMessage({
                type: "SEND_TO_HOST",
                payload: {
                    type: "PASSKEY_REG_FINISH",
                    id: credential.id,
                    public_key_pem: spkiPem
                    // We don't send attestation object if we sent PEM, simplifying host logic
                }
            });

        } catch (e) {
            console.error(e);
            statusEl.textContent = "Reg failed: " + e.message;
        }
    }
    else if (res.type === "PASSKEY_REG_SUCCESS") {
        statusEl.textContent = "Passkey Registered!";
        setTimeout(() => statusEl.textContent = "", 3000);
    }
    else if (res.type === "PASSKEY_AUTH_APP_START") {
        // Host sent challenge + allowed credentials
        try {
            statusEl.textContent = "Touch your authenticator...";
            const challenge = base64ToBuffer(res.challenge);
            const allowCredentials = res.allowCredentials.map(c => ({
                type: c.type,
                id: base64ToBuffer(c.id)
            }));

            const assertion = await navigator.credentials.get({
                publicKey: {
                    challenge: challenge,
                    allowCredentials: allowCredentials,
                    userVerification: "required",
                    timeout: 60000
                }
            });

            // Send back to host
            chrome.runtime.sendMessage({
                type: "SEND_TO_HOST",
                payload: {
                    type: "PASSKEY_AUTH_FINISH",
                    id: assertion.id,
                    signature: bufferToBase64(assertion.response.signature),
                    authenticatorData: bufferToBase64(assertion.response.authenticatorData),
                    clientDataJSON: bufferToBase64(assertion.response.clientDataJSON)
                }
            });

        } catch (e) {
            console.error(e);
            statusEl.textContent = "Auth failed: " + e.message;
        }
    }
    else if (res.type === "ERROR" || res.type === "FATAL_ERROR") {
        statusEl.textContent = "Error: " + res.payload;
        // If error is decryption fail, probably wrong password
        if (res.payload.includes("Unlock failed")) {
            statusEl.textContent = "Invalid password.";
        }
    }
}

function showLocked() {
    lockedView.classList.remove('hidden');
    unlockedView.classList.add('hidden');
}

function showUnlocked() {
    lockedView.classList.add('hidden');
    unlockedView.classList.remove('hidden');
}

function renderCredentials(items) {
    credentialsList.innerHTML = "";

    if (items.length === 0) {
        credentialsList.innerHTML = "<div style='padding:10px;text-align:center;color:#888'>No logins found for " + currentDomain + "</div>";
        return;
    }

    items.forEach(item => {
        const div = document.createElement('div');
        div.className = 'credential-item';
        div.innerHTML = `
            <div class="site-name">${item.site}</div>
            <div class="username">${item.username}</div>
        `;
        div.onclick = () => {
            fillCredential(item.username, item.secret);
        };
        credentialsList.appendChild(div);
    });
}

async function fillCredential(username, secret) {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) return;

    chrome.tabs.sendMessage(tab.id, {
        type: "FILL_CREDENTIALS",
        data: { username, secret }
    }, (response) => {
        if (chrome.runtime.lastError) {
            statusEl.textContent = "Could not autofill. Refresh page?";
        } else if (response && response.success) {
            window.close(); // Close popup on success
        } else {
            statusEl.textContent = "Autofill failed: " + (response?.error || "unknown");
        }
    });
}
