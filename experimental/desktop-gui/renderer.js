// Renderer Logic

const views = {
    locked: document.getElementById('locked-view'),
    dashboard: document.getElementById('dashboard-view')
};

const ui = {
    unlockBtn: document.getElementById('unlock-btn'),
    lockBtn: document.getElementById('lock-btn'),
    pwdInput: document.getElementById('master-password'),
    status: document.getElementById('status-bar'),
    itemList: document.getElementById('item-list'),
    lockMsg: document.getElementById('lock-msg'),
    modal: {
        overlay: document.getElementById('modal-overlay'),
        site: document.getElementById('modal-site'),
        user: document.getElementById('modal-user'),
        secret: document.getElementById('modal-secret')
    }
};

let hostConnected = false;

// Initial State
switchView('locked');

window.vaultAPI.onMessage((msg) => {
    console.log("Host Msg:", msg);

    if (msg.type === "PONG") {
        hostConnected = true;
        ui.status.textContent = "Connected to SecureVault Core";
    }
    else if (msg.type === "UNLOCK_SUCCESS") {
        ui.pwdInput.value = '';
        ui.lockMsg.textContent = '';
        switchView('dashboard');
        refreshItems();
    }
    else if (msg.type === "CREDENTIALS_FOUND") {
        renderItems(msg.payload);
    }
    else if (msg.type === "ERROR" || msg.type === "FATAL_ERROR") {
        ui.status.textContent = "Error: " + msg.payload;
        if (msg.payload.includes("Unlock failed")) {
            ui.lockMsg.textContent = "Invalid Password";
            ui.pwdInput.classList.add('shake');
            setTimeout(() => ui.pwdInput.classList.remove('shake'), 500);
        }
    }
    else if (msg.type === "VAULT_LOCKED") {
        switchView('locked');
    }
});

// Ping
window.vaultAPI.send({ type: "PING" });

// Actions
ui.unlockBtn.addEventListener('click', () => {
    const pwd = ui.pwdInput.value;
    if (!pwd) return;
    ui.status.textContent = "Unlocking...";
    window.vaultAPI.send({ type: "UNLOCK_VAULT", password: pwd });
});

ui.lockBtn.addEventListener('click', () => {
    // We don't have explicit LOCK command in host yet? 
    // Actually host.py checks "is_unlocked". 
    // We can restart host or send a placeholder?
    // Let's rely on simple state for now or add LOCK to host if needed.
    // Host logic doesn't have LOCK command implemented in Phase 3 yet!
    // We should restart the app or implement LOCK.
    // For Phase 5, let's just reload the window.
    location.reload();
});

function refreshItems() {
    ui.status.textContent = "Loading credentials...";
    // Empty domain = List All (thanks to our update)
    window.vaultAPI.send({ type: "GET_CREDENTIALS", domain: "" });
}

function renderItems(items) {
    ui.itemList.innerHTML = '';
    ui.status.textContent = `Loaded ${items.length} items.`;

    if (items.length === 0) {
        ui.itemList.innerHTML = '<div style="padding:20px; text-align:center; color:#888;">No items found.</div>';
        return;
    }

    items.forEach(item => {
        const row = document.createElement('div');
        row.className = 'item-row';
        row.innerHTML = `
            <div>
                <div class="item-site">${item.site}</div>
                <div class="item-user">${item.username}</div>
            </div>
            <div style="color:#0071e3;">&rsaquo;</div>
        `;
        row.onclick = () => showDetail(item);
        ui.itemList.appendChild(row);
    });
}

function showDetail(item) {
    ui.modal.site.textContent = item.site;
    ui.modal.user.textContent = item.username;
    ui.modal.secret.textContent = item.secret; // Only in DOM when modal open
    ui.modal.secret.style.color = 'transparent';
    ui.modal.secret.style.textShadow = '0 0 5px rgba(0,0,0,0.5)';

    ui.modal.overlay.classList.add('active');
}

function switchView(viewName) {
    Object.keys(views).forEach(k => {
        views[k].classList.remove('active');
        if (k === viewName) views[k].classList.add('active');
    });

    if (viewName === 'locked') {
        ui.lockBtn.style.display = 'none';
        views.locked.classList.add('active'); // ensure flex display
    } else {
        ui.lockBtn.style.display = 'block';
    }
}
