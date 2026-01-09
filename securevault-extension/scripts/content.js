// SecureVault Content Script

console.log("[SecureVault] Content script loaded.");

/**
 * Scans the page for password fields and attempts to identify the username field.
 * Returns an array of detected forms.
 */
function findLoginForms() {
    const passwordInputs = document.querySelectorAll('input[type="password"]');
    const forms = [];

    passwordInputs.forEach((pwdInput) => {
        // Only process visible fields
        if (pwdInput.offsetParent === null) return;

        // Finding corresponding username input
        // Heuristic: Look for the closest preceding visible text/email input in the same form (or nearby in DOM)
        let userInput = null;
        let formElement = pwdInput.form;

        if (formElement) {
            // Standard form structure
            const inputs = Array.from(formElement.querySelectorAll('input:not([type="hidden"]):not([type="submit"]):not([type="button"])'));
            const pwdIndex = inputs.indexOf(pwdInput);
            if (pwdIndex > 0) {
                // Check immediate predecessor
                const candidate = inputs[pwdIndex - 1];
                if (candidate.type === 'text' || candidate.type === 'email' || candidate.type === 'tel') {
                    userInput = candidate;
                }
            }
        } else {
            // Non-standard structure (no <form> tag)
            // Look at previous siblings or nearby elements?
            // For Phase 3, let's keep it robust for standard forms or inputs with IDs.
        }

        if (userInput) {
            // Mark fields to avoid re-scanning or to style them later
            pwdInput.dataset.svDetected = "true";
            userInput.dataset.svDetected = "true";

            forms.push({
                user: userInput,
                pass: pwdInput
            });

            console.log("[SecureVault] Login detected:", userInput.name || userInput.id, pwdInput.name || pwdInput.id);
        }
    });

    return forms;
}

// Initial scan
const detectedForms = findLoginForms();

// Notify background if forms found (optional, to update badge)
if (detectedForms.length > 0) {
    chrome.runtime.sendMessage({ type: "LOGIN_DETECTED", count: detectedForms.length });
}

// Listen for fill commands from Popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "FILL_CREDENTIALS") {
        const { username, secret } = message.data;

        // Re-scan to ensure references are fresh (SPA/DOM changes)
        const forms = findLoginForms();
        if (forms.length > 0) {
            // Fill the first matching or most likely form. 
            // For now, simpler: Fill the first detected form.
            // Better: Fill all? OR active element?
            // Strategy: Fill the first detected pair.
            const target = forms[0];

            target.user.value = username;
            target.user.dispatchEvent(new Event('input', { bubbles: true }));
            target.user.dispatchEvent(new Event('change', { bubbles: true }));

            target.pass.value = secret;
            target.pass.dispatchEvent(new Event('input', { bubbles: true }));
            target.pass.dispatchEvent(new Event('change', { bubbles: true }));

            console.log("[SecureVault] Credentials filled.");
            sendResponse({ success: true });
        } else {
            console.warn("[SecureVault] No login fields found to fill.");
            sendResponse({ success: false, error: "No fields found" });
        }
    }
});
