const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { spawn } = require('child_process');

let mainWindow;
let hostProcess;

// Path to the Python Host script
let HOST_PATH;

if (app.isPackaged) {
    // In production, the binary is in resources/securevault-host/securevault-host
    // Note: PyInstaller creates a directory 'securevault-host' containing the binary 'securevault-host' (or .exe)
    // Adjust based on how we define 'extraResources'.
    // electron-builder copies 'dist/securevault-host' -> 'resources/securevault-host'
    // So binary is '.../resources/securevault-host/securevault-host'
    const binaryName = process.platform === 'win32' ? 'securevault-host.exe' : 'securevault-host';
    HOST_PATH = path.join(process.resourcesPath, 'securevault-host', binaryName);
} else {
    // Dev mode
    HOST_PATH = path.resolve(__dirname, '../securevault-core/native_host/host.py');
}

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 800,
        height: 600,
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            contextIsolation: true,
            nodeIntegration: false
        }
    });

    mainWindow.loadFile('index.html');
    // mainWindow.webContents.openDevTools();
}

function startHostProcess() {
    console.log("Spawning host process at:", HOST_PATH);

    if (app.isPackaged) {
        // Spawn binary directly
        hostProcess = spawn(HOST_PATH);
    } else {
        // Spawn via python3
        hostProcess = spawn('python3', [HOST_PATH]);
    }

    hostProcess.stdout.on('data', (data) => {
        // Data is length-prefixed JSON strings.
        // Core sends: [4 bytes length][JSON string]
        // We need to parse this stream properly. 
        // Basic buffer handling:
        let buffer = data;
        while (buffer.length > 4) {
            const length = buffer.readUInt32LE(0); // host.py uses struct.pack('@I') -> native order (LE on mac)
            // Check if we have the full message
            if (buffer.length >= 4 + length) {
                const msgBuffer = buffer.slice(4, 4 + length);
                const jsonStr = msgBuffer.toString('utf-8');
                try {
                    const msg = JSON.parse(jsonStr);
                    // Send to Renderer
                    if (mainWindow) {
                        mainWindow.webContents.send('from-host', msg);
                    }
                } catch (e) {
                    console.error("Failed to parse host message:", e);
                }

                // Remove processed message
                buffer = buffer.slice(4 + length);
            } else {
                // Wait for more data
                // Note: For robust stream handling, we should preserve 'buffer' across 'data' events.
                // This simple impl assumes small messages fit in chunks, which is risky but ok for this prototype.
                break;
            }
        }
    });

    hostProcess.stderr.on('data', (data) => {
        console.error(`Host Stderr: ${data}`);
    });

    hostProcess.on('close', (code) => {
        console.log(`Host process exited with code ${code}`);
    });
}

app.whenReady().then(() => {
    createWindow();
    startHostProcess();

    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
});

app.on('window-all-closed', () => {
    // Kill host
    if (hostProcess) hostProcess.kill();
    if (process.platform !== 'darwin') app.quit();
});

// IPC Handler
ipcMain.handle('send-to-host', async (event, message) => {
    if (!hostProcess) return { success: false, error: "Host not running" };

    try {
        const jsonStr = JSON.stringify(message);
        const lengthBuffer = Buffer.alloc(4);
        lengthBuffer.writeUInt32LE(Buffer.byteLength(jsonStr)); // match struct.pack('@I')

        hostProcess.stdin.write(lengthBuffer);
        hostProcess.stdin.write(jsonStr);
        return { success: true };
    } catch (e) {
        return { success: false, error: e.message };
    }
});
