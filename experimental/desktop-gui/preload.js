const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('vaultAPI', {
    send: (message) => ipcRenderer.invoke('send-to-host', message),
    onMessage: (callback) => ipcRenderer.on('from-host', (event, value) => callback(value))
});
