import { contextBridge, ipcRenderer } from 'electron'
// Use require

// Expose protected methods that allow the renderer process to use
// the ipcRenderer without exposing the entire object
contextBridge.exposeInMainWorld('electronAPI', {
  // Example: If you need to send messages from renderer to main
  // send: (channel, data) => {
  //   // Whitelist channels
  //   let validChannels = ['toMain'];
  //   if (validChannels.includes(channel)) {
  //     ipcRenderer.send(channel, data);
  //   }
  // },
  // Example: If you need to receive messages from main to renderer
  // receive: (channel, func) => {
  //   let validChannels = ['fromMain'];
  //   if (validChannels.includes(channel)) {
  //     // Deliberately strip event as it includes `sender`
  //     ipcRenderer.on(channel, (event, ...args) => func(...args));
  //   }
  // }
  getAppVersion: () => ipcRenderer.invoke('get-app-version') // Example for invoking a handler
});

console.log('Preload script loaded.');

// You can also expose basic Electron information if needed by the AI assistant
// For example, to let it know it's running in Electron.
contextBridge.exposeInMainWorld('isElectron', true);
