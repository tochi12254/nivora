// import { app, BrowserWindow, Menu } from 'electron'
// import path from 'path'
// import { fileURLToPath } from 'url'
// import { spawn } from 'child_process'
// import fs from 'fs'

// const isDev = !app.isPackaged

// // Enable __dirname in ES modules
// const __filename = fileURLToPath(import.meta.url)
// const __dirname = path.dirname(__filename)

// let backendProcess = null

// function startBackend() {
//   const exeName = process.platform === 'win32' ? 'ecyber_backend.exe' : 'ecyber_backend'

//   const backendPath = isDev
//     ? path.join(__dirname, 'backend', '_internal', exeName)
//     : path.join(process.resourcesPath, 'backend', exeName)

//   console.log(`[MAIN] Trying to start backend from: ${backendPath}`)

//   if (!fs.existsSync(backendPath)) {
//     console.error(`[ERROR] Backend executable not found at: ${backendPath}`)
//     return
//   }

//   backendProcess = spawn(backendPath, [], {
//     detached: false,
//     cwd: path.dirname(backendPath),
//     stdio: 'pipe'
//   })

//   backendProcess.stdout.on('data', data => {
//     console.log(`[BACKEND] ${data.toString().trim()}`)
//   })

//   backendProcess.stderr.on('data', data => {
//     console.error(`[BACKEND ERROR] ${data.toString().trim()}`)
//   })

//   backendProcess.on('close', code => {
//     console.log(`[MAIN] Backend process exited with code ${code}`)
//   })
// }

// function createWindow() {
//   const win = new BrowserWindow({
//     width: 1200,
//     height: 800,
//     webPreferences: {
//       nodeIntegration: false,
//       contextIsolation: true,
//       devTools: isDev,
//       preload: path.join(__dirname, 'preload.mjs')
//     },
//     icon: path.join(__dirname, '../public/favicon.ico')
//   })

//   // Load UI from built frontend or dev server
//   if (app.isPackaged) {
//     win.loadFile(path.join(__dirname, '../dist/index.html'))
//   } else {
//     win.loadURL('http://localhost:4000')
//     win.webContents.openDevTools()
//   }

//   startBackend()

//   const menu = Menu.buildFromTemplate([
//     {
//       label: app.name,
//       submenu: [
//         { role: 'about' },
//         { type: 'separator' },
//         { role: 'quit' }
//       ]
//     },
//     {
//       label: 'Edit',
//       submenu: [
//         { role: 'undo' },
//         { role: 'redo' },
//         { type: 'separator' },
//         { role: 'cut' },
//         { role: 'copy' },
//         { role: 'paste' },
//         { role: 'selectAll' }
//       ]
//     },
//     {
//       label: 'View',
//       submenu: [
//         { role: 'reload' },
//         { role: 'forceReload' },
//         { role: 'toggleDevTools' },
//         { type: 'separator' },
//         { role: 'resetZoom' },
//         { role: 'zoomIn' },
//         { role: 'zoomOut' },
//         { type: 'separator' },
//         { role: 'togglefullscreen' }
//       ]
//     }
//   ])
//   Menu.setApplicationMenu(menu)
// }

// app.whenReady().then(() => {
//   createWindow()

//   app.on('activate', () => {
//     if (BrowserWindow.getAllWindows().length === 0) createWindow()
//   })
// })

// app.on('window-all-closed', () => {
//   if (backendProcess) backendProcess.kill()
//   if (process.platform !== 'darwin') app.quit()
// })
// app.on('quit', () => {
//   if (backendProcess) {
//     backendProcess.kill()
//     console.log('[MAIN] Backend process killed on app quit.')
//   }
// })


import { app, BrowserWindow } from 'electron';
import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const pythonPath = path.join(__dirname, '../../backend/venv/Scripts/python.exe');



let mainWindow;
let backendProcess;

const createWindow = () => {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    icon: path.join(__dirname, '../public/eCyber.ico'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
    },
  });

  if(app.isPackaged) {
    mainWindow.loadFile(path.join(__dirname, '../dist/index.html'));
  }
  else {
    mainWindow.loadURL('http://localhost:4000');
    mainWindow.webContents.openDevTools();
  }
};

const startBackend = () => {
  const script = path.join(__dirname, '../../backend/main.py');
  backendProcess = spawn(pythonPath, [script]);

  backendProcess.stdout.on('data', (data) => {
    console.log(`[FastAPI]: ${data}`);
  });

  backendProcess.stderr.on('data', (data) => {
    console.error(`[FastAPI error]: ${data}`);
  });
};

app.whenReady().then(() => {
  createWindow();
  // startBackend();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
  backendProcess?.kill();
});
