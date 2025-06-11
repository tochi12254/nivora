// import { app, BrowserWindow } from 'electron';
// import { spawn } from 'child_process';
// import path from 'path';
// import { fileURLToPath } from 'url';
// import { existsSync } from 'fs';

// const isDev = !app.isPackaged;
// const __dirname = path.dirname(fileURLToPath(import.meta.url));

// // Paths relative to your Electron source file (frontend/electron/main.mjs)
// const projectRoot = path.resolve(__dirname, '..', '..'); // Goes up to your main project root
// const frontendDist = path.join(__dirname, '..', 'dist');
// const backendScript = path.join(projectRoot, 'backend', 'main.py');
// const venvPython = path.join(projectRoot, 'backend', 'venv', 'Scripts', 'python.exe'); // Windows path
// const backendExe = path.join(projectRoot, 'backend', 'dist', 'backend_server.exe');

// let mainWindow;
// let backendProcess;

// const createWindow = () => {
//   mainWindow = new BrowserWindow({
//     width: 1280,
//     height: 800,
//     icon: path.join(__dirname, '..', 'public', 'eCyber.ico'),
//        webPreferences: {
//         preload: isDev
//           ? path.join(__dirname, 'electron/preload.mjs')
//           : path.join(__dirname, 'preload.mjs'), // production path
//     },
//   });

//   if (!app.isPackaged) {
//     mainWindow.loadFile(path.join(frontendDist, 'index.html'));
//   } else {
//     mainWindow.loadURL('http://localhost:4000');
//     mainWindow.webContents.openDevTools();
//   }
// };

// const startBackend = () => {
//   if (existsSync(backendExe)) {
//     backendProcess = spawn(backendExe, [], {
//       detached: true,
//       stdio: 'ignore',
//     });
//     backendProcess.unref(); // Allow the app to exit independently
//   } else if (existsSync(venvPython)) {
//     backendProcess = spawn(venvPython, [backendScript]);

//     backendProcess.stdout.on('data', (data) => {
//       console.log(`[Backend]: ${data}`);
//     });

//     backendProcess.stderr.on('data', (data) => {
//       console.error(`[Backend Error]: ${data}`);
//     });
//   } else {
//     console.error('❌ Backend executable or Python interpreter not found.');
//   }
// };

// app.whenReady().then(() => {
//   createWindow();
//   startBackend();

//   app.on('activate', () => {
//     if (BrowserWindow.getAllWindows().length === 0) createWindow();
//   });
// });

// app.on('window-all-closed', () => {
//   if (process.platform !== 'darwin') app.quit();
//   // backendProcess?.kill();  // Don't kill if detached
// });








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
import fs from 'fs'; // Import fs for existsSync

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const isDev = !app.isPackaged; // Define isDev

// const pythonPath = path.join(__dirname, '../../backend/venv/Scripts/python.exe'); // Will be defined in startBackend



let mainWindow;
let backendProcess;

const createWindow = () => {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    icon: path.join(__dirname, '..', 'public', 'eCyber.ico'), // Adjusted path for consistency if public is at eCyber/public
    webPreferences: {
      preload: path.join(__dirname, 'preload.mjs'), 
    },
  });

  if (isDev) {
    mainWindow.loadURL('http://localhost:4000'); // Vite dev server URL
    mainWindow.webContents.openDevTools();
  } else {
    // 'dist' is relative to the project root (eCyber).
    // In packaged app, main.mjs is in 'resources/app.asar/electron/', index.html is in 'resources/app.asar/dist/'
    mainWindow.loadFile(path.join(__dirname, '..', 'dist', 'index.html'));
  }
};

const startBackend = () => {
  const backendExeName = process.platform === 'win32' ? 'backend_server.exe' : 'backend_server';

  // Path for packaged app (production)
  const prodBackendPath = path.join(process.resourcesPath, 'backend', backendExeName);

  // Paths for development
  const devBackendScript = path.join(__dirname, '..', '..', 'backend', 'main.py');
  const devPythonInterpreter = path.join(__dirname, '..', '..', 'backend', 'venv', 'Scripts', 'python.exe'); // Windows specific

  if (!isDev) {
    if (fs.existsSync(prodBackendPath)) {
      console.log(`[ElectronMain] Starting packaged backend: ${prodBackendPath}`);
      backendProcess = spawn(prodBackendPath, [], { detached: false });
    } else {
      console.error(`[ElectronMain] Packaged backend not found at: ${prodBackendPath}`);
      // Optionally: dialog.showErrorBox('Backend Error', `Packaged backend not found: ${prodBackendPath}`);
      return;
    }
  } else { // isDev
    if (fs.existsSync(devPythonInterpreter) && fs.existsSync(devBackendScript)) {
      console.log(`[ElectronMain] Starting backend script with: ${devPythonInterpreter} ${devBackendScript}`);
      backendProcess = spawn(devPythonInterpreter, [devBackendScript]);
    } else {
      console.error('[ElectronMain] Development backend script or Python interpreter not found.');
      if (!fs.existsSync(devPythonInterpreter)) console.error(`[ElectronMain] Dev Interpreter not found: ${devPythonInterpreter}`);
      if (!fs.existsSync(devBackendScript)) console.error(`[ElectronMain] Dev Script not found: ${devBackendScript}`);
      // Optionally: dialog.showErrorBox('Backend Error', 'Development backend script or Python interpreter not found.');
      return;
    }
  }

  if (backendProcess) {
    backendProcess.stdout.on('data', (data) => {
      // Added trim() to remove extra newlines often present in stdout
      console.log(`[Backend]: ${data.toString().trim()}`);
    });

    backendProcess.stderr.on('data', (data) => {
      console.error(`[Backend Error]: ${data.toString().trim()}`);
    });

    backendProcess.on('close', (code) => {
      console.log(`[ElectronMain] Backend process exited with code ${code}`);
      backendProcess = null; 
      // Optionally, attempt to restart or notify the user
      // For example, if (!isDev && code !== 0) { dialog.showErrorBox('Backend Error', `Backend process exited unexpectedly with code ${code}. Please restart the application.`); }
    });

    backendProcess.on('error', (err) => {
      console.error(`[ElectronMain] Failed to start backend process: ${err.message}`);
      backendProcess = null;
      // Optionally: dialog.showErrorBox('Backend Error', `Failed to start backend process: ${err.message}`);
    });
  }
};

app.whenReady().then(() => {
  createWindow();
  startBackend();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
  backendProcess?.kill();
});