import { app, BrowserWindow, Menu, ipcMain } from 'electron'
import path from 'path'
import { fileURLToPath } from 'url'
import { spawn } from 'child_process'

// Enable __dirname in ES modules
const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

let backendProcess = null

function startBackend() {
  const exeName = process.platform === 'win32' ? 'ecyber_backend.exe' : 'ecyber_backend'
  const backendPath = path.join(__dirname, 'backend', exeName)

  backendProcess = spawn(backendPath, [], {
    detached: false,
    cwd: path.dirname(backendPath)
  })

  backendProcess.stdout.on('data', data => {
    console.log(`[BACKEND] ${data.toString().trim()}`)
  })

  backendProcess.stderr.on('data', data => {
    console.error(`[BACKEND ERROR] ${data.toString().trim()}`)
  })

  backendProcess.on('close', code => {
    console.log(`Backend process exited with code ${code}`)
  })
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.mjs')
    },
    icon: path.join(__dirname, '../public/favicon.ico')
  })

  // Load UI from built frontend or dev server
  if (app.isPackaged) {
    win.loadFile(path.join(__dirname, '../dist/index.html'))
  } else {
    win.loadURL('http://localhost:4000')
    win.webContents.openDevTools()
  }

  // Start backend when window is ready
  startBackend()

  // Basic app menu
  const menu = Menu.buildFromTemplate([
    {
      label: app.name,
      submenu: [
        { role: 'about' },
        { type: 'separator' },
        { role: 'quit' }
      ]
    },
    {
      label: 'Edit',
      submenu: [
        { role: 'undo' },
        { role: 'redo' },
        { type: 'separator' },
        { role: 'cut' },
        { role: 'copy' },
        { role: 'paste' },
        { role: 'selectAll' }
      ]
    },
    {
      label: 'View',
      submenu: [
        { role: 'reload' },
        { role: 'forceReload' },
        { role: 'toggleDevTools' },
        { type: 'separator' },
        { role: 'resetZoom' },
        { role: 'zoomIn' },
        { role: 'zoomOut' },
        { type: 'separator' },
        { role: 'togglefullscreen' }
      ]
    }
  ])
  Menu.setApplicationMenu(menu)
}

app.whenReady().then(() => {
  createWindow()

  ipcMain.handle('get-app-version', () => app.getVersion())

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

app.on('window-all-closed', () => {
  // Cleanly stop backend process
  if (backendProcess) backendProcess.kill()

  // On macOS, apps stay active until explicitly quit
  if (process.platform !== 'darwin') app.quit()
})
