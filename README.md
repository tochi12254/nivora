# CyberWatch - eCyber Security Platform

CyberWatch (also referred to as eCyber) is a comprehensive cybersecurity monitoring and threat detection system. It combines a powerful Python-based backend with a modern Electron/React frontend to provide real-time network analysis, intrusion detection/prevention, system monitoring, and a user-friendly interface for managing security posture.

## Table of Contents

- [Features](#features)
  - [Backend Features](#backend-features)
  - [Frontend Features](#frontend-features)
- [Technologies Used](#technologies-used)
  - [Backend](#backend)
  - [Frontend](#frontend)
- [Project Structure](#project-structure)
- [Setup Instructions](#setup-instructions)
  - [Prerequisites](#prerequisites)
  - [Backend Setup](#backend-setup)
  - [Frontend Setup](#frontend-setup)
- [Running the Application](#running-the-application)
  - [Backend](#running-the-backend)
  - [Frontend (Development)](#running-the-frontend-development)
  - [Frontend (Electron App)](#running-the-frontend-electron-app)
- [Building and Packaging](#building-and-packaging)
- [Contribution Guidelines](#contribution-guidelines)

## Features

### Backend Features

- **Real-time Packet Sniffing:** Captures and analyzes network traffic using Scapy.
- **Intrusion Detection/Prevention System (IDS/IPS):** Employs signature-based detection and an Enterprise IPS engine.
- **Threat Intelligence Integration:** Fetches and utilizes threat intelligence feeds.
- **Machine Learning:** Incorporates ML models (TensorFlow, Keras, Scikit-learn) for advanced threat detection (e.g., anomaly detection, malware classification).
- **RESTful API:** Built with FastAPI, providing endpoints for:
    - User authentication and management.
    - Network events, statistics, and real-time streaming.
    - Threat information (CVEs, MITRE, OSINT).
    - System monitoring data.
    - IDS/IPS rule management.
    - Firewall control.
    - DNS and NAC functionalities.
- **Real-time Communication:** Uses Socket.IO for pushing live data and events to the frontend.
- **Database:** Utilizes SQLAlchemy for ORM with a default SQLite database. Configurable for PostgreSQL.
- **System Monitoring:** Tracks system health, processes, and resource usage.
- **Application Blocker:** Provides functionality to block specified applications.
- **Firewall Management:** Interface to manage firewall rules.
- **Security:** Implements JWT for API authentication, CORS policies.

### Frontend Features

- **Interactive Dashboard:** Displays key security metrics and alerts.
- **Threat Visualization:** Shows information on CVEs, MITRE ATT&CK tactics, threat intelligence, and OSINT data.
- **Network Monitoring:** Visualizes network traffic, events, and statistics.
- **Log Viewer:** Allows inspection of system and security logs.
- **ML Model Management:** Interface to view and potentially interact with ML models.
- **User Management:** UI for managing application users.
- **System Status:** Real-time display of system health and monitored parameters.
- **Settings Panel:** Configuration options for the application.
- **Attack Simulation Interface:** Tools to simulate various attack scenarios for testing defenses.
- **Real-time Updates:** Leverages Socket.IO to receive and display live data from the backend.
- **Modern UI:** Built with React, TypeScript, Tailwind CSS, and Shadcn/ui components.
- **Cross-platform:** Packaged as an Electron application for Windows, macOS, and Linux.
- **State Management:** Uses Redux Toolkit for predictable state control.
- **Data Fetching:** Employs Tanstack Query for efficient data fetching and caching.

## Technologies Used

### Backend

- **Programming Language:** Python 3
- **Framework:** FastAPI
- **Networking:** Scapy (packet sniffing/crafting), Socket.IO (real-time communication)
- **Database:** SQLAlchemy (ORM), SQLite (default), PostgreSQL (option)
- **Machine Learning:** TensorFlow, Keras, Scikit-learn
- **API Documentation:** OpenAPI (via FastAPI)
- **Authentication:** JWT (JSON Web Tokens), Passlib (hashing)
- **Server:** Hypercorn (ASGI server)
- **System Interaction:** Psutil
- **Other Key Libraries:** GeoIP2, Pydantic, python-dotenv

### Frontend

- **Framework/Library:** React, Electron
- **Programming Language:** TypeScript
- **Build Tool:** Vite
- **Styling:** Tailwind CSS, Shadcn/ui
- **State Management:** Redux Toolkit
- **Data Fetching:** Tanstack Query (React Query)
- **Routing:** React Router DOM
- **Charting:** Recharts
- **Real-time Communication:** Socket.IO Client
- **Packaging:** Electron Builder

## Project Structure

```
.
├── backend/                  # Python FastAPI backend
│   ├── app/                  # Core application logic (APIs, services, models)
│   ├── api/                  # External/integration APIs (firewall, DNS etc.)
│   ├── ml/                   # Machine learning models and training scripts
│   ├── tests/                # Backend tests
│   ├── main.py               # Main application entry point for backend
│   ├── requirements.txt      # Backend Python dependencies
│   └── ...
├── eCyber/                   # Electron/React frontend
│   ├── electron/             # Electron main process and preload scripts
│   ├── public/               # Static assets
│   ├── src/                  # React application source code
│   │   ├── components/       # UI components
│   │   ├── hooks/            # Custom React hooks
│   │   ├── pages/            # Page components
│   │   ├── App.tsx           # Main React app component
│   │   └── main.tsx          # React app entry point
│   ├── package.json          # Frontend Node.js dependencies and scripts
│   └── ...
├── scripts/                  # Utility scripts (currently sparse)
│   └── setup.sh              # (Currently empty)
├── README.md                 # This file
└── .gitignore
```

## Setup Instructions

### Prerequisites

- Python 3.8+ and pip
- Node.js (latest LTS recommended) and npm
- Git

### Backend Setup

1.  **Clone the repository (if you haven't already):**
    ```bash
    git clone <repository_url>
    cd <repository_name>
    ```

2.  **Navigate to the backend directory:**
    ```bash
    cd backend
    ```

3.  **Create and activate a virtual environment (recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

4.  **Install Python dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

5.  **Database Initialization:**
    The backend is configured to use SQLite by default (`security.db`), which will be created automatically on first run. If you wish to use PostgreSQL, you'll need to:
    *   Install PostgreSQL.
    *   Create a database and user.
    *   Update the `SQLALCHEMY_DATABASE_URL` in `backend/app/core/config.py`.
    *   Install the necessary Python driver (e.g., `psycopg2-binary` or `asyncpg`).

### Frontend Setup

1.  **Navigate to the frontend directory:**
    ```bash
    cd eCyber  # (from the project root)
    ```

2.  **Install Node.js dependencies:**
    ```bash
    npm install
    ```

## Running the Application

### Running the Backend

1.  **Ensure your virtual environment is activated (if used).**
2.  **Navigate to the `backend` directory.**
3.  **Start the FastAPI application using Hypercorn:**
    ```bash
    python main.py
    ```
    Or, for development with Uvicorn (which might be listed in `requirements.txt` or can be installed with `pip install uvicorn`):
    ```bash
    uvicorn main:create_app --factory --host 127.0.0.1 --port 8000 --reload
    ```
    The backend API will typically be available at `http://127.0.0.1:8000`. API documentation (Swagger UI) should be at `http://127.0.0.1:8000/api/docs`.

### Running the Frontend (Development)

1.  **Navigate to the `eCyber` directory.**
2.  **Start the Vite development server:**
    ```bash
    npm run dev
    ```
    This will typically open the web application in your browser at `http://localhost:4000` (as configured in `eCyber/electron/main.mjs` for development).

### Running the Frontend (Electron App)

1.  **Ensure the backend is running.**
2.  **Build the frontend assets (if not done automatically by the Electron script):**
    ```bash
    npm run build # or npm run build:dev for a development build
    ```
3.  **Navigate to the `eCyber` directory.**
4.  **Start the Electron application:**
    ```bash
    npm run electron
    ```

## Building and Packaging

The frontend application can be packaged into distributable Electron applications for Windows, macOS, and Linux.

1.  **Navigate to the `eCyber` directory.**
2.  **Run the packaging script:**
    *   For all platforms:
        ```bash
        npm run package
        ```
    *   For Windows only:
        ```bash
        npm run package:win
        ```
    *   For macOS only:
        ```bash
        npm run package:mac
        ```
    *   For Linux only:
        ```bash
        npm run package:linux
        ```
    The packaged application will be found in the `eCyber/dist_electron` directory (or as configured in `eCyber/package.json`).

## Contribution Guidelines

(This section can be expanded with specific guidelines for contributing to the project.)

1.  **Fork the repository.**
2.  **Create a new branch for your feature or bug fix:**
    ```bash
    git checkout -b feature/your-feature-name
    ```
3.  **Make your changes.**
    *   Follow existing code style and conventions.
    *   Write clear and concise commit messages.
    *   Add/update tests for your changes.
4.  **Ensure all tests pass.**
5.  **Push your changes to your fork:**
    ```bash
    git push origin feature/your-feature-name
    ```
6.  **Create a Pull Request** against the main repository's `main` or `develop` branch.
7.  **Provide a clear description of your changes in the Pull Request.**

**Reporting Issues:**
Please use the GitHub Issues tracker to report bugs or suggest features. Provide as much detail as possible, including steps to reproduce, environment information, and expected vs. actual results.
