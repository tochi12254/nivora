# eCyber Security Platform

eCyber is a comprehensive cybersecurity monitoring and threat detection system. It combines a powerful Python-based backend with a modern Electron/React frontend to provide real-time network analysis, intrusion detection/prevention, system monitoring, and a user-friendly interface for managing security posture.

## Project Overview

eCyber aims to provide a robust, all-in-one security solution for individuals and small to medium-sized enterprises. The core goal is to democratize access to advanced cybersecurity tools by offering an open-source platform that is both powerful and relatively easy to use. 

Key objectives include:
- **Proactive Threat Detection:** Utilizing real-time analysis and machine learning to identify threats before they cause significant damage.
- **Comprehensive Monitoring:** Offering a unified view of network activity, system health, and potential vulnerabilities.
- **User Empowerment:** Providing users with the tools and information needed to understand and manage their security posture effectively.
- **Extensibility:** Building a modular system that can be expanded with new features and integrations.
- **Educational Value:** Serving as a platform for learning about cybersecurity concepts and practices.

## Table of Contents

- [Project Overview](#project-overview)
- [Features](#features)
  - [Backend Features](#backend-features)
  - [Frontend Features](#frontend-features)
  - [Machine Learning Capabilities](#machine-learning-capabilities)
- [Architecture Overview](#architecture-overview)
- [Technologies Used](#technologies-used)
  - [Backend](#backend)
  - [Frontend](#frontend)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [1. Clone the Repository](#1-clone-the-repository)
  - [2. Backend Setup](#2-backend-setup)
  - [3. Frontend Setup](#3-frontend-setup)
  - [4. Running the Backend](#4-running-the-backend)
  - [5. Running the Frontend](#5-running-the-frontend)
- [Running Tests](#running-tests)
  - [Backend Tests](#backend-tests)
  - [Frontend Tests](#frontend-tests)
- [Building and Packaging](#building-and-packaging)
- [Deployment Considerations](#deployment-considerations)
- [Troubleshooting](#troubleshooting)
- [Contribution Guidelines](#contribution-guidelines)
- [License](#license)
- [Badges](#badges)
- [Contact/Community](#contactcommunity)

## Features

### Backend Features

- **Real-time Packet Sniffing:** Captures and analyzes network traffic using Scapy.
- **Intrusion Detection/Prevention System (IDS/IPS):** Employs signature-based detection and an Enterprise IPS engine.
- **Threat Intelligence Integration:** Fetches and utilizes threat intelligence feeds.
- **Machine Learning:** See [Machine Learning Capabilities](#machine-learning-capabilities) for details.
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

### Machine Learning Capabilities

eCyber leverages machine learning for advanced threat detection and analysis. Our ML capabilities include:

-   **Anomaly Detection:**
    -   **Models:** Autoencoders (using Keras/TensorFlow), Isolation Forest, One-Class SVM (using Scikit-learn).
    -   **Role:** Identifies unusual patterns in network traffic or system behavior that may indicate novel attacks or compromised systems. For example, detecting deviations from baseline network flow characteristics or unusual sequences of system calls.
-   **Malware Classification:**
    -   **Models:** Convolutional Neural Networks (CNNs) for analyzing PE file structures or network payloads, Gradient Boosting classifiers (e.g., XGBoost, LightGBM) using extracted features.
    -   **Role:** Classifies files or network streams as benign or malicious, and potentially categorizes malware into families (e.g., ransomware, trojan, spyware). This often involves feature extraction from static file properties or dynamic analysis logs.
-   **Threat Behavior Analysis:**
    -   **Models:** Recurrent Neural Networks (RNNs) like LSTMs or GRUs for sequential data (e.g., log analysis, command sequences), Hidden Markov Models (HMMs).
    -   **Role:** Models sequences of actions to detect malicious behaviors that unfold over time, such as identifying attack patterns consistent with MITRE ATT&CK framework tactics.
-   **Data Preprocessing and Feature Engineering:** Utilizes libraries like Pandas and NumPy for cleaning data, transforming it into suitable formats for ML models, and engineering relevant features from raw security data.
-   **Model Training and Evaluation:** Includes scripts and notebooks (typically within `backend/ml/`) for training models, evaluating their performance using appropriate metrics (e.g., precision, recall, F1-score, ROC AUC), and fine-tuning hyperparameters.

The ML models are integrated into the backend pipeline, processing data collected by various sensors and providing insights that enhance the platform's detection capabilities.

## Architecture Overview

eCyber employs a client-server architecture:

-   **Backend (Server-Side):**
    -   Developed in Python using the FastAPI framework.
    -   Handles core logic: packet sniffing, IDS/IPS, data processing, machine learning inference, API services, and database interactions.
    -   Communicates with the frontend via RESTful APIs (for request-response interactions) and Socket.IO (for real-time updates).
    -   Can be deployed independently and scaled as needed.
-   **Frontend (Client-Side):**
    -   An Electron application built with React, TypeScript, and Vite.
    -   Provides the user interface for interacting with the system, visualizing data, and configuring settings.
    -   Communicates with the backend to fetch data and send commands.
-   **Database:**
    -   Uses SQLAlchemy as an ORM, allowing flexibility with database systems. SQLite is the default for ease of setup, with PostgreSQL recommended for production.
    -   Stores configuration data, user information, logs, and processed security events.
-   **Data Flow (Simplified):**
    1.  Network traffic and system events are captured/monitored by backend services.
    2.  Data is processed, analyzed by the IDS/IPS engine, and fed into ML models for further scrutiny.
    3.  Alerts and processed data are stored in the database and/or pushed to the frontend in real-time via Socket.IO.
    4.  The frontend displays this information, and users can interact with the system through API calls to the backend.

A more detailed diagram or further architectural documentation may be found in the `/docs` directory (if available) or within specific module READMEs.

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

## Getting Started

This guide will walk you through setting up and running the eCyber platform on your local machine.

### Prerequisites

-   Python 3.8+ and pip
-   Node.js (latest LTS recommended) and npm
-   Git

### 1. Clone the Repository

If you haven't already, clone the repository to your local machine:
```bash
git clone <repository_url> # Replace <repository_url> with the project's Git URL
cd <repository_directory_name> # Navigate to the cloned directory
```
If you are reading this README from within the cloned repository, you can skip this step.

### 2. Backend Setup

1.  **Navigate to the backend directory:**
    ```bash
    cd backend
    ```
2.  **Create and activate a virtual environment (recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```
3.  **Install Python dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
4.  **Database Initialization:**
    The backend uses SQLite by default (`security.db`), which is created automatically. For PostgreSQL (recommended for production):
    *   Install PostgreSQL.
    *   Create a database and user.
    *   Update `SQLALCHEMY_DATABASE_URL` in `backend/app/core/config.py`.
    *   Install the driver: `pip install psycopg2-binary asyncpg` (as needed).

### 3. Frontend Setup

1.  **Navigate to the frontend directory (from the project root):**
    ```bash
    cd eCyber
    ```
2.  **Install Node.js dependencies:**
    ```bash
    npm install
    ```

### 4. Running the Backend

1.  Ensure your backend virtual environment is activated.
2.  Navigate to the `backend` directory.
3.  Start the FastAPI application:
    ```bash
    python main.py
    ```
    Or for development with auto-reload (install Uvicorn: `pip install uvicorn`):
    ```bash
    uvicorn main:create_app --factory --host 127.0.0.1 --port 8000 --reload
    ```
    The backend API will be at `http://127.0.0.1:8000`. Docs at `http://127.0.0.1:8000/api/docs`.

### 5. Running the Frontend

You have two options for running the frontend:

**Option A: In a Web Browser (Development Mode)**

1.  Navigate to the `eCyber` directory.
2.  Start the Vite development server:
    ```bash
    npm run dev
    ```
    This usually opens the app at `http://localhost:4000`.

**Option B: As an Electron Desktop Application**

1.  Ensure the backend is running.
2.  Build frontend assets (if not done by the Electron script):
    ```bash
    npm run build # or npm run build:dev
    ```
3.  Navigate to the `eCyber` directory.
4.  Start the Electron application:
    ```bash
    npm run electron
    ```

## Running Tests

### Backend Tests

Backend tests are typically located in the `backend/tests/` directory and are run using `pytest`.

1.  **Navigate to the `backend` directory.**
2.  **Ensure your virtual environment is activated and test dependencies are installed.**
    You might need to install `pytest` and any plugins specified (e.g., in a `requirements-dev.txt` or `test-requirements.txt`):
    ```bash
    pip install pytest httpx # httpx for testing FastAPI async clients
    ```
3.  **Run tests:**
    ```bash
    pytest
    ```
    Refer to `backend/tests/README.md` or specific test files for more detailed instructions if available.

### Frontend Tests

Frontend tests are typically located within the `eCyber/src/` directory (e.g., `__tests__` subfolders or `*.test.tsx` files). The project is set up to use Vitest (common with Vite) or Jest, along with React Testing Library.

1.  **Navigate to the `eCyber` directory.**
2.  **Run tests using the npm script (defined in `eCyber/package.json`):**
    ```bash
    npm test
    ```
    This command will execute the configured test runner (Vitest or Jest). Check the `scripts` section in `eCyber/package.json` for the exact command or for more specific test scripts (e.g., unit, e2e).

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

## Deployment Considerations

When deploying eCyber to a production environment, consider the following:

-   **Database:**
    -   Use a robust database like PostgreSQL instead of SQLite.
    -   Configure regular backups and replication if high availability is needed.
-   **Backend Deployment:**
    -   Run the FastAPI backend using a production-grade ASGI server like Uvicorn with Gunicorn workers behind a reverse proxy (e.g., Nginx or Traefik).
    -   Manage backend processes using a process manager like `systemd` or Supervisor.
    -   Secure API endpoints with HTTPS.
    -   Set `DEBUG` mode to `False` in the backend configuration.
    -   Manage secrets and configurations securely (e.g., using environment variables, Vault, or cloud provider secret managers).
-   **Frontend Deployment:**
    -   The Electron application is typically packaged and distributed to end-users.
    -   If offering a web-only version, serve the static build artifacts (from `npm run build`) through a web server like Nginx.
-   **Scalability:**
    -   The backend can be scaled horizontally by running multiple instances behind a load balancer.
    -   Consider using a distributed task queue (e.g., Celery) for long-running or resource-intensive tasks.
-   **Security Hardening:**
    -   Regularly update dependencies for both backend and frontend.
    -   Implement comprehensive logging and monitoring for the production system.
    -   Configure firewalls and network security groups appropriately.
    -   Perform security audits and penetration testing.
-   **Resource Allocation:** Ensure sufficient CPU, memory, and network bandwidth for the backend services, especially the packet sniffing and ML components.

## Troubleshooting

-   **`ModuleNotFoundError` (Backend):**
    -   Ensure your Python virtual environment is activated (`source venv/bin/activate` or `venv\Scripts\activate`).
    -   Verify all dependencies in `backend/requirements.txt` are installed (`pip install -r backend/requirements.txt`).
-   **Frontend Fails to Connect to Backend:**
    -   Confirm the backend is running and accessible at the configured URL (usually `http://127.0.0.1:8000`).
    -   Check browser developer console (for web version) or Electron logs for network errors.
    -   Verify CORS settings on the backend if accessing from a different domain/port in development.
-   **`npm install` Fails (Frontend):**
    -   Ensure Node.js and npm are correctly installed and up to date.
    -   Try deleting `eCyber/node_modules` and `eCyber/package-lock.json` (or `yarn.lock`) and running `npm install` again.
    -   Check for network issues or proxy configurations that might be blocking downloads.
-   **Packet Sniffing Issues:**
    -   Running the backend might require `sudo` or administrator privileges for packet sniffing capabilities (e.g., `sudo python main.py`). Be cautious when granting elevated permissions.
    -   Ensure the network interface specified for sniffing is correct.
-   **ML Model Errors:**
    -   Ensure model files are correctly placed and accessible by the backend.
    -   Verify that the versions of ML libraries (TensorFlow, Keras, Scikit-learn) are compatible with the model files.

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

## License

This project is licensed under the MIT License. See the `LICENSE` file (if present) for more details, or refer to the standard MIT License text below:

```
MIT License

Copyright (c) [Year] [Your Name/Organization]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
(If a `LICENSE` file exists in the repository, it takes precedence. Otherwise, you might want to create one with the MIT License text, replacing `[Year]` and `[Your Name/Organization]`.)

## Badges

Add relevant badges here once the project is set up with CI/CD, code coverage, etc.
Examples:

[![Build Status](https://img.shields.io/travis/com/yourusername/ecyber.svg?style=flat-square)](https://travis-ci.com/yourusername/ecyber)
[![Coverage Status](https://img.shields.io/coveralls/github/yourusername/ecyber/main.svg?style=flat-square)](https://coveralls.io/github/yourusername/ecyber?branch=main)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![npm version](https://img.shields.io/npm/v/ecyber-frontend-package.svg?style=flat-square)](https://www.npmjs.com/package/ecyber-frontend-package) // If applicable
[![PyPI version](https://img.shields.io/pypi/v/ecyber-backend-package.svg?style=flat-square)](https://pypi.org/project/ecyber-backend-package/) // If applicable

## Contact/Community

-   **Project Lead:** [Your Name/Email or GitHub Profile]
-   **Issue Tracker:** [Link to GitHub Issues for the project]
-   **Discussion Forum/Mailing List:** (If applicable, e.g., GitHub Discussions, Google Group)
-   **Community Chat:** (If applicable, e.g., Slack, Discord server)

We welcome contributions and feedback from the community!
