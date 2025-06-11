# Frontend Documentation - eCyber Security Platform (eCyber App)

This document provides detailed information about the frontend application (eCyber) of the eCyber Security Platform. For overall project setup and backend information, please refer to the [main README.md](../README.md).

## Table of Contents

- [Frontend Overview](#frontend-overview)
- [Key Features](#key-features)
- [Setup and Configuration](#setup-and-configuration)
- [Running the Frontend (Development)](#running-the-frontend-development)
- [Running the Electron App](#running-the-electron-app)
- [Building and Packaging](#building-and-packaging)
- [Running Frontend Tests](#running-frontend-tests)
- [Project Structure (Frontend)](#project-structure-frontend)
- [Key Dependencies](#key-dependencies)
- [State Management](#state-management)
- [API Interaction](#api-interaction)
- [Styling](#styling)
- [Contribution Notes (Frontend)](#contribution-notes-frontend)

## Frontend Overview

The eCyber frontend is a modern, cross-platform desktop application built using:

-   **Electron:** To package the web application (React) as a desktop application for Windows, macOS, and Linux.
-   **React:** A JavaScript library for building user interfaces, providing a component-based architecture.
-   **TypeScript:** A superset of JavaScript that adds static typing, improving code quality and maintainability.
-   **Vite:** A fast build tool and development server for modern web projects.

Its primary purpose is to provide a user-friendly interface for users to interact with the eCyber backend, visualize security data, manage settings, and monitor system status in real-time.

## Key Features

The frontend offers a range of features to manage and monitor cybersecurity aspects:

-   **Interactive Dashboard:** Displays key security metrics, active alerts, and system summaries.
-   **Threat Visualization:** Tools to view and understand data related to CVEs, MITRE ATT&CK tactics, threat intelligence feeds, and OSINT.
-   **Network Monitoring:** Visualizes real-time network traffic, connection events, and relevant statistics.
-   **Log Viewer:** Allows inspection of system logs, security logs, and application logs streamed from the backend.
-   **ML Model Management Interface:** Provides insights into the status and performance of integrated machine learning models.
-   **User Management:** UI for administering application users and their permissions.
-   **System Status Display:** Real-time updates on system health, resource usage, and monitored parameters.
-   **Settings Panel:** Allows users to configure application preferences and backend connection settings.
-   **Attack Simulation Interface:** (If applicable) Tools to simulate various network attacks for testing the platform's defensive capabilities.
-   **Real-time Updates:** Leverages Socket.IO to receive and display live data and alerts from the backend.

## Setup and Configuration

For initial setup, including cloning the repository and installing Node.js, please follow the instructions in the [Getting Started section of the main README.md](../README.md#getting-started).

### Node.js Version
The frontend is best developed and built using **Node.js (latest LTS version recommended)**, for example, Node.js 18.x or 20.x. Check the `.nvmrc` file if present for a specific version.

### Environment Variables
The frontend might use environment variables for configuration, especially for connecting to the backend API. These are typically managed using `.env` files (e.g., `.env`, `.env.development`, `.env.production`) loaded by Vite.

Common environment variables:
-   **`VITE_API_BASE_URL`**: The base URL for the backend API (e.g., `http://127.0.0.1:8000/api`).
-   **`VITE_SOCKET_URL`**: The URL for the backend Socket.IO server (e.g., `http://127.0.0.1:8000`).

Create a `.env.local` or `.env.development.local` file in the `eCyber/` directory to override default values for your local development. Example:
```env
VITE_API_BASE_URL="http://localhost:8000/api"
VITE_SOCKET_URL="http://localhost:8000"
```
Consult `vite.config.ts` or similar configuration files for how environment variables are loaded and used. Ensure `.env*.local` files are in `.gitignore`.

## Running the Frontend (Development)

This mode runs the React application in a web browser with Vite's development server, providing hot module replacement (HMR) for a fast development experience.

1.  **Navigate to the frontend directory:**
    ```bash
    cd eCyber  # (from the project root)
    ```
2.  **Install dependencies (if not already done):**
    ```bash
    npm install
    ```
3.  **Start the Vite development server:**
    ```bash
    npm run dev
    ```
This will typically open the web application in your browser at `http://localhost:4000` (or the port configured in `vite.config.ts` and `electron/main.mjs`). The backend must be running for the frontend to fetch data.

## Running the Electron App

This mode runs the application as a standalone desktop application.

1.  **Ensure the backend is running.**
2.  **Navigate to the `eCyber` directory.**
3.  **Install dependencies (if not already done):**
    ```bash
    npm install
    ```
4.  **Build the frontend assets (if required by the Electron startup script, often it's handled automatically):**
    ```bash
    npm run build # or npm run build:dev
    ```
5.  **Start the Electron application:**
    ```bash
    npm run electron
    ```
This command typically compiles TypeScript files in the `electron/` directory and then launches the Electron application.

## Building and Packaging

### Building Frontend Assets
To create a production-ready build of the React application (static assets):
1.  **Navigate to the `eCyber` directory.**
2.  **Run the build script:**
    ```bash
    npm run build
    ```
    This will generate optimized static files in the `dist/` or `build/` directory (as configured in `vite.config.ts`).

### Packaging the Electron App
To package the Electron application into distributable installers/executables for different platforms:
1.  **Navigate to the `eCyber` directory.**
2.  **Ensure `npm run build` has been run successfully.**
3.  **Run the packaging script(s) defined in `package.json`:**
    *   For all configured platforms:
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
The packaged application will be found in `eCyber/dist_electron` or the directory specified in the `electron-builder` configuration within `package.json`.

## Running Frontend Tests

Frontend tests are typically run using a test runner like Vitest (which is Vite-native) or Jest, along with React Testing Library for component testing.

1.  **Navigate to the `eCyber` directory.**
2.  **Run the test script defined in `package.json`:**
    ```bash
    npm test
    ```
    Or, if specific scripts are available:
    ```bash
    npm run test:unit  # For unit/component tests
    npm run test:e2e   # For end-to-end tests (if configured)
    ```
Test files are usually co-located with the components they test (e.g., `src/components/MyComponent/MyComponent.test.tsx`) or in `__tests__` subdirectories.

Frameworks used:
-   **Vitest/Jest:** Test runner and assertion library.
-   **React Testing Library:** For testing React components by interacting with them as a user would.
-   **Testing-library/jest-dom:** Custom Jest matchers for testing the state of the DOM.

## Project Structure (Frontend)

The `eCyber/` directory (frontend) is generally structured as follows:

```
eCyber/
├── electron/             # Electron main process, preload scripts, and related config
│   ├── main.mjs          # Electron main process entry point
│   └── preload.mjs       # Electron preload script
├── public/               # Static assets (e.g., index.html, favicons, images)
├── src/                  # React application source code (TypeScript)
│   ├── App.tsx           # Main React application component
│   ├── main.tsx          # React application entry point (renders App.tsx)
│   ├── assets/           # Static assets like images, fonts used by components
│   ├── components/       # Reusable UI components (Shadcn/ui components might be here or imported)
│   │   └── ui/           # Shadcn/ui components (if added via CLI)
│   ├── features/         # Feature-based modules (e.g., dashboard, network, auth)
│   ├── hooks/            # Custom React hooks
│   ├── layouts/          # Layout components (e.g., MainLayout, AuthLayout)
│   ├── lib/              # Utility functions, helper classes (e.g., apiClient.ts)
│   ├── pages/            # Page components (routed components)
│   ├── router/           # Routing configuration (React Router DOM)
│   ├── services/         # API service definitions (using Tanstack Query)
│   ├── store/            # Redux Toolkit store configuration (slices, reducers)
│   └── types/            # TypeScript type definitions and interfaces
├── .env.example          # Example environment variables file
├── index.html            # Main HTML entry point for Vite
├── package.json          # Frontend Node.js dependencies, scripts, and Electron Builder config
├── vite.config.ts        # Vite configuration file
├── tsconfig.json         # TypeScript configuration
└── README.md             # This file
```
(Note: This is a common structure; the actual layout might vary based on project evolution.)

## Key Dependencies

All frontend dependencies are listed in `package.json`. Key libraries and frameworks include:

-   **React:** Core library for building the UI.
-   **ReactDOM:** For rendering React components in the browser/Electron renderer.
-   **Electron:** Framework for building cross-platform desktop apps with web technologies.
-   **Electron Builder:** For packaging and building Electron apps.
-   **Vite:** Build tool and development server.
-   **TypeScript:** Language for static typing.
-   **Redux Toolkit:** For predictable and efficient state management.
-   **React Redux:** Official React bindings for Redux.
-   **Tanstack Query (React Query):** For data fetching, caching, and server state synchronization.
-   **React Router DOM:** For client-side routing.
-   **Socket.IO Client:** For real-time communication with the backend.
-   **Tailwind CSS:** Utility-first CSS framework for styling.
-   **Shadcn/ui:** Collection of re-usable UI components built with Radix UI and Tailwind CSS.
-   **Recharts:** Composable charting library.
-   **Axios (or `fetch` API):** For making HTTP requests to the backend (often wrapped by Tanstack Query).
-   **Vitest/Jest & React Testing Library:** For testing.

Install dependencies using:
```bash
npm install
```

## State Management

The frontend uses **Redux Toolkit** for global state management. Redux Toolkit is the official, opinionated, batteries-included toolset for efficient Redux development.

-   **Slices:** State is organized into "slices" (e.g., `authSlice.ts`, `networkSlice.ts`), each managing a specific piece of the application state. Slices include reducers and action creators.
-   **Store:** A single store (`src/store/store.ts` or similar) combines all slices.
-   **Selectors:** Used to read data from the store in components.
-   **Dispatch:** Used to dispatch actions to update the state.

Redux Toolkit simplifies common Redux patterns, reduces boilerplate, and includes tools like Immer for immutable updates. For server state, caching, and asynchronous data, Tanstack Query is used alongside Redux Toolkit, with Redux primarily handling global UI state and client-side state.

## API Interaction

The frontend interacts with the backend API through two main channels:

1.  **RESTful API Calls:**
    -   Managed primarily by **Tanstack Query (React Query)** for fetching, caching, and updating server state.
    -   Requests are typically made using `axios` or the native `fetch` API, often encapsulated in service functions (e.g., in `src/services/`).
    -   An API client instance might be configured in `src/lib/apiClient.ts` with the base URL and any necessary headers (like auth tokens).
2.  **Socket.IO for Real-time Communication:**
    -   The **Socket.IO client** establishes a persistent connection to the backend Socket.IO server.
    -   Used for receiving real-time updates, notifications, and streaming data (e.g., live network packets, system metrics).
    -   Socket event handlers are typically set up in relevant components or hooks to update the UI or Redux store based on incoming messages.

Authentication tokens (JWTs), once obtained, are usually stored securely (e.g., in `localStorage` or Redux state) and attached to API requests.

## Styling

Styling is primarily handled using:

-   **Tailwind CSS:** A utility-first CSS framework that allows for rapid UI development by composing utility classes directly in the HTML/TSX markup. Configuration is in `tailwind.config.js`.
-   **Shadcn/ui:** A collection of beautifully designed, accessible, and customizable React components built on top of Radix UI and styled with Tailwind CSS. These components are typically added via a CLI and can be customized.
-   **Global Styles/CSS Modules:** Some global styles or CSS Modules might be used for base styling or more complex component-specific styles, located in `src/assets/css` or similar.

## Contribution Notes (Frontend)

When contributing to the frontend, please consider the following:

-   **Code Style:** Follow the existing code style, which likely includes Prettier for code formatting and ESLint for linting (check `package.json` for configurations). Run `npm run lint` and `npm run format` if available.
-   **Component Structure:** Aim to create reusable, well-defined components. For complex components, consider co-locating styles, tests, and stories.
-   **TypeScript:** Utilize TypeScript's features for strong typing to improve code quality and reduce runtime errors. Define clear interfaces and types.
-   **State Management:** Use Redux Toolkit for global UI state and Tanstack Query for server state. Avoid prop-drilling by using selectors and context where appropriate.
-   **Commit Messages:** Write clear and concise commit messages, potentially following a convention like Conventional Commits.
-   **Testing:** Add unit or integration tests for new components and features using Vitest/Jest and React Testing Library.
-   **Shadcn/ui:** When using Shadcn/ui components, prefer to use them as intended and customize them via their props or by modifying their underlying structure if necessary (as they are copied into your codebase).
-   **Accessibility:** Keep accessibility in mind when developing UI components (e.g., proper ARIA attributes, keyboard navigation). Many Shadcn/ui components are built with accessibility in mind.
```
