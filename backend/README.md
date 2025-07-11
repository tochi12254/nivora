# Backend Documentation - eCyber Security Platform

This document provides detailed information about the backend system of the eCyber Security Platform. For overall project setup and frontend information, please refer to the [main README.md](../README.md).

## Table of Contents

- [Backend Architecture Overview](#backend-architecture-overview)
- [Setup and Configuration](#setup-and-configuration)
- [Running the Backend](#running-the-backend)
- [Running Backend Tests](#running-backend-tests)
- [Project Structure (Backend)](#project-structure-backend)
- [Dependencies](#dependencies)
- [API Endpoints](#api-endpoints)
- [Logging](#logging)
- [Error Handling](#error-handling)

## Backend Architecture Overview

The backend is built using Python and the [FastAPI](https://fastapi.tiangolo.com/) framework, providing a high-performance asynchronous API. Key components include:

-   **FastAPI:** Serves as the core web framework for building RESTful APIs, handling HTTP requests, routing, and data validation (using Pydantic).
-   **SQLAlchemy:** Used as the Object-Relational Mapper (ORM) for database interactions, allowing for flexible connections to databases like SQLite (default for development) and PostgreSQL (recommended for production).
-   **Machine Learning (ML) Integration:** ML models (developed with TensorFlow, Keras, Scikit-learn) are integrated to perform tasks like anomaly detection and malware classification. These models typically reside in the `ml/` directory and are called by specific service modules.
-   **Scapy:** Utilized for network packet sniffing and analysis, forming a core part of the real-time monitoring capabilities.
-   **Socket.IO:** Enables real-time, bidirectional communication with the frontend for streaming live data, alerts, and notifications.
-   **Service Modules:** Business logic is organized into service modules within the `app/services/` directory, handling specific functionalities like user management, threat intelligence, system monitoring, etc.
-   **API Routers:** Endpoints are organized using FastAPI routers, typically found in `app/api/endpoints/`, to keep the codebase modular.

Data flows from network interfaces and system monitors, through processing and ML analysis pipelines, and is then made available via APIs or pushed to the frontend.

## Setup and Configuration

For initial setup, including cloning the repository and setting up Python virtual environments, please follow the instructions in the [Getting Started section of the main README.md](../README.md#getting-started).

### Python Version
The backend is designed to work with **Python 3.8+**.

### Environment Variables and Configuration
Backend configurations are primarily managed within `app/core/config.py`. Key configurations include:

-   **`SQLALCHEMY_DATABASE_URL`**: Defines the connection string for the database. Defaults to SQLite but can be configured for PostgreSQL.
    -   Example for SQLite: `sqlite:///./security.db`
    -   Example for PostgreSQL: `postgresql://user:password@host:port/database`
-   **`SECRET_KEY`**: A secret key used for signing JWT tokens.
-   **`ALGORITHM`**: The algorithm used for JWT token encoding (e.g., `HS256`).
-   **`ACCESS_TOKEN_EXPIRE_MINUTES`**: Expiry time for JWT access tokens.
-   **API Keys/External Service Credentials**: If the application integrates with external threat intelligence feeds or other services requiring API keys, these are typically configured in `config.py` or loaded from environment variables (using a library like `python-dotenv` if a `.env` file approach is adopted).

If a `.env` file is used (check for `python-dotenv` in `requirements.txt` and a `.env.example` file), you would create a `.env` file in the `backend` directory to store sensitive credentials. Example `.env` content:
```env
SQLALCHEMY_DATABASE_URL="postgresql://user:password@host:port/database"
SECRET_KEY="your_very_secret_key"
# Other sensitive variables
```
Ensure the `.env` file is listed in `.gitignore` to prevent committing it.

## Running the Backend

1.  **Navigate to the `backend` directory:**
    ```bash
    cd backend
    ```
2.  **Activate your Python virtual environment:**
    ```bash
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```
3.  **Start the application:**
    There are a couple of ways to run the backend:

    *   **Using the main script (often configured for Hypercorn or another ASGI server directly):**
        ```bash
        python main.py
        ```
    *   **Using Uvicorn for development (with auto-reload):**
        Make sure Uvicorn is installed (`pip install uvicorn`).
        ```bash
        uvicorn main:create_app --factory --host 127.0.0.1 --port 8000 --reload
        ```
        The `--factory` flag assumes `main.py` has a `create_app()` factory function.

The backend API will typically be available at `http://127.0.0.1:8000`.

### API Documentation
Interactive API documentation (Swagger UI) is automatically generated by FastAPI and can be accessed at:
`http://127.0.0.1:8000/api/docs`

An alternative ReDoc interface is usually available at:
`http://127.0.0.1:8000/api/redoc`

## Running Backend Tests

Backend tests are located in the `tests/` directory and are typically run using `pytest`.

1.  **Navigate to the `backend` directory.**
2.  **Ensure your virtual environment is activated.**
3.  **Install test dependencies (if not already included in `requirements.txt`):**
    ```bash
    pip install pytest pytest-cov httpx # httpx is useful for testing async FastAPI endpoints
    ```
4.  **Run tests:**
    ```bash
    pytest
    ```
    Or with coverage:
    ```bash
    pytest --cov=app
    ```

### Test Database
Tests might require a separate test database. Check `tests/conftest.py` or specific test files for how the database session is handled for tests. Often, an in-memory SQLite database or a dedicated test PostgreSQL database is used. Ensure any necessary configuration for the test database is correctly set up (e.g., via environment variables or a test configuration file).

## Project Structure (Backend)

The `backend/` directory is structured as follows:

```
backend/
├── app/                  # Core application logic
│   ├── api/              # API endpoint definitions (routers)
│   │   └── endpoints/    # Specific endpoint modules
│   ├── core/             # Configuration, core settings (e.g., config.py)
│   ├── crud/             # CRUD operations (Create, Read, Update, Delete) for database models
│   ├── db/               # Database session management, base models
│   ├── models/           # SQLAlchemy ORM models
│   ├── schemas/          # Pydantic schemas for data validation and serialization
│   ├── services/         # Business logic and service layer
│   ├── static/           # Static files served by the backend (if any)
│   └── utils/            # Utility functions
├── ml/                   # Machine learning models, training scripts, and related utilities
│   ├── models/           # Saved model files (e.g., .h5, .pkl)
│   ├── notebooks/        # Jupyter notebooks for experimentation and training
│   └── scripts/          # Scripts for training, preprocessing, etc.
├── tests/                # Automated tests for the backend (pytest)
│   ├── api/              # Tests for API endpoints
│   ├── services/         # Tests for service logic
│   └── conftest.py       # Pytest configuration and fixtures
├── .env.example          # Example environment variables file (if used)
├── main.py               # Main application entry point (FastAPI app initialization)
├── requirements.txt      # Python dependencies for the backend
├── requirements-dev.txt  # Python dependencies for development and testing (optional)
└── README.md             # This file
```
(Note: This is a common structure; the actual layout might vary slightly.)

## Dependencies

All Python dependencies are listed in `requirements.txt`. Key libraries include:

-   **FastAPI:** Modern, fast (high-performance) web framework for building APIs.
-   **Uvicorn/Hypercorn:** ASGI server to run the FastAPI application.
-   **SQLAlchemy:** ORM for database interaction.
-   **Pydantic:** Data validation and settings management using Python type annotations.
-   **Scapy:** Powerful interactive packet manipulation program and library.
-   **TensorFlow/Keras/Scikit-learn:** Libraries for machine learning tasks.
-   **python-jose[cryptography]:** For JWT handling (authentication).
-   **Passlib[bcrypt]:** For password hashing.
-   **python-socketio:** For real-time communication.
-   **Psutil:** For system monitoring and process management.
-   **GeoIP2:** For IP geolocation.
-   **python-dotenv:** (If used) For managing environment variables from a `.env` file.

Install dependencies using:
```bash
pip install -r requirements.txt
```
For development dependencies (like `pytest`), if a separate `requirements-dev.txt` exists:
```bash
pip install -r requirements-dev.txt
```

## API Endpoints

The backend provides a comprehensive set of RESTful API endpoints for various functionalities. For a detailed and interactive list of all endpoints, their parameters, and responses, please refer to the auto-generated API documentation:

-   **Swagger UI:** [`http://127.0.0.1:8000/api/docs`](http://127.0.0.1:8000/api/docs)
-   **ReDoc:** [`http://127.0.0.1:8000/api/redoc`](http://127.0.0.1:8000/api/redoc)

Major groups of endpoints typically include:
-   User authentication and management (`/auth`, `/users`)
-   Network monitoring and events (`/network`, `/packets`)
-   IDS/IPS management (`/ids`, `/rules`)
-   Threat intelligence (`/threats`, `/cve`)
-   System monitoring (`/system`)
-   Machine learning model interactions (`/ml`)
-   Firewall and NAC controls (`/firewall`, `/nac`)

## Logging

Logging is crucial for monitoring and troubleshooting the backend application.

-   **Configuration:** Logging is typically configured in `app/core/config.py` or a dedicated logging setup module. This includes log format, log level, and handlers.
-   **Log Output:**
    -   During development with Uvicorn, logs are often outputted to the console.
    -   In a production setup, logs might be written to files (e.g., `backend/logs/main.log` or `backend/logs/error.log`) or sent to a centralized logging system (e.g., ELK stack, Splunk). Check the logging configuration for specific file paths if file-based logging is used.
-   **Log Levels:** Standard Python log levels (DEBUG, INFO, WARNING, ERROR, CRITICAL) are used. The active log level can usually be set in the configuration.

Example (conceptual, actual implementation might vary):
```python
# In app/core/config.py or a logging utility
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("backend/logs/app.log"), # Check if this path is used
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
```
Ensure the `logs` directory exists and has appropriate write permissions if file logging is enabled.

## Error Handling

FastAPI has built-in support for handling errors and returning appropriate HTTP responses.

-   **HTTPExceptions:** Standard way to return HTTP error responses. FastAPI converts these into JSON responses.
    ```python
    from fastapi import HTTPException

    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    ```
-   **Validation Errors:** Pydantic automatically handles request data validation. If validation fails, FastAPI returns a 422 Unprocessable Entity error with details about the validation issues.
-   **Custom Exception Handlers:** For more specific error handling or to customize error responses, FastAPI allows adding custom exception handlers using `@app.exception_handler(CustomException)`. These can be defined in `main.py` or a dedicated error handling module.
-   **Global Exception Handlers:** A global exception handler for unhandled errors might be in place to ensure that users always receive a structured JSON response, even for unexpected server errors (typically returning a 500 Internal Server Error).

Error details, especially in a development environment, are often logged for easier debugging. In production, generic error messages might be shown to the user while detailed errors are logged internally.
```
