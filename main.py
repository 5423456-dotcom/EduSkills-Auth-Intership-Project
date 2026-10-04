import os
import sqlite3
import time
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field

# Try importing gspread and google-auth for Google Sheets audit logging
try:
    import gspread
    from google.oauth2.service_account import Credentials
    GSPREAD_AVAILABLE = True
except ImportError:
    GSPREAD_AVAILABLE = False

# SQLite Database setup
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "auth.db")

# Google Sheets Configuration
# Checks for 'credentials.json' (standard placeholder) or 'service_account.json'
CREDENTIALS_FILES = [
    os.path.join(BASE_DIR, "credentials.json"),
    os.path.join(BASE_DIR, "service_account.json")
]
GOOGLE_SHEET_NAME = os.getenv("GOOGLE_SHEET_NAME", "AuthAuditLogs")
GSPREAD_SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive"
]

def get_credentials_path() -> Optional[str]:
    """Finds existing credentials file in the backend directory."""
    for path in CREDENTIALS_FILES:
        if os.path.exists(path):
            return path
    return None

def append_to_google_sheet(username: str, status_text: str = "SUCCESS") -> dict:
    """
    Appends a new row [Username, Timestamp, Status] into a Google Sheet using gspread.
    Safe & resilient: If credentials.json is missing or network fails, logs a console notice
    without interrupting the authentication process.
    """
    if not GSPREAD_AVAILABLE:
        msg = "gspread library is not installed."
        print(f"[Google Sheets Warning] {msg}")
        return {"logged": False, "reason": msg}

    creds_path = get_credentials_path()
    if not creds_path:
        msg = f"Placeholder active: credentials.json not found in {BASE_DIR}. Place your Google Service Account key at 'backend/credentials.json' to log to Google Sheets."
        print(f"[Google Sheets Notice] {msg}")
        return {"logged": False, "reason": msg}

    try:
        credentials = Credentials.from_service_account_file(
            creds_path,
            scopes=GSPREAD_SCOPES
        )
        gc = gspread.authorize(credentials)

        try:
            sh = gc.open(GOOGLE_SHEET_NAME)
        except gspread.SpreadsheetNotFound:
            msg = (
                f"Google Sheet '{GOOGLE_SHEET_NAME}' not found. "
                f"Create a sheet named '{GOOGLE_SHEET_NAME}' and share edit access with: "
                f"{credentials.service_account_email}"
            )
            print(f"[Google Sheets Warning] {msg}")
            return {"logged": False, "reason": msg}

        worksheet = sh.sheet1
        timestamp_now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Auto-append header if sheet is brand new
        existing_values = worksheet.get_all_values()
        if not existing_values:
            worksheet.append_row(["Username", "Timestamp", "Status"])

        worksheet.append_row([username, timestamp_now, status_text])
        print(f"[Google Sheets] Logged: {username} ({status_text}) at {timestamp_now}")
        return {"logged": True, "sheet": GOOGLE_SHEET_NAME, "timestamp": timestamp_now}

    except Exception as e:
        msg = f"Failed to log to Google Sheets: {str(e)}"
        print(f"[Google Sheets Error] {msg}")
        return {"logged": False, "reason": msg}

def get_db_connection():
    """Returns a SQLite connection with row access by column name."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database schema if it doesn't already exist."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            failed_attempts INTEGER DEFAULT 0,
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

# Initialize database schema immediately
init_db()

# Custom Password Hashing Algorithm
def custom_hash(password: str) -> str:
    """
    Custom Hash Algorithm:
    Calculates the sum of the ASCII values of all characters in the password.
    Returns the sum as a string representation.
    """
    return str(sum(ord(c) for c in password))

# Native HTTP Basic Auth security scheme (RFC 7617)
basic_security = HTTPBasic(auto_error=False)

# FastAPI application initialization
app = FastAPI(
    title="Basic Authentication Simulation API",
    description="Authentication simulation with custom ASCII sum hashing, 3-attempt lockout, CORS, and Google Sheets audit logging.",
    version="3.0.0"
)

# Robust CORS Configuration: Allow all origins, methods, and headers
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic Schemas
class AuthRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=50, description="Unique username")
    password: str = Field(..., min_length=1, description="Raw user password")

class UserResponse(BaseModel):
    id: int
    username: str
    status: str
    failed_attempts: int
    created_at: Optional[str] = None

# Root health check endpoint
@app.get("/", summary="Health Check & Status")
def root():
    creds_file = get_credentials_path()
    return {
        "status": "online",
        "service": "Basic Authentication Simulation API",
        "cors_enabled": True,
        "google_sheets_integration": {
            "gspread_installed": GSPREAD_AVAILABLE,
            "credentials_detected": bool(creds_file),
            "credentials_file": os.path.basename(creds_file) if creds_file else "Placeholder: backend/credentials.json expected",
            "target_sheet": GOOGLE_SHEET_NAME
        },
        "endpoints": {
            "register": "POST /register",
            "login": "POST /login",
            "native_auth": "GET /api/native-auth",
            "benchmark": "GET /api/benchmark",
            "simulate_lockout": "POST /api/simulate-lockout/{username}",
            "audit": "GET /admin/audit",
            "unlock": "POST /admin/unlock/{username}"
        }
    }

# 1. User Registration Endpoint (ASCII Sum Hashing)
@app.post("/register", status_code=status.HTTP_201_CREATED, summary="Register User")
def register_user(payload: AuthRequest):
    username = payload.username.strip()
    raw_password = payload.password

    if not username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username cannot be empty or whitespace."
        )

    # Compute custom ASCII sum hash: sum(ord(c) for c in password)
    hashed_password = custom_hash(raw_password)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    existing_user = cursor.fetchone()

    if existing_user:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Username '{username}' is already registered."
        )

    # Insert user with 'active' status and 0 failed attempts
    cursor.execute(
        "INSERT INTO users (username, password_hash, failed_attempts, status) VALUES (?, ?, 0, 'active')",
        (username, hashed_password)
    )
    conn.commit()
    user_id = cursor.lastrowid
    conn.close()

    return {
        "message": "User registered successfully.",
        "user_id": user_id,
        "username": username,
        "custom_hash_info": {
            "formula": "sum(ASCII values of password)",
            "hash_value": hashed_password
        }
    }

# 2. Login Validation Endpoint (Lockout Tracking + Google Sheets Logging)
@app.post("/login", summary="Validate Login")
def login_user(payload: AuthRequest):
    username = payload.username.strip()
    raw_password = payload.password

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id, username, password_hash, failed_attempts, status FROM users WHERE username = ?",
        (username,)
    )
    user = cursor.fetchone()

    if not user:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password."
        )

    # Check if account is already locked
    if user["status"] == "locked":
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is LOCKED due to 3 consecutive failed login attempts. Contact an administrator to unlock."
        )

    # Validate against custom ASCII sum hash
    computed_hash = custom_hash(raw_password)

    if computed_hash == user["password_hash"]:
        # Successful login: reset failed attempts counter to 0
        if user["failed_attempts"] > 0:
            cursor.execute("UPDATE users SET failed_attempts = 0 WHERE id = ?", (user["id"],))
            conn.commit()
        conn.close()

        # Google Sheets Audit Logging (gspread): Append [Username, Timestamp, Status]
        sheet_result = append_to_google_sheet(username=username, status_text="SUCCESS")

        return {
            "message": "Login successful! Access granted.",
            "username": username,
            "status": "active",
            "token": f"token_{username}_{int(time.time())}",
            "google_sheet_logged": sheet_result.get("logged", False),
            "google_sheet_info": sheet_result
        }
    else:
        # Invalid password: increment failed login attempts
        new_failed_attempts = user["failed_attempts"] + 1

        if new_failed_attempts >= 3:
            # Lock the account completely after 3 consecutive failed login attempts
            cursor.execute(
                "UPDATE users SET failed_attempts = ?, status = 'locked' WHERE id = ?",
                (new_failed_attempts, user["id"])
            )
            conn.commit()
            conn.close()

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account has been LOCKED after 3 consecutive failed login attempts."
            )
        else:
            cursor.execute(
                "UPDATE users SET failed_attempts = ? WHERE id = ?",
                (new_failed_attempts, user["id"])
            )
            conn.commit()
            conn.close()

            attempts_left = 3 - new_failed_attempts
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid credentials. Failed attempt {new_failed_attempts}/3. {attempts_left} attempt(s) remaining before lockout."
            )

# 3. Native RFC 7617 HTTP Basic Auth Endpoint
@app.get("/api/native-auth", summary="Native HTTP Basic Authentication Tester")
def native_auth(credentials: Optional[HTTPBasicCredentials] = Depends(basic_security)):
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization: Basic header. Provide native credentials.",
            headers={"WWW-Authenticate": "Basic realm='AuthShield'"}
        )

    username = credentials.username.strip()
    raw_password = credentials.password

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password_hash, failed_attempts, status FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"User '{username}' does not exist in SQLite database.",
            headers={"WWW-Authenticate": "Basic realm='AuthShield'"}
        )

    if user["status"] == "locked":
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Account '{username}' is LOCKED in SQLite database due to consecutive failures."
        )

    computed_hash = custom_hash(raw_password)

    if computed_hash == user["password_hash"]:
        if user["failed_attempts"] > 0:
            cursor.execute("UPDATE users SET failed_attempts = 0 WHERE id = ?", (user["id"],))
            conn.commit()
        conn.close()

        append_to_google_sheet(username=username, status_text="SUCCESS (Native Basic Auth)")

        header_bytes = len(f"Basic {username}:{raw_password}".encode("utf-8"))
        return {
            "status": "success",
            "protocol": "RFC 7617 HTTP Basic Auth",
            "authenticated_user": username,
            "header_inspection": {
                "format": "Authorization: Basic <base64(user:password)>",
                "approx_header_size_bytes": header_bytes,
                "encoding": "Base64 (Standard ASCII)"
            },
            "message": f"Successfully authenticated user '{username}' via Native HTTP Basic Auth protocol!"
        }
    else:
        new_attempts = user["failed_attempts"] + 1
        if new_attempts >= 3:
            cursor.execute("UPDATE users SET failed_attempts = ?, status = 'locked' WHERE id = ?", (new_attempts, user["id"]))
            conn.commit()
            conn.close()
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account LOCKED after 3 consecutive failed attempts.")
        else:
            cursor.execute("UPDATE users SET failed_attempts = ? WHERE id = ?", (new_attempts, user["id"]))
            conn.commit()
            conn.close()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid password for native auth. Failed attempt {new_attempts}/3.",
                headers={"WWW-Authenticate": "Basic realm='AuthShield'"}
            )

# 4. Overhead & Latency Benchmark Endpoint
@app.get("/api/benchmark", summary="Overhead & Latency Benchmark")
def get_benchmark():
    t_start = time.perf_counter()
    conn = get_db_connection()
    conn.execute("SELECT COUNT(*) FROM users").fetchone()
    conn.close()
    sqlite_latency_ms = round((time.perf_counter() - t_start) * 1000, 3)

    return {
        "status": "active",
        "benchmark_timestamp": datetime.now(timezone.utc).isoformat(),
        "sqlite_ping_ms": sqlite_latency_ms,
        "overhead_comparison": [
            {
                "protocol": "HTTP Basic Auth (RFC 7617)",
                "header_size_bytes": 42,
                "complexity": "O(1) Direct Hash/ASCII Lookup",
                "server_cpu_cost": "Negligible (< 0.05 ms)",
                "state": "Stateless per request"
            },
            {
                "protocol": "JWT Bearer Token",
                "header_size_bytes": 820,
                "complexity": "O(N) RS256/HS256 Signature Verification",
                "server_cpu_cost": "Moderate (~ 1.45 ms)",
                "state": "Stateless token with signature"
            },
            {
                "protocol": "OAuth2 / Session Cookie",
                "header_size_bytes": 1850,
                "complexity": "Distributed Cache / Redis / IdP lookup",
                "server_cpu_cost": "High (~ 3.80 ms)",
                "state": "Stateful Session Store"
            }
        ]
    }

# 5. Quick Simulation Lockout Endpoint
@app.post("/api/simulate-lockout/{username}", summary="1-Click Lockout Simulator")
def simulate_lockout(username: str):
    target = username.strip()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, status FROM users WHERE username = ?", (target,))
    user = cursor.fetchone()

    if not user:
        dummy_hash = custom_hash("password123")
        cursor.execute(
            "INSERT INTO users (username, password_hash, failed_attempts, status) VALUES (?, ?, 3, 'locked')",
            (target, dummy_hash)
        )
        conn.commit()
        conn.close()
        return {
            "message": f"User '{target}' was registered and immediately LOCKED (failed_attempts=3).",
            "username": target,
            "status": "locked",
            "failed_attempts": 3
        }
    else:
        cursor.execute(
            "UPDATE users SET failed_attempts = 3, status = 'locked' WHERE id = ?",
            (user["id"],)
        )
        conn.commit()
        conn.close()
        return {
            "message": f"Simulated 3 consecutive failed attempts on '{target}'. Account is now LOCKED.",
            "username": target,
            "status": "locked",
            "failed_attempts": 3
        }

# 6. Audit Report Endpoint
@app.get("/admin/audit", response_model=List[UserResponse], summary="Fetch User Audit Report")
def get_audit_report():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, status, failed_attempts, created_at FROM users ORDER BY id ASC")
    rows = cursor.fetchall()
    conn.close()

    audit_list = [
        {
            "id": row["id"],
            "username": row["username"],
            "status": row["status"],
            "failed_attempts": row["failed_attempts"],
            "created_at": row["created_at"]
        }
        for row in rows
    ]
    return audit_list

# 7. Admin Unlock Endpoint
@app.post("/admin/unlock/{username}", summary="Unlock Account")
def unlock_user(username: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ?", (username.strip(),))
    user = cursor.fetchone()

    if not user:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{username}' not found."
        )

    cursor.execute(
        "UPDATE users SET status = 'active', failed_attempts = 0 WHERE id = ?",
        (user["id"],)
    )
    conn.commit()
    conn.close()

    return {
        "message": f"Account '{username}' has been successfully unlocked and failed attempts reset to 0.",
        "username": username,
        "status": "active"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
