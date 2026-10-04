# Basic Authentication Simulation (Route-Protected Cyber Security Dashboard)

A production-grade full-stack security simulation dashboard built with **FastAPI**, **SQLite**, and **Vanilla HTML5/CSS3/JavaScript (Fetch API)**.

---

## 🚀 Key Features

1. **Two Distinct Views with Route Guard (`localStorage`)**:
   - **Auth Gateway (Public View):** Tabbed interface for Login & Registration with live ASCII sum calculation and password visibility toggles.
   - **Security Dashboard (Protected View):** Route-guarded! Hidden by default; unauthenticated access redirects to the login view. Displays user session profile, live security operations center, and **Log Out** button that clears `localStorage`.
2. **Custom ASCII-Sum Password Hashing**:
   - Computes $\text{Hash} = \sum_{i=1}^n \text{ord}(\text{char}_i)$.
3. **3-Attempt Account Lockout Mechanism**:
   - Tracks consecutive failed attempts in SQLite.
   - 3rd consecutive failed attempt sets `status = 'locked'`.
   - Rejects future logins (HTTP 403 Forbidden) until unlocked by an administrator.
4. **CORS Configured**:
   - `CORSMiddleware` with `allow_origins=["*"]` ensures seamless browser communication without cross-origin errors.
5. **Google Sheets Integration (`gspread`)**:
   - Appends `[Username, Timestamp, Status]` into a Google Sheet on successful login.
   - Placeholder for `credentials.json` in `backend/` with resilient non-crashing fallback.

---

## 🏃 Running the Application

### 1. Backend Server (FastAPI)
```powershell
cd d:\Java_fulStack\backend
python -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
```
- **Base URL:** `http://127.0.0.1:8000`
- **Swagger Docs:** `http://127.0.0.1:8000/docs`

### 2. Frontend Application
Open [d:\Java_fulStack\frontend\index.html](file:///d:/Java_fulStack/frontend/index.html) or run:
```powershell
cd d:\Java_fulStack\frontend
python -m http.server 3000
```
- **Web App URL:** `http://localhost:3000`

---

## 📊 Google Sheets Setup Placeholder

Place your Google Service Account JSON key in the backend directory as:
```
d:\Java_fulStack\backend\credentials.json
```
*(A template placeholder is available at `backend/credentials.json.example`)*.
Create a Google Sheet titled `AuthAuditLogs` and share edit access with your service account email.
