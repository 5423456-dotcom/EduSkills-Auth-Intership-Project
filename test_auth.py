import sys
import os
import base64

# Add backend directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient
from main import app, custom_hash, DB_PATH, append_to_google_sheet
import sqlite3

def run_tests():
    # Remove existing test DB if any to have a clean state
    if os.path.exists(DB_PATH):
        try:
            os.remove(DB_PATH)
        except PermissionError:
            pass
    
    # Re-initialize main DB
    from main import init_db
    init_db()

    client = TestClient(app)

    print("--- 1. Testing Custom Hash Algorithm ---")
    expected_sum = str(sum(ord(c) for c in "cyberpass123"))
    assert custom_hash("cyberpass123") == expected_sum
    print(f"Hash verified: 'cyberpass123' -> {expected_sum}")

    print("\n--- 2. Testing Root Health Check & CORS Info ---")
    root_res = client.get("/")
    assert root_res.status_code == 200
    root_data = root_res.json()
    assert root_data["status"] == "online"
    assert root_data["cors_enabled"] is True
    print(f"Root health check verified: {root_data['endpoints']}")

    print("\n--- 3. Testing User Registration ---")
    reg_res = client.post("/register", json={"username": "Abhi_hack", "password": "password123"})
    assert reg_res.status_code == 201
    reg_data = reg_res.json()
    assert reg_data["username"] == "Abhi_hack"
    print(f"User 'Abhi_hack' registered successfully: {reg_data['custom_hash_info']}")

    print("\n--- 4. FEATURE 1 TEST: Instant Test Runner / Valid Login ---")
    login_res = client.post("/login", json={"username": "Abhi_hack", "password": "password123"})
    assert login_res.status_code == 200
    assert login_res.json()["status"] == "active"
    print("Standard login validation passed (HTTP 200).")

    print("\n--- 5. FEATURE 2 TEST: Native RFC 7617 HTTP Basic Auth ---")
    # Encode 'Abhi_hack:password123' in base64
    b64_creds = base64.b64encode(b"Abhi_hack:password123").decode("utf-8")
    native_res = client.get("/api/native-auth", headers={"Authorization": f"Basic {b64_creds}"})
    assert native_res.status_code == 200
    native_data = native_res.json()
    assert native_data["status"] == "success"
    assert native_data["authenticated_user"] == "Abhi_hack"
    print(f"Native HTTP Basic Auth verified: {native_data['protocol']} - {native_data['message']}")

    print("\n--- 6. FEATURE 3 TEST: Low Overhead & Latency Benchmark ---")
    bench_res = client.get("/api/benchmark")
    assert bench_res.status_code == 200
    bench_data = bench_res.json()
    assert "sqlite_ping_ms" in bench_data
    assert len(bench_data["overhead_comparison"]) == 3
    print(f"Benchmark verified: DB Ping {bench_data['sqlite_ping_ms']}ms, Overhead items: {len(bench_data['overhead_comparison'])}")

    print("\n--- 7. FEATURE 4 TEST: 1-Click Lockout Simulator ---")
    sim_res = client.post("/api/simulate-lockout/Abhi_hack")
    assert sim_res.status_code == 200
    sim_data = sim_res.json()
    assert sim_data["status"] == "locked"
    assert sim_data["failed_attempts"] == 3
    print(f"Simulate lockout verified: {sim_data['message']}")

    # Verify user is blocked now
    blocked_res = client.post("/login", json={"username": "Abhi_hack", "password": "password123"})
    assert blocked_res.status_code == 403
    print("Verification passed: user 'Abhi_hack' is locked and blocked from login.")

    print("\n--- 8. Testing Admin Unlock Endpoint ---")
    unlock_res = client.post("/admin/unlock/Abhi_hack")
    assert unlock_res.status_code == 200
    
    # Login again
    login_again = client.post("/login", json={"username": "Abhi_hack", "password": "password123"})
    assert login_again.status_code == 200
    print("User 'Abhi_hack' successfully logged in after admin unlock.")

    print("\n========================================================")
    print("ALL 4 FEATURES & TEST SUITE PASSED SUCCESSFULLY! (100%)")
    print("========================================================")

if __name__ == "__main__":
    run_tests()
