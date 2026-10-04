// Basic Authentication Simulation - Route-Protected Frontend Controller v3.0
const API_BASE_URL = "http://127.0.0.1:8000";
const AUTH_STORAGE_KEY = "cyber_auth_user";

// View Containers
const authView = document.getElementById("authView");
const dashboardView = document.getElementById("dashboardView");

// Auth Tabs & Panels
const tabLoginBtn = document.getElementById("tabLoginBtn");
const tabRegisterBtn = document.getElementById("tabRegisterBtn");
const loginPanel = document.getElementById("loginPanel");
const registerPanel = document.getElementById("registerPanel");

// Forms
const loginForm = document.getElementById("loginForm");
const loginUsernameInput = document.getElementById("loginUsername");
const loginPasswordInput = document.getElementById("loginPassword");
const loginAlert = document.getElementById("loginAlert");
const btnLogin = document.getElementById("btnLogin");

const registerForm = document.getElementById("registerForm");
const regUsernameInput = document.getElementById("regUsername");
const regPasswordInput = document.getElementById("regPassword");
const previewHashVal = document.getElementById("previewHashVal");
const registerAlert = document.getElementById("registerAlert");
const btnRegister = document.getElementById("btnRegister");

// Dashboard Elements
const sessionUsername = document.getElementById("sessionUsername");
const userAvatar = document.getElementById("userAvatar");
const btnLogout = document.getElementById("btnLogout");
const dashBackendStatus = document.getElementById("dashBackendStatus");
const dashBackendLabel = document.getElementById("dashBackendLabel");

// Feature Interactive Panel Elements
const featurePills = document.querySelectorAll(".feature-pill");
const featurePanels = document.querySelectorAll(".feature-panel-content");

// Feature 1: Instant Test Runner
const btnRunInstantTest = document.getElementById("btnRunInstantTest");
const instantTestOutput = document.getElementById("instantTestOutput");

// Feature 2: Native RFC 7617 Tester
const nativeUser = document.getElementById("nativeUser");
const nativePass = document.getElementById("nativePass");
const nativeHeaderPreview = document.getElementById("nativeHeaderPreview");
const btnSendNativeAuth = document.getElementById("btnSendNativeAuth");
const nativeAuthOutput = document.getElementById("nativeAuthOutput");

// Feature 3: Low Overhead
const btnRunBenchmark = document.getElementById("btnRunBenchmark");
const livePingVal = document.getElementById("livePingVal");

// Feature 4: Practical Simulator
const simTargetUser = document.getElementById("simTargetUser");
const btnSimulateLockout = document.getElementById("btnSimulateLockout");
const btnResetAllAccounts = document.getElementById("btnResetAllAccounts");
const simAlert = document.getElementById("simAlert");

// Audit Table
const auditTableBody = document.getElementById("auditTableBody");
const btnRefreshAudit = document.getElementById("btnRefreshAudit");
const userCountBadge = document.getElementById("userCountBadge");

// ==========================================================================
// Initialization & Route Guard Check
// ==========================================================================
document.addEventListener("DOMContentLoaded", () => {
  initRouteGuard();
  initAuthTabs();
  initPasswordToggles();
  initAsciiHashPreview();
  initFeatureTabs();
  initNativeAuthPreview();

  // Form Submissions
  loginForm.addEventListener("submit", handleLogin);
  registerForm.addEventListener("submit", handleRegister);

  // Logout Handler
  btnLogout.addEventListener("click", handleLogout);

  // Dashboard Feature Handlers
  btnRunInstantTest.addEventListener("click", runInstantEndToEndTest);
  btnSendNativeAuth.addEventListener("click", sendNativeAuthRequest);
  btnRunBenchmark.addEventListener("click", runOverheadBenchmark);
  btnSimulateLockout.addEventListener("click", handleSimulateLockout);
  btnResetAllAccounts.addEventListener("click", handleUnlockAll);

  // Audit Refresh
  btnRefreshAudit.addEventListener("click", () => {
    btnRefreshAudit.querySelector(".btn-spin-icon").style.transform = "rotate(360deg)";
    loadAuditReport();
  });
});

// ==========================================================================
// Route Guard: Protected Route & View Switching
// ==========================================================================
function initRouteGuard() {
  const userJson = localStorage.getItem(AUTH_STORAGE_KEY);
  if (userJson) {
    try {
      const user = JSON.parse(userJson);
      if (user && user.username) {
        showDashboardView(user);
        return;
      }
    } catch {
      localStorage.removeItem(AUTH_STORAGE_KEY);
    }
  }

  // Default: Route Guard forces unauthenticated users to Auth View
  showAuthView();
}

function showDashboardView(user) {
  authView.classList.add("hidden");
  dashboardView.classList.remove("hidden");

  sessionUsername.textContent = user.username;
  userAvatar.textContent = (user.username.charAt(0) || "U").toUpperCase();

  // Prefill simulator and native auth tester
  if (simTargetUser) simTargetUser.value = user.username;
  if (nativeUser) {
    nativeUser.value = user.username;
    nativeUser.dispatchEvent(new Event("input"));
  }

  checkBackendHealth();
  loadAuditReport();
}

function showAuthView(noticeHtml = null) {
  dashboardView.classList.add("hidden");
  authView.classList.remove("hidden");

  if (noticeHtml) {
    showAlert(loginAlert, noticeHtml, "warning");
  }
  checkBackendHealth();
}

function handleLogout() {
  localStorage.removeItem(AUTH_STORAGE_KEY);
  loginPasswordInput.value = "";
  showAuthView("🔒 <strong>Logged Out:</strong> Your session was cleared from localStorage. Please log in again.");
}

// ==========================================================================
// Auth Tabs: Login vs Register Switcher
// ==========================================================================
function initAuthTabs() {
  tabLoginBtn.addEventListener("click", () => {
    tabLoginBtn.classList.add("active-tab");
    tabRegisterBtn.classList.remove("active-tab");
    loginPanel.classList.remove("hidden");
    registerPanel.classList.add("hidden");
    clearAlert(loginAlert);
  });

  tabRegisterBtn.addEventListener("click", () => {
    tabRegisterBtn.classList.add("active-tab");
    tabLoginBtn.classList.remove("active-tab");
    registerPanel.classList.remove("hidden");
    loginPanel.classList.add("hidden");
    clearAlert(registerAlert);
  });
}

// ==========================================================================
// Authentication Handlers (Register & Login)
// ==========================================================================
async function handleRegister(e) {
  e.preventDefault();
  clearAlert(registerAlert);

  const username = regUsernameInput.value.trim();
  const password = regPasswordInput.value;

  if (!username || !password) {
    showAlert(registerAlert, "Please provide both username and password.", "danger");
    return;
  }

  btnRegister.disabled = true;
  btnRegister.innerHTML = `<span>Creating Account...</span>`;

  try {
    const response = await fetch(`${API_BASE_URL}/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password })
    });

    const data = await response.json();

    if (response.ok) {
      showAlert(
        registerAlert,
        `✅ <strong>Success!</strong> User <code>${escapeHtml(data.username)}</code> registered.<br>` +
        `∑ ASCII Hash: <strong style="color: var(--neon-pink);">${data.custom_hash_info.hash_value}</strong> saved in SQLite. Switch to 'Log In' to enter!`,
        "success"
      );

      // Pre-fill login username and switch to login tab after 1 second
      loginUsernameInput.value = username;
      setTimeout(() => {
        tabLoginBtn.click();
        showAlert(loginAlert, `Account <code>${escapeHtml(username)}</code> ready. Enter your password to log in.`, "success");
      }, 1200);
    } else {
      showAlert(
        registerAlert,
        `❌ <strong>Registration Rejected:</strong> ${escapeHtml(data.detail || "Error registering user.")}`,
        "danger"
      );
    }
  } catch (err) {
    showAlert(
      registerAlert,
      `⚠️ <strong>Connection Error:</strong> Could not reach backend at <code>${API_BASE_URL}</code>. Ensure FastAPI is running.`,
      "danger"
    );
  } finally {
    btnRegister.disabled = false;
    btnRegister.innerHTML = `<span>Create Account</span><svg class="btn-arrow" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M5 12h14M12 5l7 7-7 7"/></svg>`;
  }
}

async function handleLogin(e) {
  e.preventDefault();
  clearAlert(loginAlert);

  const username = loginUsernameInput.value.trim();
  const password = loginPasswordInput.value;

  if (!username || !password) {
    showAlert(loginAlert, "Please enter both username and password.", "danger");
    return;
  }

  btnLogin.disabled = true;
  btnLogin.innerHTML = `<span>Authenticating...</span>`;

  try {
    const response = await fetch(`${API_BASE_URL}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password })
    });

    const data = await response.json();

    if (response.ok) {
      // Successful Login: Save to localStorage (Route Guard state)
      const userSession = {
        username: data.username,
        token: data.token || "session_token",
        loggedInAt: new Date().toISOString()
      };
      localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(userSession));

      loginPasswordInput.value = "";

      // Smooth Route Guard transition to Protected Dashboard
      showDashboardView(userSession);
    } else if (response.status === 403) {
      // 403 Forbidden - Account Locked
      showAlert(
        loginAlert,
        `🔒 <strong>SECURITY LOCKOUT:</strong> ${escapeHtml(data.detail)}`,
        "danger"
      );
    } else if (response.status === 401) {
      // 401 Unauthorized - Failed Attempt
      showAlert(
        loginAlert,
        `⚠️ <strong>Authentication Failed:</strong> ${escapeHtml(data.detail)}`,
        "warning"
      );
    } else {
      showAlert(
        loginAlert,
        `❌ <strong>Error:</strong> ${escapeHtml(data.detail || "Authentication error.")}`,
        "danger"
      );
    }
  } catch (err) {
    showAlert(
      loginAlert,
      `⚠️ <strong>Connection Error:</strong> Could not reach backend server at <code>${API_BASE_URL}</code>.<br>` +
      `<small>Start the server: <code>cd backend && python -m uvicorn main:app --reload --host 127.0.0.1 --port 8000</code></small>`,
      "danger"
    );
  } finally {
    btnLogin.disabled = false;
    btnLogin.innerHTML = `<span>Authenticate & Enter Dashboard</span><svg class="btn-arrow" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M5 12h14M12 5l7 7-7 7"/></svg>`;
  }
}

// ==========================================================================
// Dashboard: Feature Interactive Tools
// ==========================================================================
function initFeatureTabs() {
  featurePills.forEach((pill) => {
    pill.addEventListener("click", () => {
      const featureKey = pill.getAttribute("data-feature");

      featurePills.forEach((p) => p.classList.remove("active-feature"));
      pill.classList.add("active-feature");

      featurePanels.forEach((panel) => {
        if (panel.id === `panel-${featureKey}`) {
          panel.classList.remove("hidden");
        } else {
          panel.classList.add("hidden");
        }
      });
    });
  });
}

// Feature 1: Instant Test Runner
async function runInstantEndToEndTest() {
  btnRunInstantTest.disabled = true;
  instantTestOutput.innerHTML = `<span class="term-info">⚡ Initializing automated 1-click test sequence...</span>\n`;

  const testUser = `test_bot_${Math.floor(1000 + Math.random() * 9000)}`;
  const testPass = "pass123";
  const startTime = performance.now();

  try {
    instantTestOutput.innerHTML += `<span>[1/3] POST /register &bull; payload: { username: "${testUser}", password: "${testPass}" }...</span>\n`;
    const regRes = await fetch(`${API_BASE_URL}/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: testUser, password: testPass })
    });
    const regData = await regRes.json();
    if (!regRes.ok) throw new Error(regData.detail || "Registration failed");

    instantTestOutput.innerHTML += `<span class="term-success">&radic; User registered! Stored ASCII Hash: <strong>${regData.custom_hash_info.hash_value}</strong></span>\n`;

    instantTestOutput.innerHTML += `<span>[2/3] POST /login &bull; Verifying credentials against SQLite...</span>\n`;
    const loginRes = await fetch(`${API_BASE_URL}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: testUser, password: testPass })
    });
    const loginData = await loginRes.json();
    if (!loginRes.ok) throw new Error(loginData.detail || "Login failed");

    instantTestOutput.innerHTML += `<span class="term-success">&radic; Authentication approved! Status: <strong>${loginData.status}</strong></span>\n`;

    instantTestOutput.innerHTML += `<span>[3/3] GET /admin/audit &bull; Refreshing audit registry...</span>\n`;
    await loadAuditReport();

    const elapsedMs = (performance.now() - startTime).toFixed(1);
    instantTestOutput.innerHTML += `<span class="term-highlight">🚀 SUCCESS: Full Register &bull; Hash &bull; Authenticate cycle completed in ${elapsedMs}ms!</span>\n`;
  } catch (err) {
    instantTestOutput.innerHTML += `<span style="color: #ff4797;">&times; Test Failed: ${err.message}</span>\n`;
  } finally {
    btnRunInstantTest.disabled = false;
  }
}

// Feature 2: Native RFC 7617 Protocol Tester
function initNativeAuthPreview() {
  const updatePreview = () => {
    if (!nativeUser || !nativePass) return;
    const u = nativeUser.value.trim();
    const p = nativePass.value;
    try {
      const b64 = btoa(`${u}:${p}`);
      nativeHeaderPreview.textContent = `Authorization: Basic ${b64}`;
    } catch {
      nativeHeaderPreview.textContent = `Authorization: Basic [Encoding...]`;
    }
  };

  if (nativeUser && nativePass) {
    nativeUser.addEventListener("input", updatePreview);
    nativePass.addEventListener("input", updatePreview);
    updatePreview();
  }
}

async function sendNativeAuthRequest() {
  const u = nativeUser.value.trim();
  const p = nativePass.value;

  if (!u || !p) {
    nativeAuthOutput.innerHTML = `<span style="color: #ff4797;">Please enter both username and password.</span>`;
    return;
  }

  btnSendNativeAuth.disabled = true;
  nativeAuthOutput.innerHTML = `<span class="term-info">Sending RFC 7617 header: Authorization: Basic ${btoa(u + ":" + p)}...</span>\n`;

  try {
    const basicToken = btoa(`${u}:${p}`);
    const res = await fetch(`${API_BASE_URL}/api/native-auth`, {
      method: "GET",
      headers: { "Authorization": `Basic ${basicToken}` }
    });

    const data = await res.json();

    if (res.ok) {
      nativeAuthOutput.innerHTML = `
<span class="term-success">&radic; HTTP 200 OK &bull; Native Basic Auth Verified!</span>
<span class="term-info">Protocol:</span> ${data.protocol}
<span class="term-info">Authenticated User:</span> <strong style="color: #ffffff;">${data.authenticated_user}</strong>
<span class="term-info">Header Overhead:</span> ~${data.header_inspection.approx_header_size_bytes} Bytes
<span class="term-highlight">${data.message}</span>
`;
      loadAuditReport();
    } else {
      nativeAuthOutput.innerHTML = `
<span style="color: #ff4797;">&times; HTTP ${res.status}: ${data.detail || "Authentication Failed"}</span>
<span class="term-muted">Tip: Register '${u}' first or verify password.</span>
`;
    }
  } catch (err) {
    nativeAuthOutput.innerHTML = `<span style="color: #ff4797;">Connection Error: Ensure backend is running.</span>`;
  } finally {
    btnSendNativeAuth.disabled = false;
  }
}

// Feature 3: Low Overhead Benchmark
async function runOverheadBenchmark() {
  btnRunBenchmark.disabled = true;
  livePingVal.textContent = "Measuring latency...";

  const t0 = performance.now();
  try {
    const res = await fetch(`${API_BASE_URL}/api/benchmark`);
    const rtt = (performance.now() - t0).toFixed(1);
    const data = await res.json();

    if (res.ok) {
      livePingVal.textContent = `${rtt} ms RTT (DB Ping: ${data.sqlite_ping_ms} ms)`;
    } else {
      livePingVal.textContent = `${rtt} ms`;
    }
  } catch (err) {
    livePingVal.textContent = "Server Unreachable";
  } finally {
    btnRunBenchmark.disabled = false;
  }
}

// Feature 4: 1-Click Lockout Simulator
async function handleSimulateLockout() {
  const username = simTargetUser.value.trim() || "Abhi_hack";
  btnSimulateLockout.disabled = true;

  try {
    const res = await fetch(`${API_BASE_URL}/api/simulate-lockout/${encodeURIComponent(username)}`, {
      method: "POST"
    });
    const data = await res.json();

    showAlert(
      simAlert,
      `🔒 <strong>Lockout Triggered:</strong> ${data.message} Status: <strong>${data.status}</strong> (${data.failed_attempts}/3 attempts).`,
      "danger"
    );
    loadAuditReport();
  } catch (err) {
    showAlert(simAlert, "Error triggering simulated lockout.", "danger");
  } finally {
    btnSimulateLockout.disabled = false;
  }
}

async function handleUnlockAll() {
  btnResetAllAccounts.disabled = true;
  try {
    const auditRes = await fetch(`${API_BASE_URL}/admin/audit`);
    const users = await auditRes.json();
    let unlockedCount = 0;

    for (const u of users) {
      if (u.status === "locked" || u.failed_attempts > 0) {
        await fetch(`${API_BASE_URL}/admin/unlock/${encodeURIComponent(u.username)}`, { method: "POST" });
        unlockedCount++;
      }
    }

    showAlert(simAlert, `🔓 Reset complete! Unlocked ${unlockedCount} account(s) back to active status.`, "success");
    loadAuditReport();
  } catch (err) {
    showAlert(simAlert, "Failed to reset accounts.", "danger");
  } finally {
    btnResetAllAccounts.disabled = false;
  }
}

// ==========================================================================
// Security Audit Registry Loader
// ==========================================================================
async function loadAuditReport() {
  btnRefreshAudit.disabled = true;

  try {
    const res = await fetch(`${API_BASE_URL}/admin/audit`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);

    const users = await res.json();
    userCountBadge.textContent = `${users.length} ${users.length === 1 ? "Record" : "Records"}`;

    if (users.length === 0) {
      auditTableBody.innerHTML = `
        <tr>
          <td colspan="6" class="empty-state">
            No registered users in SQLite database.
          </td>
        </tr>
      `;
      return;
    }

    auditTableBody.innerHTML = users.map((u) => {
      const isLocked = u.status === "locked";
      const statusPillClass = isLocked ? "locked" : "active";
      const statusText = isLocked ? "🔒 Locked" : "🟢 Active";

      let attemptPillClass = "safe";
      if (u.failed_attempts === 1) attemptPillClass = "warn";
      if (u.failed_attempts === 2) attemptPillClass = "warn";
      if (u.failed_attempts >= 3) attemptPillClass = "danger";

      const attemptLabel = isLocked
        ? `<span class="table-attempt-pill danger">${u.failed_attempts} / 3 (Locked)</span>`
        : `<span class="table-attempt-pill ${attemptPillClass}">${u.failed_attempts} / 3</span>`;

      const actionBtn = isLocked
        ? `<button class="btn-unlock-account" onclick="unlockUserAccount('${escapeHtml(u.username)}')">🔓 Unlock Account</button>`
        : `<span style="color: var(--text-muted); font-size: 0.8rem;">Active</span>`;

      return `
        <tr>
          <td><span style="font-family: var(--font-mono); color: #94a3b8;">#${u.id}</span></td>
          <td><strong style="color: #ffffff;">${escapeHtml(u.username)}</strong></td>
          <td>
            <span class="table-status-pill ${statusPillClass}">${statusText}</span>
          </td>
          <td>${attemptLabel}</td>
          <td><small style="color: var(--text-secondary);">${formatTimestamp(u.created_at)}</small></td>
          <td>${actionBtn}</td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    auditTableBody.innerHTML = `
      <tr>
        <td colspan="6" class="empty-state" style="color: var(--neon-pink);">
          ⚠️ Failed to load audit report. Ensure the FastAPI backend is running at ${API_BASE_URL}.
        </td>
      </tr>
    `;
  } finally {
    btnRefreshAudit.disabled = false;
  }
}

async function unlockUserAccount(username) {
  try {
    const res = await fetch(`${API_BASE_URL}/admin/unlock/${encodeURIComponent(username)}`, {
      method: "POST"
    });
    const data = await res.json();

    if (res.ok) {
      loadAuditReport();
    } else {
      alert(`Could not unlock user: ${data.detail || "Error"}`);
    }
  } catch (err) {
    alert("Unlock error: Backend not reachable.");
  }
}

window.unlockUserAccount = unlockUserAccount;

// ==========================================================================
// Helpers
// ==========================================================================
function initAsciiHashPreview() {
  regPasswordInput.addEventListener("input", (e) => {
    const pwd = e.target.value;
    let sum = 0;
    for (let i = 0; i < pwd.length; i++) {
      sum += pwd.charCodeAt(i);
    }
    previewHashVal.textContent = sum;
  });
}

function initPasswordToggles() {
  document.querySelectorAll(".eye-toggle-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const targetId = btn.getAttribute("data-target");
      const targetInput = document.getElementById(targetId);
      if (targetInput.type === "password") {
        targetInput.type = "text";
        btn.textContent = "🙈";
      } else {
        targetInput.type = "password";
        btn.textContent = "👁️";
      }
    });
  });
}

async function checkBackendHealth() {
  try {
    const res = await fetch(`${API_BASE_URL}/`, { method: "GET" });
    if (res.ok) {
      if (dashBackendStatus && dashBackendLabel) {
        dashBackendStatus.className = "status-pill status-online";
        dashBackendLabel.textContent = "FastAPI Online";
      }
    }
  } catch {
    if (dashBackendStatus && dashBackendLabel) {
      dashBackendStatus.className = "status-pill status-offline";
      dashBackendLabel.textContent = "Backend Offline";
    }
  }
}

function showAlert(container, messageHtml, type = "success") {
  container.className = `cyber-alert alert-${type}`;
  container.innerHTML = messageHtml;
  container.classList.remove("hidden");
}

function clearAlert(container) {
  container.className = "cyber-alert hidden";
  container.innerHTML = "";
}

function escapeHtml(str) {
  if (!str) return "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function formatTimestamp(timestamp) {
  if (!timestamp) return "N/A";
  try {
    const d = new Date(timestamp);
    return isNaN(d.getTime()) ? timestamp : d.toLocaleString();
  } catch {
    return timestamp;
  }
}
