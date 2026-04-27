from flask import Flask, render_template_string, request, jsonify
from threading import Lock
import json
import os
import hashlib
import uuid
from datetime import datetime
import time

# Importer la configuration
import config

# Importer MFA manager from security module
try:
    from security import mfa_manager
    USE_MFA = True
    print("✓ MFA manager loaded from security.py")
except ImportError as e:
    print(f"⚠ Could not import mfa_manager: {e} — MFA disabled")
    USE_MFA = False
    mfa_manager = None

# Importer le PDP
try:
    from pdp import PolicyDecisionPoint
    USE_REAL_PDP = True
    print("✓ Using real PDP from pdp.py")
except ImportError as e:
    print(f"⚠ Could not import pdp.py: {e}")
    USE_REAL_PDP = False

# ============================================================================
# HTML TEMPLATE
# ============================================================================

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f7fa;
            color: #2c3e50;
        }

        .login-modal {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.6);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 9999;
        }

        .login-card {
            background: white;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
            width: 100%;
            max-width: 450px;
        }

        .login-card h2 {
            margin-bottom: 10px;
            color: #2c3e50;
            font-size: 28px;
        }

        .login-card > p {
            color: #7f8c8d;
            margin-bottom: 30px;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #2c3e50;
            font-weight: 600;
        }

        .form-group input {
            width: 100%;
            padding: 12px;
            border: 1px solid #bdc3c7;
            border-radius: 6px;
            font-size: 14px;
            transition: border-color 0.3s;
        }

        .form-group input:focus {
            outline: none;
            border-color: #3498db;
            box-shadow: 0 0 5px rgba(52, 152, 219, 0.3);
        }

        .password-container {
            position: relative;
            display: flex;
        }

        .password-container input {
            flex: 1;
        }

        .password-toggle {
            position: absolute;
            right: 12px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            cursor: pointer;
            color: #7f8c8d;
            font-size: 18px;
            padding: 0;
        }

        .password-toggle:hover {
            color: #3498db;
        }

        .login-submit {
            width: 100%;
            padding: 12px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 6px;
            font-weight: bold;
            font-size: 16px;
            cursor: pointer;
            transition: background 0.3s;
            margin-top: 10px;
        }

        .login-submit:hover {
            background: #5568d3;
        }

        #login-message {
            text-align: center;
            margin-top: 15px;
        }

        .main-container {
            display: flex;
            height: 100vh;
        }

        .sidebar {
            width: 280px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            overflow-y: auto;
            box-shadow: 2px 0 10px rgba(0, 0, 0, 0.1);
        }

        .sidebar-header {
            text-align: center;
            margin-bottom: 30px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.2);
            padding-bottom: 20px;
        }

        .sidebar-header h2 {
            font-size: 20px;
            margin-bottom: 10px;
        }

        .sidebar-user {
            font-size: 12px;
            opacity: 0.9;
        }

        .sidebar-username {
            font-weight: bold;
            display: block;
            font-size: 14px;
        }

        .sidebar-role {
            display: block;
            font-size: 12px;
            color: rgba(255, 255, 255, 0.7);
        }

        .sidebar-menu {
            list-style: none;
            margin-bottom: 30px;
        }

        .sidebar-menu li {
            margin-bottom: 15px;
        }

        .nav-link {
            color: rgba(255, 255, 255, 0.8);
            cursor: pointer;
            padding: 10px;
            border-radius: 6px;
            transition: all 0.3s;
            display: block;
            text-decoration: none;
        }

        .nav-link:hover {
            background: rgba(255, 255, 255, 0.1);
            color: white;
        }

        .nav-link.active {
            background: rgba(255, 255, 255, 0.2);
            color: white;
            font-weight: bold;
        }

        .logout-btn {
            width: 100%;
            padding: 10px;
            background: rgba(255, 255, 255, 0.2);
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-weight: bold;
            margin-top: 30px;
            transition: background 0.3s;
        }

        .logout-btn:hover {
            background: rgba(255, 0, 0, 0.5);
        }

        .content {
            flex: 1;
            overflow-y: auto;
            padding: 30px;
        }

        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid #e0e0e0;
        }

        .header h1 {
            font-size: 28px;
            color: #2c3e50;
        }

        .header-time {
            font-size: 12px;
            color: #7f8c8d;
            font-weight: bold;
        }

        .section {
            display: none;
        }

        .section.active {
            display: block;
        }

        .card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            margin-bottom: 20px;
        }

        .card h3 {
            color: #2c3e50;
            margin-bottom: 15px;
        }

        .card p {
            margin-bottom: 10px;
            color: #555;
        }

        .user-info-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
            margin-bottom: 20px;
        }

        .user-info-item {
            background: white;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }

        .user-info-label {
            display: block;
            font-size: 12px;
            color: #7f8c8d;
            font-weight: bold;
            text-transform: uppercase;
        }

        .user-info-value {
            display: block;
            font-size: 16px;
            color: #2c3e50;
            font-weight: bold;
            margin-top: 5px;
        }

        .resources-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }

        .resource-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            border-top: 4px solid #3498db;
        }

        .resource-card h4 {
            color: #2c3e50;
            margin-bottom: 10px;
        }

        .classification-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            margin: 5px 0;
        }

        .classification-badge.public {
            background: #d4edda;
            color: #155724;
        }

        .classification-badge.confidential {
            background: #fff3cd;
            color: #856404;
        }

        .classification-badge.secret {
            background: #f8d7da;
            color: #721c24;
        }

        .resource-actions {
            display: flex;
            gap: 10px;
            margin-top: 10px;
            align-items: center;
        }

        .op-select {
            padding: 8px 12px;
            border: 1px solid #bdc3c7;
            border-radius: 6px;
            font-size: 14px;
            background: white;
            cursor: pointer;
        }

        .op-select:hover {
            border-color: #3498db;
        }

        .action-btn {
            background: #3498db;
            color: white;
            padding: 8px 15px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-weight: bold;
            transition: background 0.3s;
        }

        .action-btn:hover {
            background: #2980b9;
        }

        .access-modal {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 8888;
        }

        .access-modal.hidden {
            display: none;
        }

        .access-modal-content {
            background: white;
            padding: 40px;
            border-radius: 12px;
            max-width: 600px;
            width: 90%;
            max-height: 80vh;
            overflow-y: auto;
            position: relative;
        }

        .modal-close {
            position: absolute;
            top: 15px;
            right: 15px;
            background: none;
            border: none;
            font-size: 24px;
            cursor: pointer;
            color: #7f8c8d;
        }

        .modal-close:hover {
            color: #e74c3c;
        }

        .table-container {
            background: white;
            padding: 20px;
            border-radius: 8px;
            overflow-x: auto;
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        table thead {
            background: #f5f5f5;
        }

        table th {
            padding: 12px;
            text-align: left;
            font-weight: bold;
            border-bottom: 2px solid #e0e0e0;
        }

        table td {
            padding: 12px;
            border-bottom: 1px solid #e0e0e0;
        }

        table tr:hover {
            background: #f9f9f9;
        }

        .log-entry {
            padding: 15px;
            margin-bottom: 12px;
            background: #f5f5f5;
            border-left: 4px solid #3498db;
            border-radius: 6px;
            font-size: 13px;
        }

        .log-entry.allowed {
            border-left-color: #2ecc71;
            background: #d4edda;
        }

        .log-entry.denied {
            border-left-color: #e74c3c;
            background: #f8d7da;
        }

        .log-timestamp {
            color: #7f8c8d;
            font-weight: bold;
            font-size: 12px;
        }

        .log-username {
            color: #3498db;
            font-weight: bold;
        }

        .form-input-group {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
            margin-bottom: 15px;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }

        .form-input-group input,
        .form-input-group select {
            padding: 12px;
            border: 1px solid #bdc3c7;
            border-radius: 6px;
            font-size: 14px;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }

        .form-input-group input:focus,
        .form-input-group select:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 5px rgba(102, 126, 234, 0.3);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }

        .form-submit-btn {
            background: #27ae60;
            color: white;
            padding: 12px 20px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-weight: bold;
            transition: all 0.3s;
            width: 100%;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }

        .form-submit-btn:hover {
            background: #229954;
        }

        .status-card {
            background: #d4edda;
            border-left: 4px solid #2ecc71;
        }

        .status-card.warning {
            background: #f8d7da;
            border-left-color: #e74c3c;
        }

        .permission-badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            margin: 2px;
        }

        .permission-read { background: #d4edda; color: #155724; }
        .permission-write { background: #fff3cd; color: #856404; }
        .permission-delete { background: #f8d7da; color: #721c24; }

        @media (max-width: 768px) {
            .sidebar {
                width: 200px;
            }
            .form-input-group {
                grid-template-columns: 1fr;
            }
            .user-info-grid {
                grid-template-columns: 1fr;
            }
            .resource-actions {
                flex-direction: column;
            }
            .op-select {
                width: 100%;
            }
            .action-btn {
                width: 100%;
            }
        }
    </style>
</head>
<body>

<!-- LOGIN MODAL -->
<div id="login-modal" class="login-modal">
    <div class="login-card">

        <!-- STEP 1: Username + Password -->
        <div id="login-step-1">
            <h2>🔐 Login</h2>
            <p>Enter your credentials to continue</p>
            <form id="login-form" onsubmit="performLogin(event)">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" placeholder="username" required>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <div class="password-container">
                        <input type="password" id="password" name="password" placeholder="password" required>
                        <button type="button" class="password-toggle" onclick="togglePasswordVisibility()" tabindex="-1">
                            <i class="bi bi-eye" id="password-icon"></i>
                        </button>
                    </div>
                </div>
                <button type="submit" class="login-submit" id="login-submit-btn">Login</button>
                <div id="login-message" style="margin-top: 15px;"></div>
            </form>
        </div>

        <!-- STEP 2: MFA PIN (hidden until step 1 succeeds) -->
        <div id="login-step-2" style="display:none;">
            <h2>🔑 Two-Factor Authentication</h2>
            <p style="color:#7f8c8d; margin-bottom:20px;">A 6-digit PIN has been sent to the MFA terminal.<br>Check the second terminal window and enter it below.</p>
            <div style="background:#eaf4fb; border-left:4px solid #3498db; padding:12px 16px; border-radius:6px; margin-bottom:20px; font-size:13px;">
                <strong>💻 MFA Terminal:</strong> Run <code style="background:#d6eaf8;padding:2px 6px;border-radius:4px;">python mfa_server.py</code> in a second terminal to receive your PIN.
            </div>
            <form id="mfa-form" onsubmit="submitMfaCode(event)">
                <div class="form-group">
                    <label for="mfa-pin">Enter 6-digit PIN</label>
                    <input type="text" id="mfa-pin" name="mfa-pin"
                           placeholder="_ _ _ _ _ _"
                           maxlength="6" pattern="[0-9]{6}"
                           inputmode="numeric"
                           autocomplete="one-time-code"
                           style="font-size:28px; letter-spacing:10px; text-align:center; font-weight:bold;"
                           required>
                </div>
                <button type="submit" class="login-submit" id="mfa-submit-btn">Verify PIN</button>
                <div id="mfa-message" style="margin-top: 15px;"></div>
            </form>
            <button onclick="cancelMfa()" style="width:100%;margin-top:12px;padding:10px;background:none;border:1px solid #bdc3c7;border-radius:6px;cursor:pointer;color:#7f8c8d;font-size:13px;">
                ← Back to Login
            </button>
        </div>

    </div>
</div>

<!-- MAIN DASHBOARD -->
<div class="main-container" style="display: none;">
    <div class="sidebar">
        <div class="sidebar-header">
            <h2>Menu</h2>
            <div class="sidebar-user">
                <span class="sidebar-username" id="sidebar-username">-</span>
                <span class="sidebar-role" id="sidebar-role">-</span>
            </div>
        </div>

        <ul class="sidebar-menu">
            <li><a class="nav-link active" onclick="showSection(event, 'dashboard')"><i class="bi bi-speedometer2"></i> Dashboard</a></li>
            <li><a class="nav-link" onclick="showSection(event, 'resources')"><i class="bi bi-folder"></i> Resources</a></li>
            <li><a class="nav-link" onclick="showSection(event, 'policies')"><i class="bi bi-shield-lock"></i> Policies</a></li>
            <li id="users-link" style="display:none;"><a class="nav-link" onclick="showSection(event, 'users')"><i class="bi bi-people"></i> Users</a></li>
            <li id="matrix-link" style="display:none;"><a class="nav-link" onclick="showSection(event, 'matrix')"><i class="bi bi-table"></i> Access Matrix</a></li>
            <li id="logs-link" style="display:none;"><a class="nav-link" onclick="showSection(event, 'logs')"><i class="bi bi-file-text"></i> Security Logs</a></li>
        </ul>

        <button class="logout-btn" onclick="performLogout()">🚪 Logout</button>
    </div>

    <div class="content">
        <!-- DASHBOARD -->
        <div id="dashboard" class="section active">
            <div class="header">
                <h1><i class="bi bi-speedometer2"></i> Dashboard</h1>
                <span class="header-time" id="current-time-dashboard"></span>
            </div>

            <div class="card">
                <h3>👤 User Information</h3>
                <div class="user-info-grid">
                    <div class="user-info-item">
                        <span class="user-info-label">Username</span>
                        <span class="user-info-value" id="user-name">-</span>
                    </div>
                    <div class="user-info-item">
                        <span class="user-info-label">Role</span>
                        <span class="user-info-value" id="user-role">-</span>
                    </div>
                    <div class="user-info-item">
                        <span class="user-info-label">Department</span>
                        <span class="user-info-value" id="user-department">-</span>
                    </div>
                    <div class="user-info-item">
                        <span class="user-info-label">Clearance Level</span>
                        <span class="user-info-value" id="user-clearance">-</span>
                    </div>
                    <div class="user-info-item">
                        <span class="user-info-label">Permissions</span>
                        <span class="user-info-value" id="user-permissions">-</span>
                    </div>
                </div>
            </div>

            <div class="card">
                <h3>📊 System Statistics</h3>
                <p><strong>Total Users:</strong> <span id="stat-users">0</span></p>
                <p><strong>Total Resources:</strong> <span id="stat-resources">0</span></p>
                <p><strong>Total Policies:</strong> <span id="stat-policies">0</span></p>
            </div>

            <div id="system-status" class="card"></div>
        </div>

        <!-- RESOURCES -->
        <div id="resources" class="section">
            <div class="header">
                <h1><i class="bi bi-folder"></i> Resources</h1>
                <span class="header-time" id="current-time-resources"></span>
            </div>
            <div id="resources-grid" class="resources-grid"></div>
        </div>

        <!-- POLICIES -->
        <div id="policies" class="section">
            <div class="header">
                <h1><i class="bi bi-shield-lock"></i> Policies</h1>
                <span class="header-time" id="current-time-policies"></span>
            </div>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Policy ID</th>
                            <th>Name</th>
                            <th>Description</th>
                
                        </tr>
                    </thead>
                    <tbody id="policies-table-body"></tbody>
                </table>
            </div>
        </div>

        <!-- USERS -->
        <div id="users" class="section">
            <div class="header">
                <h1><i class="bi bi-people"></i> Users</h1>
                <span class="header-time" id="current-time-users"></span>
            </div>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Username</th>
                            <th>Role</th>
                            <th>Department</th>
                            <th>Clearance</th>
                            <th>Permissions</th>
                        </tr>
                    </thead>
                    <tbody id="users-table-body"></tbody>
                </table>
            </div>

            <div class="card">
                <h3>➕ Add New User</h3>
                <form onsubmit="addNewUser(event)">
                    <div class="form-input-group">
                        <input type="text" id="new-username" placeholder="Username" required>
                        <input type="password" id="new-password" placeholder="Password" required>
                    </div>
                    <div class="form-input-group">
                        <select id="new-role" required>
                            <option value="">Select Role</option>
                            <option value="Employee">Employee (read only)</option>
                            <option value="Manager">Manager (read/write)</option>
                            <option value="Admin">Admin (read/write/delete)</option>
                        </select>
                        <select id="new-department" required>
                            <option value="">Select Department</option>
                            <option value="HR">HR</option>
                            <option value="Finance">Finance</option>
                            <option value="IT">IT</option>
                            <option value="Operations">Operations</option>
                        </select>
                    </div>
                    <div class="form-input-group">
                        <select id="new-clearance" required>
                            <option value="">Select Clearance</option>
                            <option value="public">Public</option>
                            <option value="confidential">Confidential</option>
                            <option value="secret">Secret</option>
                        </select>
                        <select id="new-location" required>
                            <option value="">Select Location</option>
                            <option value="internal">Internal</option>
                            <option value="external">External</option>
                        </select>
                    </div>
                    <button type="submit" class="form-submit-btn">Create User</button>
                    <div id="adduser-message" style="margin-top: 15px;"></div>
                </form>
            </div>
        </div>

        <!-- ACCESS MATRIX -->
        <div id="matrix" class="section">
            <div class="header">
                <span class="header-time" id="current-time-matrix"></span>
            </div>
            <div class="table-container">
                <table>
                    <thead id="matrix-table-head"></thead>
                    <tbody id="matrix-table-body"></tbody>
                </table>
            </div>
        </div>

        <!-- SECURITY LOGS -->
        <div id="logs" class="section">
            <div class="header">
                <h1><i class="bi bi-file-text"></i> Security Logs</h1>
                <span class="header-time" id="current-time-logs"></span>
            </div>
            <div id="logs-container"></div>
        </div>
    </div>
</div>

<!-- ACCESS MODAL -->
<div id="access-modal" class="access-modal hidden">
    <div class="access-modal-content">
        <button class="modal-close" onclick="closeAccessModal()">✕</button>
        <h2 id="modal-title">Resource Access</h2>
        <div id="modal-content"></div>
    </div>
</div>

<script>
let sessionData = null;
let pendingMfaUsername = null;   // tracks who is mid-MFA

// Mapping des permissions par rôle
const ROLE_PERMISSIONS = {
    "Admin": ["read", "write", "delete"],
    "Manager": ["read", "write"],
    "Employee": ["read"]
};

window.addEventListener('DOMContentLoaded', () => {
    document.querySelector('.main-container').style.display = 'none';
    document.getElementById('login-modal').style.display = 'flex';
});

// ─── STEP 1: Password ────────────────────────────────────────────────────────
async function performLogin(event) {
    event.preventDefault();
    
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const messageDiv = document.getElementById('login-message');
    
    if (!username || !password) {
        messageDiv.innerHTML = '<span style="color: #e74c3c;">❌ Username and password required</span>';
        return;
    }
    
    const btn = document.getElementById('login-submit-btn');
    btn.disabled = true;
    btn.textContent = 'Verifying...';
    messageDiv.innerHTML = '';

    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username, password})
        });
        
        const result = await response.json();
        
        if (response.ok && result.mfa_required) {
            // Password accepted — move to step 2
            pendingMfaUsername = result.username;
            document.getElementById('login-step-1').style.display = 'none';
            document.getElementById('login-step-2').style.display = 'block';
            document.getElementById('mfa-pin').value = '';
            document.getElementById('mfa-pin').focus();
        } else if (response.ok && result.status === 'success') {
            // MFA disabled fallback (should not happen in secure build)
            _completeLogin(result.user);
        } else {
            messageDiv.innerHTML = `<span style="color: #e74c3c;">❌ ${result.error || 'Login failed'}</span>`;
        }
    } catch (error) {
        console.error('Login error:', error);
        messageDiv.innerHTML = '<span style="color: #e74c3c;">❌ Connection error</span>';
    } finally {
        btn.disabled = false;
        btn.textContent = 'Login';
    }
}

// ─── STEP 2: MFA PIN ─────────────────────────────────────────────────────────
async function submitMfaCode(event) {
    event.preventDefault();

    const pin = document.getElementById('mfa-pin').value.trim();
    const messageDiv = document.getElementById('mfa-message');

    if (!pin || pin.length !== 6 || !/^[0-9]{6}$/.test(pin)) {
        messageDiv.innerHTML = '<span style="color:#e74c3c;">❌ Enter a valid 6-digit PIN</span>';
        return;
    }

    const btn = document.getElementById('mfa-submit-btn');
    btn.disabled = true;
    btn.textContent = 'Verifying PIN...';
    messageDiv.innerHTML = '';

    try {
        const response = await fetch('/api/login/mfa', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username: pendingMfaUsername, pin})
        });

        const result = await response.json();

        if (response.ok && result.status === 'success') {
            _completeLogin(result.user);
        } else {
            messageDiv.innerHTML = `<span style="color:#e74c3c;">❌ ${result.error || 'MFA verification failed'}</span>`;
            document.getElementById('mfa-pin').value = '';
            document.getElementById('mfa-pin').focus();
        }
    } catch (error) {
        console.error('MFA error:', error);
        messageDiv.innerHTML = '<span style="color:#e74c3c;">❌ Connection error</span>';
    } finally {
        btn.disabled = false;
        btn.textContent = 'Verify PIN';
    }
}

function cancelMfa() {
    pendingMfaUsername = null;
    document.getElementById('login-step-2').style.display = 'none';
    document.getElementById('login-step-1').style.display = 'block';
    document.getElementById('mfa-message').innerHTML = '';
    document.getElementById('login-message').innerHTML = '';
    document.getElementById('login-form').reset();
}

function _completeLogin(user) {
    sessionData = user;
    pendingMfaUsername = null;

    document.getElementById('login-modal').style.display = 'none';
    document.querySelector('.main-container').style.display = 'flex';

    // Reset both login steps for next time
    document.getElementById('login-step-1').style.display = 'block';
    document.getElementById('login-step-2').style.display = 'none';
    document.getElementById('login-form').reset();
    document.getElementById('mfa-pin').value = '';

    updateUserInfo();
    checkAdminAccess();
    loadResources();
    loadPolicies();
    loadStats();
    loadSecurityLogs();
    loadSystemStatus();
}

function performLogout() {
    sessionData = null;
    document.getElementById('login-modal').style.display = 'flex';
    document.querySelector('.main-container').style.display = 'none';
    document.getElementById('login-form').reset();
}

function togglePasswordVisibility() {
    const passwordInput = document.getElementById('password');
    const icon = document.getElementById('password-icon');
    
    if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        icon.classList.remove('bi-eye');
        icon.classList.add('bi-eye-slash');
    } else {
        passwordInput.type = 'password';
        icon.classList.remove('bi-eye-slash');
        icon.classList.add('bi-eye');
    }
}

function getPermissionsForRole(role) {
    const perms = ROLE_PERMISSIONS[role] || [];
    return perms;
}

function updateUserInfo() {
    if (sessionData) {
        document.getElementById('sidebar-username').textContent = sessionData.username;
        document.getElementById('sidebar-role').textContent = sessionData.role;
        document.getElementById('user-name').textContent = sessionData.username;
        document.getElementById('user-role').textContent = sessionData.role;
        document.getElementById('user-department').textContent = sessionData.department;
        document.getElementById('user-clearance').textContent = sessionData.clearance;
        
        const perms = getPermissionsForRole(sessionData.role);
        const permsHtml = perms.map(p => `<span class="permission-badge permission-${p}">${p}</span>`).join('');
        document.getElementById('user-permissions').innerHTML = permsHtml || '<span class="permission-badge">none</span>';
    }
}

function checkAdminAccess() {
    const isAdmin = sessionData && sessionData.role === 'Admin';
    const adminLinks = ['users-link', 'matrix-link', 'logs-link'];
    adminLinks.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.style.display = isAdmin ? 'block' : 'none';
    });
    
    if (isAdmin) {
        loadUsers();
        loadAccessMatrix();
    }
}

async function loadSystemStatus() {
    try {
        const response = await fetch('/api/system-status');
        const status = await response.json();
        
        const statusDiv = document.getElementById('system-status');
        const isBusinessHours = status.current_hour >= status.business_hours.start && 
                                status.current_hour < status.business_hours.end;
        
        statusDiv.innerHTML = `
            <h3>🕐 System Status</h3>
            <p><strong>Current time:</strong> ${new Date().toLocaleString()} (${status.current_hour}:00)</p>
            <p><strong>Business hours:</strong> ${status.business_hours.start}:00 - ${status.business_hours.end}:00</p>
            <p><strong>Status:</strong> ${isBusinessHours ? '✓ Within business hours' : '✗ Outside business hours'}</p>
            
        `;
        statusDiv.className = `card ${isBusinessHours ? '' : 'warning'}`;
    } catch (error) {
        console.error('Error loading system status:', error);
    }
}

async function loadResources() {
    try {
        const response = await fetch('/api/resources');
        const resources = await response.json();
        
        let html = '';
        for (const [id, resource] of Object.entries(resources)) {
            html += `
                <div class="resource-card">
                    <h4>${escapeHtml(resource.name)}</h4>
                    <p><strong>ID:</strong> ${escapeHtml(id)}</p>
                    <p><strong>Classification:</strong> <span class="classification-badge ${resource.classification}">${resource.classification}</span></p>
                    <p><strong>Department:</strong> ${escapeHtml(resource.department)}</p>
                    <div class="resource-actions">
                        <select id="op-${escapeHtml(id)}" class="op-select">
                            <option value="read">📖 Read</option>
                            <option value="write">✏️ Write</option>
                            <option value="delete">🗑️ Delete</option>
                        </select>
                        <button onclick="checkResourceAccess('${escapeHtml(id)}', document.getElementById('op-${escapeHtml(id)}').value)" class="action-btn">📋 Check Access</button>
                    </div>
                </div>
            `;
        }
        document.getElementById('resources-grid').innerHTML = html || '<p>No resources found</p>';
    } catch (error) {
        console.error('Error loading resources:', error);
    }
}

async function loadPolicies() {
    try {
        const response = await fetch('/api/policies');
        const policies = await response.json();
        
        let html = '';
        policies.forEach(policy => {
            html += `<tr><td>${escapeHtml(policy.id)}</td><td>${escapeHtml(policy.name)}</td><td>${escapeHtml(policy.description)}</td></tr>`;
        });
        document.getElementById('policies-table-body').innerHTML = html || '<tr><td colspan="4">No policies found</td></tr>';
    } catch (error) {
        console.error('Error loading policies:', error);
    }
}

async function loadStats() {
    try {
        const response = await fetch('/api/stats');
        const stats = await response.json();
        document.getElementById('stat-users').textContent = stats.total_users;
        document.getElementById('stat-resources').textContent = stats.total_resources;
        document.getElementById('stat-policies').textContent = stats.total_policies;
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

async function loadUsers() {
    try {
        const response = await fetch('/api/users');
        const users = await response.json();
        
        let html = '';
        for (const [username, user] of Object.entries(users)) {
            const perms = getPermissionsForRole(user.role);
            const permsHtml = perms.map(p => `<span class="permission-badge permission-${p}">${p}</span>`).join('');
            html += `<tr><td>${escapeHtml(username)}</td><td>${escapeHtml(user.role)}</td><td>${escapeHtml(user.department)}</td><td>${escapeHtml(user.clearance)}</td><td>${permsHtml}</td></tr>`;
        }
        document.getElementById('users-table-body').innerHTML = html || '<tr><td colspan="5">No users found</td></tr>';
    } catch (error) {
        console.error('Error loading users:', error);
    }
}

async function loadAccessMatrix() {
    try {
        const response = await fetch('/api/access-matrix', {method: 'POST'});
        const matrix = await response.json();
        const users = Object.keys(matrix).sort();
        const resources = users.length > 0 ? Object.keys(matrix[users[0]]).sort() : [];

        const thead = document.getElementById('matrix-table-head');
        const tbody = document.getElementById('matrix-table-body');
        thead.innerHTML = '';
        tbody.innerHTML = '';

        let headerRow = '<tr><th>User / Role</th>';
        resources.forEach(rid => { headerRow += `<th>${escapeHtml(rid)}</th>`; });
        headerRow += '</tr>';
        thead.innerHTML = headerRow;

        for (const uname of users) {
            let userRole = '?';
            try {
                const userResp = await fetch('/api/users');
                const usersData = await userResp.json();
                if (usersData[uname]) userRole = usersData[uname].role;
            } catch(e) {}
            
            let row = `<tr><td style="min-width:120px;"><strong>${escapeHtml(uname)}</strong><br><small>${userRole}</small></td>`;
            for (const rid of resources) {
                const access = matrix[uname][rid];
                const color = access.allowed ? '#2ecc71' : '#e74c3c';
                const text = access.allowed ? '✓' : '✗';
                row += `<td style="background:${color}33;color:${color};font-weight:bold;text-align:center;cursor:help;" title="${escapeHtml(access.reason || '')}">${text}${access.allowed ? ' ALLOW' : ' DENY'}</td>`;
            }
            row += '</tr>';
            tbody.innerHTML += row;
        }
    } catch (error) {
        console.error('Error loading access matrix:', error);
        document.getElementById('matrix-table-body').innerHTML = '<tr><td>Error loading matrix</td></tr>';
    }
}

async function loadSecurityLogs() {
    try {
        const response = await fetch('/api/logs');
        const logs = await response.json();
        
        let html = '';
        logs.forEach(log => {
            const allowed = log.allowed;
            const logClass = allowed ? 'allowed' : 'denied';
            const icon = allowed ? '✓' : '✗';
            html += `<div class="log-entry ${logClass}">
                        <span class="log-timestamp">${new Date(log.timestamp).toLocaleString()}</span> |
                        <span class="log-username">${escapeHtml(log.username)}</span> |
                        ${icon} ${escapeHtml(log.action)} on <strong>${escapeHtml(log.resource_id)}</strong> |
                        <strong>${escapeHtml(log.reason)}</strong>
                    </div>`;
        });
        document.getElementById('logs-container').innerHTML = html || '<p>No logs found</p>';
    } catch (error) {
        console.error('Error loading logs:', error);
    }
}

async function addNewUser(event) {
    event.preventDefault();
    
    const data = {
        username: document.getElementById('new-username').value,
        password: document.getElementById('new-password').value,
        role: document.getElementById('new-role').value,
        department: document.getElementById('new-department').value,
        clearance: document.getElementById('new-clearance').value,
        location: document.getElementById('new-location').value
    };
    
    try {
        const response = await fetch('/api/admin/add-user', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data)
        });
        
        const result = await response.json();
        const messageDiv = document.getElementById('adduser-message');
        
        if (response.ok) {
            messageDiv.innerHTML = `<span style="color: #2ecc71;">✓ ${escapeHtml(result.message)}</span>`;
            document.getElementById('new-username').value = '';
            document.getElementById('new-password').value = '';
            document.getElementById('new-role').value = '';
            document.getElementById('new-department').value = '';
            document.getElementById('new-clearance').value = '';
            document.getElementById('new-location').value = '';
            loadUsers();
            loadStats();
            if (sessionData && sessionData.role === 'Admin') {
                loadAccessMatrix();
            }
        } else {
            messageDiv.innerHTML = `<span style="color: #e74c3c;">❌ ${escapeHtml(result.error)}</span>`;
        }
    } catch (error) {
        console.error('Error adding user:', error);
        document.getElementById('adduser-message').innerHTML = '<span style="color: #e74c3c;">❌ Connection error</span>';
    }
}

async function checkResourceAccess(resourceId, operation) {
    if (!sessionData) {
        alert('Please login first');
        return;
    }
    
    try {
        const response = await fetch('/api/pdp/evaluate', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                user: {
                    role: sessionData.role,
                    department: sessionData.department,
                    clearance: sessionData.clearance,
                    location: sessionData.location
                },
                resource_id: resourceId,
                operation: operation
            })
        });
        
        const result = await response.json();
        
        const operationIcon = {
            'read': '📖',
            'write': '✏️',
            'delete': '🗑️'
        }[operation] || '📋';
        
        let html = `<h3>${operationIcon} ${escapeHtml(resourceId)} - ${operation.toUpperCase()}</h3>
                    <p><strong>Status:</strong> ${result.allowed ? '✓ ALLOWED' : '✗ DENIED'}</p>
                    <p><strong>Reason:</strong> ${escapeHtml(result.reason)}</p>`;
        
        if (result.context) {
            html += `<p><strong>Context:</strong> Hour: ${result.context.current_hour}:00 (Business hours: ${result.context.business_hours})</p>`;
        }
        
        if (result.rules_applied && result.rules_applied.length > 0) {
            html += '<h4>📜 Policy Evaluation Trace:</h4><ul>';
            result.rules_applied.forEach(rule => {
                const matchedClass = rule.matched ? 'style="color:#2ecc71"' : 'style="color:#e74c3c"';
                html += `<li ${matchedClass}>${escapeHtml(rule.policy_id)} (${rule.effect}): ${escapeHtml(rule.reason)}</li>`;
            });
            html += '</ul>';
        }
        
        document.getElementById('modal-content').innerHTML = html;
        document.getElementById('access-modal').classList.remove('hidden');
    } catch (error) {
        console.error('Error checking access:', error);
        document.getElementById('modal-content').innerHTML = '<p style="color:red;">Error checking access</p>';
        document.getElementById('access-modal').classList.remove('hidden');
    }
}

function closeAccessModal() {
    document.getElementById('access-modal').classList.add('hidden');
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/[&<>]/g, function(m) {
        if (m === '&') return '&amp;';
        if (m === '<') return '&lt;';
        if (m === '>') return '&gt;';
        return m;
    });
}

function showSection(event, sectionId) {
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
    document.getElementById(sectionId).classList.add('active');
    if (event && event.target) event.target.closest('.nav-link').classList.add('active');
    
    if (sectionId === 'matrix' && sessionData && sessionData.role === 'Admin') {
        loadAccessMatrix();
    }
}

function updateTime() {
    const now = new Date();
    const timeString = now.toLocaleTimeString('en-US');
    const timeIds = ['current-time-dashboard', 'current-time-resources', 'current-time-policies', 'current-time-users', 'current-time-matrix', 'current-time-logs'];
    timeIds.forEach(id => { const el = document.getElementById(id); if (el) el.textContent = timeString; });
}

setInterval(updateTime, 1000);
setInterval(loadSystemStatus, 60000);
updateTime();
</script>
</body>
</html>
"""

# ============================================================================
# FLASK APP INITIALIZATION
# ============================================================================

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'

log_lock = Lock()
session_data_store = {}

def load_json(filename):
    if not os.path.exists(filename):
        return {}
    with open(filename, 'r') as f:
        return json.load(f)

def save_json(filename, data):
    os.makedirs(os.path.dirname(filename) if os.path.dirname(filename) else '.', exist_ok=True)
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)

resources_data = load_json('resources.json').get('resources', {})
policies_json = load_json('policies.json')
policies_data = {p['id']: p for p in policies_json.get('policies', [])}

def get_users():
    return load_json('users.json').get('users', {})

print(f"✓ Loaded {len(get_users())} users")
print(f"✓ Loaded {len(resources_data)} resources")
print(f"✓ Loaded {len(policies_data)} policies")

if USE_REAL_PDP:
    pdp = PolicyDecisionPoint('policies.json')
    print(f"✓ PDP initialized with {len(pdp.policies)} policies")
    print(f"✓ Business hours: {config.ACCESS_START_HOUR}:00 - {config.ACCESS_END_HOUR}:00")

# ============================================================================
# HELPERS
# ============================================================================

def get_current_hour():
    return datetime.now().hour

def get_role_permissions(role):
    """Retourne les permissions d'un rôle selon config.py"""
    return config.ROLE_PERMISSIONS.get(role, [])

def verify_password(username, password):
    users_data = get_users()
    if username not in users_data:
        return False, None
    user = users_data[username]
    salt = user.get('salt', '')
    stored = user.get('password_hash', '')
    computed = hashlib.sha256(f"{password}:{salt}".encode()).hexdigest()
    return (computed == stored, user) if computed == stored else (False, None)

def log_access(username, resource_id, action, allowed, reason, rules_applied):
    with log_lock:
        entry = {
            'timestamp': datetime.now().isoformat(),
            'username': username,
            'resource_id': resource_id,
            'action': action,
            'allowed': allowed,
            'reason': reason,
            'rules_applied': rules_applied
        }
        os.makedirs('logs', exist_ok=True)
        with open('logs/security.log', 'a') as f:
            f.write(json.dumps(entry) + '\n')

def evaluate_with_pdp(username, resource_id, action, context=None):
    if context is None:
        context = {'hour_override': get_current_hour()}
    
    users_data = get_users()
    if username not in users_data:
        return False, "User not found", []
    
    user = users_data[username]
    resource = resources_data.get(resource_id, {})
    
    if not resource:
        return False, f"Resource {resource_id} not found", []
    
    user_attrs = {
        'username': username,
        'role': user.get('role'),
        'department': user.get('department'),
        'clearance': user.get('clearance'),
        'location': user.get('location')
    }
    
    resource_attrs = {
        'department': resource.get('department'),
        'classification': resource.get('classification')
    }
    
    if USE_REAL_PDP:
        decision, reason, trace = pdp.evaluate(user_attrs, resource_attrs, action, context)
        rules_applied = []
        for t in trace:
            rules_applied.append({
                'policy_id': t.get('check', 'UNKNOWN'),
                'effect': 'allow' if t.get('decision') == 'ALLOW' else 'deny',
                'matched': t.get('decision') == 'ALLOW',
                'reason': t.get('reason', ''),
            })
        allowed = (decision == 'ALLOW')
        return allowed, reason, rules_applied
    else:
        # Fallback selon config.py
        allowed_ops = get_role_permissions(user.get('role'))
        if action in allowed_ops:
            return True, f"Role {user.get('role')} has {action} permission", []
        return False, f"Role {user.get('role')} does not have {action} permission", []

# ============================================================================
# API ROUTES
# ============================================================================

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/resources')
def get_resources():
    return jsonify(resources_data)

@app.route('/api/policies')
def get_policies():
    result = []
    for pid, p in policies_data.items():
        result.append({
            'id': pid,
            'name': p.get('name', 'Unknown'),
            'description': p.get('description', ''),
           
            'priority': p.get('priority', 999)
        })
    return jsonify(result)

@app.route('/api/logs')
def get_logs():
    log_file = 'logs/security.log'
    if not os.path.exists(log_file):
        return jsonify([])
    logs = []
    try:
        with open(log_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        logs.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    except Exception as e:
        print(f"Error reading logs: {e}")
        return jsonify([])
    return jsonify(logs[-100:][::-1])

@app.route('/api/users')
def get_users_list():
    users_data = get_users()
    result = {}
    for username, user in users_data.items():
        result[username] = {
            'role': user.get('role'),
            'department': user.get('department'),
            'clearance': user.get('clearance'),
            'location': user.get('location'),
            'permissions': get_role_permissions(user.get('role'))
        }
    return jsonify(result), 200

@app.route('/api/stats')
def get_stats():
    return jsonify({
        'total_users': len(get_users()),
        'total_resources': len(resources_data),
        'total_policies': len(policies_data)
    })

@app.route('/api/system-status')
def system_status():
    return jsonify({
        'business_hours': {
            'start': config.ACCESS_START_HOUR,
            'end': config.ACCESS_END_HOUR
        },
        'current_hour': get_current_hour(),
        'role_permissions': config.ROLE_PERMISSIONS
    }), 200

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username', '').lower().strip()
    password = data.get('password', '')
    
    verified, user = verify_password(username, password)
    
    if not verified or not user:
        return jsonify({'error': 'Invalid username or password'}), 401

    if USE_MFA and mfa_manager:
        # Generate a 6-digit PIN and display it on the MFA terminal
        pin = mfa_manager.generate_pin(username)

        # Also print to this server's console so the "MFA terminal" (mfa_server.py) picks it up
        print(f"\n{'═'*52}")
        print(f"  🔐  MFA PIN for '{username}':  {pin}")
        print(f"  (valid for 120 seconds)")
        print(f"{'═'*52}\n", flush=True)

        return jsonify({
            'mfa_required': True,
            'username': username,
            'message': 'Password verified — please enter your MFA PIN'
        }), 200
    else:
        # MFA not available — fall back to direct login (development only)
        session_data_store['current_user'] = {
            'username': username,
            'role': user.get('role'),
            'department': user.get('department'),
            'clearance': user.get('clearance'),
            'location': user.get('location')
        }
        log_access(username, 'LOGIN', 'auth', True, 'User logged in (MFA disabled)', [])
        return jsonify({
            'status': 'success',
            'user': session_data_store['current_user']
        }), 200


@app.route('/api/login/mfa', methods=['POST'])
def login_mfa():
    """Step 2: verify the 6-digit PIN and complete the login session."""
    if not USE_MFA or not mfa_manager:
        return jsonify({'error': 'MFA not available'}), 503

    data = request.get_json()
    username = data.get('username', '').lower().strip()
    pin = str(data.get('pin', '')).strip()

    if not username or not pin:
        return jsonify({'error': 'username and pin required'}), 400

    ok, reason = mfa_manager.verify_pin(username, pin)
    if not ok:
        return jsonify({'error': reason}), 401

    # PIN correct — load user and create session
    users_data = get_users()
    if username not in users_data:
        return jsonify({'error': 'User not found'}), 401

    user = users_data[username]
    session_data_store['current_user'] = {
        'username': username,
        'role': user.get('role'),
        'department': user.get('department'),
        'clearance': user.get('clearance'),
        'location': user.get('location')
    }
    log_access(username, 'LOGIN', 'auth', True, 'User logged in via MFA', [])

    return jsonify({
        'status': 'success',
        'user': session_data_store['current_user']
    }), 200

@app.route('/api/pdp/evaluate', methods=['POST'])
def pdp_evaluate():
    data = request.get_json()
    
    user = data.get('user', {})
    resource_id = data.get('resource_id')
    operation = data.get('operation', 'read')
    
    if not user or not resource_id:
        return jsonify({'error': 'user and resource_id are required'}), 400
    
    username = session_data_store.get('current_user', {}).get('username', 'unknown')
    current_hour = get_current_hour()
    context = {'hour_override': current_hour}
    
    allowed, reason, rules_applied = evaluate_with_pdp(username, resource_id, operation, context)
    
    log_access(username, resource_id, operation, allowed, reason, rules_applied)
    
    return jsonify({
        'allowed': allowed,
        'reason': reason,
        'rules_applied': rules_applied,
        'context': {
            'current_hour': current_hour,
            'business_hours': f"{config.ACCESS_START_HOUR}:00-{config.ACCESS_END_HOUR}:00"
        }
    }), 200

@app.route('/api/access-matrix', methods=['POST'])
def access_matrix():
    matrix = {}
    users_data = get_users()
    current_hour = get_current_hour()
    context = {'hour_override': current_hour}
    
    for username in users_data.keys():
        matrix[username] = {}
        for resource_id in resources_data.keys():
            allowed, reason, _ = evaluate_with_pdp(username, resource_id, 'read', context)
            matrix[username][resource_id] = {'allowed': allowed, 'reason': reason}
    
    return jsonify(matrix), 200

@app.route('/mfa/pending', methods=['GET'])
def mfa_pending():
    result = []
    with mfa_manager._lock:
        for username, entry in list(mfa_manager._pending.items()):
            remaining = max(0, int(entry['expires_at'] - time.time()))
            if remaining > 0:
                result.append({
                    'username':   username,
                    'pin':        entry['pin'],
                    'expires_in': remaining,
                })
    return jsonify({'pending': result}), 200

@app.route('/api/admin/add-user', methods=['POST'])
def add_user():
    data = request.get_json()

    required = ['username', 'password', 'role', 'department', 'clearance', 'location']
    for field in required:
        if not data.get(field):
            return jsonify({'error': f'Missing field: {field}'}), 400

    username = data['username'].lower().strip()
    users_file = load_json('users.json')
    users = users_file.get('users', {})

    if username in users:
        return jsonify({'error': f"User '{username}' already exists"}), 409

    salt = uuid.uuid4().hex
    pw_hash = hashlib.sha256(f"{data['password']}:{salt}".encode()).hexdigest()

    users[username] = {
        'role': data['role'],
        'department': data['department'],
        'clearance': data['clearance'],
        'location': data['location'],
        'salt': salt,
        'password_hash': pw_hash
    }

    users_file['users'] = users
    save_json('users.json', users_file)
    log_access('ADMIN', f'ADD_USER:{username}', 'write', True, 'User created via admin panel', [])

    return jsonify({
        'status': 'success',
        'message': f"User '{username}' created successfully"
    }), 201

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    current_hour = get_current_hour()
    in_business_hours = (config.ACCESS_START_HOUR <= current_hour < config.ACCESS_END_HOUR)
    
    print("""
╔════════════════════════════════════════════════════════════════════╗
║                   Web Dashboard v8.0                               ║
╠════════════════════════════════════════════════════════════════════╣           ║
╠════════════════════════════════════════════════════════════════════╣
║  🕐 Current system time: {:02d}:00                                 
║  🏢 Business hours: {}:00 - {}:00                                 
║  📋 Status: {}                                                     
╠════════════════════════════════════════════════════════════════════╣
╠════════════════════════════════════════════════════════════════════╣
║  🚀 Navigate to http://localhost:{}                                   
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝
    """.format(current_hour, config.ACCESS_START_HOUR, config.ACCESS_END_HOUR, 
               "WITHIN BUSINESS HOURS ✓" if in_business_hours else "OUTSIDE BUSINESS HOURS ⚠",
               config.APP_PORT))
    
    app.run(debug=True, host='0.0.0.0', port=config.APP_PORT)