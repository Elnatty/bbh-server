const express = require('express');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware to parse JSON and URL-encoded data
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.raw({ type: 'application/octet-stream', limit: '10mb' }));

// Custom logging middleware
app.use((req, res, next) => {
    const timestamp = new Date().toISOString();
    const logEntry = {
        timestamp,
        method: req.method,
        url: req.url,
        headers: req.headers,
        query: req.query,
        body: req.body,
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent'),
        referer: req.get('Referer') || 'none',
        contentType: req.get('Content-Type') || 'none'
    };
    
    console.log('=== REQUEST LOG ===');
    console.log(JSON.stringify(logEntry, null, 2));
    console.log('==================');
    
    next();
});

// Root endpoint with vulnerability testing menu
app.get('/', (req, res) => {
    res.send(`
        <html>
            <head>
                <title>Bug Bounty Vulnerability Test Server</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 40px; }
                    .vuln-section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; }
                    .vuln-title { color: #d32f2f; font-weight: bold; }
                    a { color: #1976d2; text-decoration: none; margin-right: 10px; }
                    form { margin: 10px 0; }
                    input, textarea { margin: 5px; padding: 5px; }
                </style>
            </head>
            <body>
                <h1>🎯 Bug Bounty Vulnerability Test Server</h1>
                <p><strong>All requests are logged with full details!</strong></p>
                
                <div class="vuln-section">
                    <div class="vuln-title">XSS (Cross-Site Scripting)</div>
                    <a href="/xss/reflected?input=<script>alert('XSS')</script>">Reflected XSS Test</a>
                    <a href="/xss/dom">DOM XSS Test</a>
                    <form method="POST" action="/xss/stored">
                        <input type="text" name="comment" placeholder="Enter comment for stored XSS">
                        <button type="submit">Submit Stored XSS</button>
                    </form>
                </div>

                <div class="vuln-section">
                    <div class="vuln-title">SQL Injection</div>
                    <a href="/sqli?id=1' OR '1'='1">Basic SQLi Test</a>
                    <a href="/sqli/blind?id=1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--">Blind SQLi</a>
                    <form method="POST" action="/sqli/login">
                        <input type="text" name="username" placeholder="admin' --">
                        <input type="password" name="password" placeholder="password">
                        <button type="submit">Login SQLi Test</button>
                    </form>
                </div>

                <div class="vuln-section">
                    <div class="vuln-title">Command Injection</div>
                    <a href="/rce?cmd=whoami">RCE Test</a>
                    <form method="POST" action="/rce/upload">
                        <input type="text" name="filename" placeholder="test.txt; cat /etc/passwd">
                        <button type="submit">File Command Injection</button>
                    </form>
                </div>

                <div class="vuln-section">
                    <div class="vuln-title">Path Traversal / LFI</div>
                    <a href="/lfi?file=../../../etc/passwd">LFI Test</a>
                    <a href="/download?file=../../../../etc/hosts">Path Traversal</a>
                </div>

                <div class="vuln-section">
                    <div class="vuln-title">XXE (XML External Entity)</div>
                    <form method="POST" action="/xxe" enctype="application/xml">
                        <textarea name="xml" placeholder='<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/passwd">]><data>&file;</data>'></textarea>
                        <button type="submit">XXE Test</button>
                    </form>
                </div>

                <div class="vuln-section">
                    <div class="vuln-title">SSRF (Server-Side Request Forgery)</div>
                    <a href="/ssrf?url=http://localhost:22">SSRF Port Scan</a>
                    <a href="/ssrf?url=http://169.254.169.254/latest/meta-data/">AWS Metadata</a>
                    <form method="POST" action="/ssrf/webhook">
                        <input type="text" name="callback_url" placeholder="http://attacker.com/callback">
                        <button type="submit">SSRF Webhook</button>
                    </form>
                </div>

                <div class="vuln-section">
                    <div class="vuln-title">CSRF (Cross-Site Request Forgery)</div>
                    <form method="POST" action="/csrf/transfer">
                        <input type="text" name="amount" placeholder="1000">
                        <input type="text" name="to_account" placeholder="attacker_account">
                        <button type="submit">Transfer Money (No CSRF Token)</button>
                    </form>
                </div>

                <div class="vuln-section">
                    <div class="vuln-title">File Upload Vulnerabilities</div>
                    <form method="POST" action="/upload/image" enctype="multipart/form-data">
                        <input type="file" name="image" accept="image/*">
                        <button type="submit">Upload Image</button>
                    </form>
                    <form method="POST" action="/upload/unrestricted" enctype="multipart/form-data">
                        <input type="file" name="file">
                        <button type="submit">Upload Any File</button>
                    </form>
                </div>

                <div class="vuln-section">
                    <div class="vuln-title">Insecure Direct Object Reference (IDOR)</div>
                    <a href="/user/profile?id=1">User Profile 1</a>
                    <a href="/user/profile?id=2">User Profile 2</a>
                    <a href="/admin/users?user_id=1">Admin Panel</a>
                </div>

                <div class="vuln-section">
                    <div class="vuln-title">Authentication Bypass</div>
                    <a href="/admin/panel">Admin Panel (No Auth)</a>
                    <form method="POST" action="/login/weak">
                        <input type="text" name="username" placeholder="admin">
                        <input type="password" name="password" placeholder="123456">
                        <button type="submit">Weak Login</button>
                    </form>
                </div>

                <div class="vuln-section">
                    <div class="vuln-title">Open Redirect</div>
                    <a href="/redirect?url=http://evil.com">Open Redirect Test</a>
                </div>

                <div class="vuln-section">
                    <div class="vuln-title">Information Disclosure</div>
                    <a href="/debug">Debug Info</a>
                    <a href="/config">Config File</a>
                    <a href="/.env">Environment Variables</a>
                    <a href="/phpinfo">PHP Info</a>
                </div>
            </body>
        </html>
    `);
});

// XSS Endpoints
app.get('/xss/reflected', (req, res) => {
    const input = req.query.input || '';
    res.send(`<h1>Reflected XSS Test</h1><p>You entered: ${input}</p>`);
});

app.get('/xss/dom', (req, res) => {
    res.send(`
        <h1>DOM XSS Test</h1>
        <script>
            const params = new URLSearchParams(window.location.search);
            const input = params.get('input');
            if (input) {
                document.body.innerHTML += '<p>Input: ' + input + '</p>';
            }
        </script>
    `);
});

app.post('/xss/stored', (req, res) => {
    const comment = req.body.comment || '';
    res.send(`<h1>Stored XSS Test</h1><p>Comment stored: ${comment}</p>`);
});

// SQL Injection Endpoints
app.all('/sqli', (req, res) => {
    const id = req.query.id || req.body.id || '1';
    res.json({
        message: 'SQL Injection Test',
        query: `SELECT * FROM users WHERE id = ${id}`,
        vulnerable: true,
        input: id
    });
});

app.all('/sqli/blind', (req, res) => {
    const id = req.query.id || req.body.id || '1';
    // Simulate blind SQL injection
    const delay = id.includes('SLEEP') || id.includes('WAITFOR') ? 5000 : 0;
    setTimeout(() => {
        res.json({ message: 'Blind SQL Injection Test', delay: delay + 'ms' });
    }, delay);
});

app.post('/sqli/login', (req, res) => {
    const { username, password } = req.body;
    res.json({
        message: 'Login SQL Injection Test',
        query: `SELECT * FROM users WHERE username='${username}' AND password='${password}'`,
        vulnerable: true
    });
});

// Command Injection / RCE Endpoints
app.all('/rce', (req, res) => {
    const cmd = req.query.cmd || req.body.cmd || 'echo "test"';
    res.json({
        message: 'RCE Test (Simulated)',
        command: cmd,
        result: 'Command execution simulated (not actually executed)',
        vulnerable: true
    });
});

app.post('/rce/upload', (req, res) => {
    const filename = req.body.filename || 'test.txt';
    res.json({
        message: 'File Command Injection Test',
        filename: filename,
        command: `touch ${filename}`,
        vulnerable: true
    });
});

// Path Traversal / LFI Endpoints
app.get('/lfi', (req, res) => {
    const file = req.query.file || 'index.html';
    res.json({
        message: 'Local File Inclusion Test',
        requested_file: file,
        vulnerable: true,
        content: 'File content would be displayed here'
    });
});

app.get('/download', (req, res) => {
    const file = req.query.file || 'safe.txt';
    res.json({
        message: 'Path Traversal Test',
        requested_file: file,
        vulnerable: true
    });
});

// XXE Endpoint
app.post('/xxe', (req, res) => {
    const xml = req.body.xml || req.body;
    res.json({
        message: 'XXE Test',
        received_xml: xml,
        vulnerable: true,
        note: 'XML parsing simulated'
    });
});

// SSRF Endpoints
app.get('/ssrf', (req, res) => {
    const url = req.query.url || 'http://example.com';
    res.json({
        message: 'SSRF Test',
        target_url: url,
        vulnerable: true,
        result: 'Request would be made to: ' + url
    });
});

app.post('/ssrf/webhook', (req, res) => {
    const callback_url = req.body.callback_url || '';
    res.json({
        message: 'SSRF Webhook Test',
        callback_url: callback_url,
        vulnerable: true
    });
});

// CSRF Endpoint
app.post('/csrf/transfer', (req, res) => {
    const { amount, to_account } = req.body;
    res.json({
        message: 'CSRF Test - Money Transfer',
        amount: amount,
        to_account: to_account,
        vulnerable: true,
        note: 'No CSRF token validation'
    });
});

// File Upload Endpoints
app.post('/upload/image', (req, res) => {
    res.json({
        message: 'Image Upload Test',
        content_type: req.get('Content-Type'),
        vulnerable: true,
        note: 'File upload simulated'
    });
});

app.post('/upload/unrestricted', (req, res) => {
    res.json({
        message: 'Unrestricted File Upload Test',
        content_type: req.get('Content-Type'),
        vulnerable: true,
        note: 'No file type restrictions'
    });
});

// IDOR Endpoints
app.get('/user/profile', (req, res) => {
    const id = req.query.id || '1';
    res.json({
        message: 'IDOR Test - User Profile',
        user_id: id,
        vulnerable: true,
        profile: `Private data for user ${id}`
    });
});

app.get('/admin/users', (req, res) => {
    const user_id = req.query.user_id || '1';
    res.json({
        message: 'IDOR Test - Admin Panel',
        accessing_user: user_id,
        vulnerable: true,
        admin_data: 'Sensitive admin information'
    });
});

// Authentication Bypass
app.get('/admin/panel', (req, res) => {
    res.json({
        message: 'Authentication Bypass Test',
        admin_panel: true,
        vulnerable: true,
        note: 'No authentication required'
    });
});

app.post('/login/weak', (req, res) => {
    const { username, password } = req.body;
    res.json({
        message: 'Weak Authentication Test',
        username: username,
        password: password,
        authenticated: true,
        vulnerable: true
    });
});

// Open Redirect
app.get('/redirect', (req, res) => {
    const url = req.query.url || 'https://example.com';
    res.json({
        message: 'Open Redirect Test',
        redirect_url: url,
        vulnerable: true,
        note: 'Would redirect to: ' + url
    });
});

// Information Disclosure Endpoints
app.get('/debug', (req, res) => {
    res.json({
        message: 'Debug Information Disclosure',
        server_info: {
            node_version: process.version,
            platform: process.platform,
            memory_usage: process.memoryUsage(),
            uptime: process.uptime()
        },
        vulnerable: true
    });
});

app.get('/config', (req, res) => {
    res.json({
        message: 'Configuration File Disclosure',
        config: {
            database_host: 'localhost',
            database_user: 'admin',
            database_password: 'secret123',
            api_key: 'sk-1234567890abcdef'
        },
        vulnerable: true
    });
});

app.get('/.env', (req, res) => {
    res.type('text/plain').send(`
DB_HOST=localhost
DB_USER=admin
DB_PASSWORD=supersecret
API_KEY=sk-very-secret-key
JWT_SECRET=my-jwt-secret
    `);
});

app.get('/phpinfo', (req, res) => {
    res.json({
        message: 'PHP Info Disclosure (Simulated)',
        php_version: '8.1.0',
        loaded_extensions: ['mysqli', 'curl', 'openssl'],
        vulnerable: true
    });
});

// Catch-all endpoint for any other requests
app.all('*', (req, res) => {
    res.status(404).json({
        message: 'Endpoint not found but request logged!',
        path: req.path,
        method: req.method,
        timestamp: new Date().toISOString(),
        note: 'This could be useful for directory bruteforcing tests'
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.log('=== ERROR LOG ===');
    console.log('Error:', err.message);
    console.log('Stack:', err.stack);
    console.log('Request:', {
        method: req.method,
        url: req.url,
        headers: req.headers,
        body: req.body
    });
    console.log('=================');
    
    res.status(500).json({
        error: 'Internal server error',
        message: err.message,
        stack: err.stack, // Information disclosure in error
        timestamp: new Date().toISOString(),
        vulnerable: true
    });
});

app.listen(PORT, () => {
    console.log(`🎯 Bug bounty vulnerability server running on port ${PORT}`);
    console.log('All requests are logged with full details');
    console.log('Available vulnerability categories:');
    console.log('- XSS (Reflected, DOM, Stored)');
    console.log('- SQL Injection (Basic, Blind, Login)');
    console.log('- Command Injection / RCE');
    console.log('- Path Traversal / LFI');
    console.log('- XXE');
    console.log('- SSRF');
    console.log('- CSRF');
    console.log('- File Upload');
    console.log('- IDOR');
    console.log('- Authentication Bypass');
    console.log('- Open Redirect');
    console.log('- Information Disclosure');
});
