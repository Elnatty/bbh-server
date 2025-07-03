const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware to parse JSON and URL-encoded data
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

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
        referer: req.get('Referer') || 'none'
    };
    
    // Log to console (visible in Render logs)
    console.log('=== REQUEST LOG ===');
    console.log(JSON.stringify(logEntry, null, 2));
    console.log('==================');
    
    next();
});

// Root endpoint
app.get('/', (req, res) => {
    res.send(`
        <html>
            <head><title>Bug Bounty Test Server</title></head>
            <body>
                <h1>Bug Bounty Test Server</h1>
                <p>Server is running and logging all requests!</p>
                <h2>Test Endpoints:</h2>
                <ul>
                    <li><a href="/test">GET /test</a></li>
                    <li><a href="/vulnerable?param=test">GET /vulnerable</a></li>
                    <li>POST /submit (for form testing)</li>
                    <li>Any other path (catch-all)</li>
                </ul>
                <h2>Test Form:</h2>
                <form method="POST" action="/submit">
                    <input type="text" name="username" placeholder="Username">
                    <input type="password" name="password" placeholder="Password">
                    <input type="hidden" name="csrf_token" value="fake_token">
                    <button type="submit">Submit</button>
                </form>
            </body>
        </html>
    `);
});

// Test endpoint
app.get('/test', (req, res) => {
    res.json({
        message: 'Test endpoint hit!',
        timestamp: new Date().toISOString(),
        yourIP: req.ip,
        parameters: req.query
    });
});

// Vulnerable endpoint (for testing)
app.all('/vulnerable', (req, res) => {
    const param = req.query.param || req.body.param || 'none';
    res.json({
        message: 'Vulnerable endpoint',
        echo: param, // Potential XSS/injection point
        method: req.method,
        allParams: { ...req.query, ...req.body }
    });
});

// Form submission endpoint
app.post('/submit', (req, res) => {
    res.json({
        message: 'Form submitted successfully',
        received: req.body,
        timestamp: new Date().toISOString()
    });
});

// File upload endpoint (multipart support)
app.post('/upload', (req, res) => {
    res.json({
        message: 'Upload endpoint hit',
        contentType: req.get('Content-Type'),
        body: req.body
    });
});

// Catch-all endpoint for any other requests
app.all('*', (req, res) => {
    res.status(404).json({
        message: 'Endpoint not found but request logged!',
        path: req.path,
        method: req.method,
        timestamp: new Date().toISOString()
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
        timestamp: new Date().toISOString()
    });
});

app.listen(PORT, () => {
    console.log(`Bug bounty server running on port ${PORT}`);
    console.log('All requests will be logged to console');
});
