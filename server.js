const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const express = require('express');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const helmet = require('helmet');
require('dotenv').config();

const app = express();
app.use(express.json());

// TASK 3: SECURITY HEADERS (Helmet & CSP)
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
        },
    }
}));// TASK 3: CSRF Protection Middleware Configuration
app.use(cookieParser());
const csrfProtection = csrf({ cookie: true });

// TASK 2: API SECURITY (Rate Limiting)
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Max 5 requests per 15 mins for testing
    message: { error: "Too many requests! You have been rate-limited." }
});
app.use('/api/', limiter);

// TASK 2: CORS Configuration
app.use(cors({
    origin: 'http://localhost:3000' 
}));

// TASK 2: API Key Authentication Middleware
const verifyApiKey = (req, res, next) => {
    const userKey = req.header('X-API-KEY');
    const correctKey = process.env.MY_SECRET_KEY;

    if (!userKey || userKey !== correctKey) {
        return res.status(401).json({ error: "Access Denied: Invalid or missing API Key!" });
    }
    next(); 
};

// Secured Endpoint
app.get('/api/data', verifyApiKey, (req, res) => {
    res.json({ message: "Congratulations! You successfully bypassed the security layers." });
});
// ==========================================
// WEEK 5: ETHICAL HACKING & EXPLOITATION TEST ROUTES
// ==========================================

// TASK 2: Simulating a Vulnerable SQL Route (String Concatenation)
app.get('/api/vulnerable-user', (req, res) => {
    const userId = req.query.id;
    // VULNERABLE: Attackers use SQLMap here because it directly strings input together
    const insecureQuery = `SELECT * FROM users WHERE id = '${userId}'`; 
    
    res.json({ 
        status: "Vulnerable Endpoint Active", 
        executedQuery: insecureQuery,
        patch: "To fix this, use parameterization placeholders: ?, [userId]" 
    });
});

// TASK 2: The Secure Fixed Route (Prepared Statements Simulation)
app.get('/api/secure-user', (req, res) => {
    const userId = req.query.id;
    // SECURE: Database engine compiles the query structure first, ignoring input tricks
    const secureQuery = "SELECT * FROM users WHERE id = ?"; 
    
    res.json({ 
        status: "Secured Endpoint Active", 
        executedQuery: secureQuery,
        sanitizedValues: [userId]
    });
});

// TASK 3: Unprotected Profile Route (Vulnerable to CSRF)
app.post('/api/update-profile', (req, res) => {
    res.json({ status: "Success", message: "Profile updated without any CSRF validation tokens!" });
});

// TASK 3: Secure Profile Route (Protected via CSRF Token validation)
app.post('/api/secure-update-profile', csrfProtection, (req, res) => {
    res.json({ status: "Success", message: "Profile altered securely. CSRF Token validated successfully!" });
// TASK 3: Token Delivery Route (Required to fetch token before testing mutation routes)
app.get('/api/get-csrf-token', csrfProtection, (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});
app.listen(3000, () => console.log("Security server is running on port 3000"));