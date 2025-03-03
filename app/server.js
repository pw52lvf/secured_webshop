// server.js
const express = require("express");
const path = require('path');
const mysql = require('mysql2');
const fs = require('fs');
const https = require('https');
const session = require('express-session');

const sslOptions = {
  key: fs.readFileSync("./privkey.key"),
  cert: fs.readFileSync("./certificate.crt")
};

const app = express();

// Add middleware for parsing request bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Add session middleware
app.use(session({
    secret: 'your-secret-key', // Change this to a real secret key
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: true, // Because you're using HTTPS
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Serve static files
app.use(express.static(path.join(__dirname, 'pages')));

// Database connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'root',
    database: 'secure_webshop',
    port: 6033
});

db.connect((err) => {
    if (err) {
        console.error('Database connection failed:', err);
    } else {
        console.log('Connected to database');
    }
});

// Routes
const userRoute = require('./routes/User');
app.use('/user', userRoute);

app.post('/auth/login', (req, res) => {
    const { Username, Password } = req.body;
    
    db.query(
        'SELECT * FROM Users WHERE Username = ?',
        [Username],
        (error, results) => {
            if (error) {
                console.error('Database error:', error);
                return res.status(500).json({ error: 'Internal server error' });
            }

            if (results.length === 0) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            // For now, comparing password directly
            // In production, you should use bcrypt.compare()
            if (Password === results[0].Password) {
                req.session.userId = results[0].id;
                req.session.isAdmin = results[0].isAdmin;
                
                if (results[0].isAdmin) {
                    res.redirect('/admin.html');
                } else {
                    res.redirect('/user.html');
                }
            } else {
                res.status(401).json({ error: 'Invalid credentials' });
            }
        }
    );
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'pages', 'index.html'));
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'pages', 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

// Start HTTPS server
https.createServer(sslOptions, app).listen(443, () => {
    console.log("Server running on port 443");
});