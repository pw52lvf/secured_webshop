const express = require("express");
const path = require('path');
const mysql = require('mysql2');
const fs = require('fs');
const https = require('https');
const session = require('express-session');

const bcrypt = require('bcrypt');
const saltRounds = 10;

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
// Add this to your server.js file

// Update this API endpoint to match your actual database schema
app.get('/api/users', (req, res) => {
    // Check if user is admin
    if (!req.session.isAdmin) {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    
    // Query the database for all users - adjust the columns to match your actual table
    db.query(
        'SELECT id, Username, isAdmin FROM Users', // Remove 'Email' from here
        (error, results) => {
            if (error) {
                console.error('Database error:', error);
                return res.status(500).json({ error: 'Internal server error' });
            }
            
            // Add empty email field to each result for compatibility with the frontend
            const usersWithEmail = results.map(user => ({
                ...user,
                Email: '' // Add an empty Email field
            }));
            
            // Return the results as JSON
            res.json(usersWithEmail);
        }
    );
});

app.get('/api/user-stats', (req, res) => {
    // Check if user is admin
    if (!req.session.isAdmin) {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    
    // Get total users
    db.query('SELECT COUNT(*) as totalUsers FROM Users', (error, totalResults) => {
        if (error) {
            return res.status(500).json({ error: 'Internal server error' });
        }
        
        // Get admin count
        db.query('SELECT COUNT(*) as adminCount FROM Users WHERE isAdmin = 1', (error, adminResults) => {
            if (error) {
                return res.status(500).json({ error: 'Internal server error' });
            }
            
            // Return stats without the newUsers query
            res.json({
                totalUsers: totalResults[0].totalUsers,
                adminCount: adminResults[0].adminCount,
                newUsers: 0 // Set to 0 since we don't have createdAt
            });
        });
    });
});

// Add this to your server.js file

// API endpoint to delete a user
app.delete('/api/users/:id', (req, res) => {
    // Check if user is admin
    if (!req.session.isAdmin) {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const userId = req.params.id;
    
    // Prevent admins from deleting themselves
    if (parseInt(userId) === req.session.userId) {
        return res.status(400).json({ error: 'Cannot delete your own account' });
    }
    
    // Delete the user
    db.query(
        'DELETE FROM Users WHERE id = ?',
        [userId],
        (error, results) => {
            if (error) {
                console.error('Database error:', error);
                return res.status(500).json({ error: 'Internal server error' });
            }
            
            if (results.affectedRows === 0) {
                return res.status(404).json({ error: 'User not found' });
            }
            
            res.json({ message: 'User deleted successfully' });
        }
    );
});

// Add this to your server.js file

// Logout route
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).send('Error logging out');
        }
        res.redirect('/login');
    });
});

// Add this route to handle user signup
app.post('/auth/signup', (req, res) => {
    const { Username, Password } = req.body;
    
    // Check if username already exists
    db.query(
        'SELECT * FROM Users WHERE Username = ?',
        [Username],
        (error, results) => {
            if (error) {
                console.error('Database error:', error);
                return res.status(500).json({ error: 'Internal server error' });
            }
            
            if (results.length > 0) {
                return res.status(400).json({ error: 'Username already exists' });
            }
            
            // Insert new user
            // Note: In production, you should hash the password using bcrypt
            db.query(
                'INSERT INTO Users (Username, Password, isAdmin) VALUES (?, ?, 0)',
                [Username, Password],
                (error, results) => {
                    if (error) {
                        console.error('Database error:', error);
                        return res.status(500).json({ error: 'Internal server error' });
                    }
                    
                    // Redirect to login page after successful signup
                    res.redirect('/login');
                }
            );
        }
    );
});

// Add this route to serve the signup page
app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'pages', 'signup.html'));
});