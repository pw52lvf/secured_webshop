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

            // Compare password with hashed password in database
            bcrypt.compare(Password, results[0].Password, (err, isMatch) => {
                if (err) {
                    console.error('Comparison error:', err);
                    return res.status(500).json({ error: 'Internal server error' });
                }
                
                if (!isMatch) {
                    return res.status(401).json({ error: 'Invalid credentials' });
                }
                
                // Login successful
                req.session.userId = results[0].id;
                req.session.isAdmin = results[0].isAdmin;
                
                if (results[0].isAdmin) {
                    res.redirect('/admin.html');
                } else {
                    res.redirect('/user.html');
                }
            });
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

app.get('/api/users', (req, res) => {
    // Get search term from query parameter
    const searchTerm = req.query.search || '';
    
    // Check if user is logged in as admin (using session for now since JWT might not be fully set up)
    if (!req.session.isAdmin) {
        return res.status(403).json({ error: 'Unauthorized - Admin access required' });
    }
    
    // Use parameterized query to prevent SQL injection
    let query = 'SELECT id, Username, isAdmin FROM Users';
    let params = [];
    
    // Add WHERE clause if search term is provided
    if (searchTerm) {
        query += ' WHERE Username LIKE ?';
        params.push(`%${searchTerm}%`);
    }
    
    // Execute the query
    db.query(query, params, (error, results) => {
        if (error) {
            console.error('Database error:', error);
            return res.status(500).json({ error: 'Internal server error' });
        }
        
        // Return the results
        res.json(results);
    });
});

app.get('/api/user-stats', (req, res) => {
    // Check if user is logged in as admin
    if (!req.session.isAdmin) {
        return res.status(403).json({ error: 'Unauthorized - Admin access required' });
    }
    
    // Get total users count
    db.query('SELECT COUNT(*) as totalUsers FROM Users', (error, totalResults) => {
        if (error) {
            console.error('Database error:', error);
            return res.status(500).json({ error: 'Internal server error' });
        }
        
        // Get admin count
        db.query('SELECT COUNT(*) as adminCount FROM Users WHERE isAdmin = 1', (error, adminResults) => {
            if (error) {
                console.error('Database error:', error);
                return res.status(500).json({ error: 'Internal server error' });
            }
            
            // Set new users to 0 for now (you can implement actual calculation later)
            const newUsers = 0;
            
            // Return the stats
            res.json({
                totalUsers: totalResults[0].totalUsers,
                adminCount: adminResults[0].adminCount,
                newUsers: newUsers
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
            
            // Hash the password
            bcrypt.hash(Password, saltRounds, (err, hashedPassword) => {
                if (err) {
                    console.error('Hashing error:', err);
                    return res.status(500).json({ error: 'Password hashing failed' });
                }
                
                // Get the maximum ID to generate a new one
                db.query('SELECT MAX(id) as maxId FROM Users', (error, results) => {
                    if (error) {
                        console.error('Database error:', error);
                        return res.status(500).json({ error: 'Internal server error' });
                    }
                    
                    // Generate a new ID safely
                    let newId = 1; // Default to 1 if table is empty
                    if (results[0].maxId !== null) {
                        newId = parseInt(results[0].maxId) + 1;
                    }
                    
                    // Insert new user with hashed password
                    db.query(
                        'INSERT INTO Users (id, Username, Password, isAdmin) VALUES (?, ?, ?, 0)',
                        [newId, Username, hashedPassword],
                        (error, results) => {
                            if (error) {
                                console.error('Database error:', error);
                                return res.status(500).json({ error: 'Internal server error' });
                            }
                            
                            // Redirect to login page after successful signup
                            res.redirect('/login');
                        }
                    );
                });
            });
        }
    );
});

// Add this route to serve the signup page
app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'pages', 'signup.html'));
});

// First, install the required packages:
// npm install jsonwebtoken crypto

// Add these requires to your server.js
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Secret key for JWT signing - store this in an environment variable in production
const JWT_SECRET = 'your-secret-key-should-be-long-and-random';

// Custom password hashing function (as required by the project)
function customHashPassword(password, salt) {
    // Using SHA-256 for hashing, but you could use other algorithms
    const hash = crypto.createHash('sha256');
    const saltedPassword = password + salt;
    hash.update(saltedPassword);
    return hash.digest('hex');
}

// Generate a random salt
function generateSalt() {
    return crypto.randomBytes(16).toString('hex');
}

// Middleware to verify JWT token
function authenticateJWT(req, res, next) {
    const token = req.session.token || req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Unauthorized - No token provided' });
    }

    try {
        // Verify the token
        const decoded = jwt.verify(token, JWT_SECRET);
        
        // Add user info to request object
        req.user = decoded;
        
        next();
    } catch (error) {
        console.error('Token verification error:', error);
        return res.status(403).json({ error: 'Forbidden - Invalid token' });
    }
}

// Middleware to check admin role
function isAdmin(req, res, next) {
    if (!req.user || !req.user.isAdmin) {
        return res.status(403).json({ error: 'Forbidden - Admin access required' });
    }
    next();
}

// Modified login route with JWT
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

            const user = results[0];
            let isPasswordValid;
            
            // Option to use either custom hash or bcrypt (as per your project requirements)
            const useBcrypt = false; // Change this as needed

            if (useBcrypt) {
                // This part would use bcrypt when you implement it later
                // bcrypt.compare(Password, user.Password, (err, result) => { ... });
                isPasswordValid = (Password === user.Password); // Temporary placeholder
            } else {
                // Custom hash verification
                // Assuming the password in DB is stored as "hash:salt"
                const [storedHash, salt] = user.Password.split(':');
                const calculatedHash = customHashPassword(Password, salt);
                isPasswordValid = (calculatedHash === storedHash);
            }

            if (!isPasswordValid) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }
            
            // Create JWT token
            const token = jwt.sign(
                { 
                    id: user.id,
                    username: user.Username,
                    isAdmin: user.isAdmin 
                }, 
                JWT_SECRET,
                { expiresIn: '1h' } // Token expires in 1 hour
            );
            
            // Store token in session
            req.session.token = token;
            req.session.userId = user.id;
            req.session.isAdmin = user.isAdmin;
            
            // Redirect based on user role
            if (user.isAdmin) {
                res.redirect('/admin.html');
            } else {
                res.redirect('/user.html');
            }
        }
    );
});

// Modified signup route with custom password hashing
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
            
            // Generate a salt and hash the password
            const salt = generateSalt();
            const hashedPassword = customHashPassword(Password, salt);
            
            // Get the maximum ID to generate a new one
            db.query('SELECT MAX(id) as maxId FROM Users', (error, results) => {
                if (error) {
                    console.error('Database error:', error);
                    return res.status(500).json({ error: 'Internal server error' });
                }
                
                // Generate a new ID safely
                let newId = 1; // Default to 1 if table is empty
                if (results[0].maxId !== null) {
                    newId = parseInt(results[0].maxId) + 1;
                }
                
                // Insert new user with hashed password
                db.query(
                    'INSERT INTO Users (id, Username, Password, isAdmin) VALUES (?, ?, ?, 0)',
                    [newId, Username, `${hashedPassword}:${salt}`], // Store as "hash:salt"
                    (error, results) => {
                        if (error) {
                            console.error('Database error:', error);
                            return res.status(500).json({ error: 'Internal server error' });
                        }
                        
                        // Redirect to login page after successful signup
                        res.redirect('/login');
                    }
                );
            });
        }
    );
});

// Protected route example - gets user profile
app.get('/api/users/:username', authenticateJWT, (req, res) => {
    // Get the requested username
    const requestedUsername = req.params.username;
    
    // Check if the user is trying to access their own profile or is an admin
    if (req.user.username !== requestedUsername && !req.user.isAdmin) {
        return res.status(403).json({ error: 'Access denied' });
    }
    
    // Get user data
    db.query(
        'SELECT id, Username, isAdmin FROM Users WHERE Username = ?',
        [requestedUsername],
        (error, results) => {
            if (error) {
                console.error('Database error:', error);
                return res.status(500).json({ error: 'Internal server error' });
            }
            
            if (results.length === 0) {
                return res.status(404).json({ error: 'User not found' });
            }
            
            // Return user data (excluding password)
            res.json(results[0]);
        }
    );
});

// Admin route example - search users
app.get('/api/users', authenticateJWT, isAdmin, (req, res) => {
    const searchTerm = req.query.search || '';
    
    // Use parameterized query to prevent SQL injection
    db.query(
        'SELECT id, Username, isAdmin FROM Users WHERE Username LIKE ?',
        [`%${searchTerm}%`],
        (error, results) => {
            if (error) {
                console.error('Database error:', error);
                return res.status(500).json({ error: 'Internal server error' });
            }
            
            res.json(results);
        }
    );
});

// Logout route
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).send('Error logging out');
        }
        res.redirect('/login');
    });
});