const express = require("express");
const path = require('path');
const mysql = require('mysql2');
const fs = require('fs');
const https = require('https');
const session = require('express-session');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const sslOptions = {
  key: fs.readFileSync("./privkey.key"),
  cert: fs.readFileSync("./certificate.crt")
};

const JWT_SECRET = 'your-secret-key-should-be-long-and-random';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'pages')));

app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: true,
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000
    }
}));

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

function customHashPassword(password, salt) {
    let hash = password;
    const iterations = 1000;
    
    for (let i = 0; i < iterations; i++) {
        const hmac = crypto.createHmac('sha256', salt);
        hmac.update(hash);
        hash = hmac.digest('hex');
    }
    
    return hash;
}

function generateSalt() {
    return crypto.randomBytes(16).toString('hex');
}

function authenticateJWT(req, res, next) {
    const token = req.session.token || req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Unauthorized - No token provided' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        console.error('Token verification error:', error);
        return res.status(403).json({ error: 'Forbidden - Invalid token' });
    }
}

function isAdmin(req, res, next) {
    if (!req.user || !req.user.isAdmin) {
        return res.status(403).json({ error: 'Forbidden - Admin access required' });
    }
    next();
}

const userRoute = require('./routes/User');
app.use('/user', userRoute);

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'pages', 'index.html'));
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'pages', 'index.html'));
});

app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'pages', 'signup.html'));
});

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
            
            const storedHash = user.Password;
            const salt = user.Salt;
            
            const calculatedHash = customHashPassword(Password, salt);
            const isPasswordValid = (calculatedHash === storedHash);

            if (!isPasswordValid) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }
            
            const token = jwt.sign(
                { 
                    id: user.id,
                    username: user.Username,
                    isAdmin: user.isAdmin 
                }, 
                JWT_SECRET,
                { expiresIn: '1h' }
            );
            
            req.session.token = token;
            req.session.userId = user.id;
            req.session.isAdmin = user.isAdmin;
            
            if (user.isAdmin) {
                res.redirect('/admin.html');
            } else {
                res.redirect('/user.html');
            }
        }
    );
});

app.post('/auth/signup', (req, res) => {
    const { Username, Password } = req.body;
    
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
            
            const salt = generateSalt();
            const hashedPassword = customHashPassword(Password, salt);
            
            db.query('SELECT MAX(id) as maxId FROM Users', (error, results) => {
                if (error) {
                    console.error('Database error:', error);
                    return res.status(500).json({ error: 'Internal server error' });
                }
                
                let newId = 1;
                if (results[0].maxId !== null) {
                    newId = parseInt(results[0].maxId) + 1;
                }
                
                db.query(
                    'INSERT INTO Users (id, Username, Password, Salt, isAdmin) VALUES (?, ?, ?, ?, 0)',
                    [newId, Username, hashedPassword, salt],
                    (error, results) => {
                        if (error) {
                            console.error('Database error:', error);
                            return res.status(500).json({ error: 'Internal server error' });
                        }
                        
                        res.redirect('/login');
                    }
                );
            });
        }
    );
});

app.get('/api/users/:username', authenticateJWT, (req, res) => {
    const requestedUsername = req.params.username;
    
    if (req.user.username !== requestedUsername && !req.user.isAdmin) {
        return res.status(403).json({ error: 'Access denied' });
    }
    
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
            
            res.json(results[0]);
        }
    );
});

app.get('/api/users', authenticateJWT, isAdmin, (req, res) => {
    const searchTerm = req.query.search || '';
    
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

app.delete('/api/users/:id', authenticateJWT, isAdmin, (req, res) => {
    const userId = req.params.id;
    
    if (parseInt(userId) === req.user.id) {
        return res.status(400).json({ error: 'Cannot delete your own account' });
    }
    
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

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).send('Error logging out');
        }
        res.redirect('/login');
    });
});

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

https.createServer(sslOptions, app).listen(443, () => {
    console.log("Server running on port 443");
});