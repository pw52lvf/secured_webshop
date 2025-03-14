const mysql = require('mysql2');
const crypto = require('crypto');

const db = mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'secure_webshop'
});

function generateSalt(length = 16) {
    return crypto.randomBytes(length).toString('hex');
}

function hashPassword(password, salt) {
    let hash = password;
    const iterations = 1000;
    
    for (let i = 0; i < iterations; i++) {
        const hmac = crypto.createHmac('sha256', salt);
        hmac.update(hash);
        hash = hmac.digest('hex');
    }
    
    return hash;
}

function verifyPassword(password, salt, storedHash) {
    const hashedAttempt = hashPassword(password, salt);
    return hashedAttempt === storedHash;
}

exports.login = async (req, res) => {
    try {
        const { username, password } = req.body;

        db.query(
            'SELECT * FROM Users WHERE Username = ?',
            [username],
            (error, results) => {
                if (error) {
                    console.error('Database error:', error);
                    return res.status(500).json({ error: 'Internal server error' });
                }

                if (results.length === 0) {
                    return res.status(401).json({ error: 'Invalid credentials' });
                }

                const salt = results[0].Salt;
                const storedHash = results[0].Password;
                const match = verifyPassword(password, salt, storedHash);
                
                if (!match) {
                    return res.status(401).json({ error: 'Invalid credentials' });
                }

                req.session.userId = results[0].id;
                req.session.isAdmin = results[0].isAdmin;

                if (results[0].isAdmin) {
                    res.redirect('/admin/dashboard');
                } else {
                    res.redirect('/user/dashboard');
                }
            }
        );
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};

exports.register = async (req, res) => {
    try {
        const { username, password, email } = req.body;

        db.query(
            'SELECT * FROM Users WHERE Username = ?',
            [username],
            (error, results) => {
                if (error) {
                    console.error('Database error:', error);
                    return res.status(500).json({ error: 'Internal server error' });
                }

                if (results.length > 0) {
                    return res.status(400).json({ error: 'Username already exists' });
                }

                const salt = generateSalt();
                const hashedPassword = hashPassword(password, salt);
                
                db.query(
                    'INSERT INTO Users (Username, Password, Email, Salt, isAdmin) VALUES (?, ?, ?, ?, false)',
                    [username, hashedPassword, email, salt],
                    (error, results) => {
                        if (error) {
                            console.error('Registration error:', error);
                            return res.status(500).json({ error: 'Error registering user' });
                        }
                        
                        res.status(201).json({ message: 'User registered successfully' });
                    }
                );
            }
        );
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};

exports.testCustomEncryption = () => {
    const password = "testPassword123";
    console.log("Original password:", password);
    
    const salt = generateSalt();
    console.log("Generated salt:", salt);
    
    const hashedPassword = hashPassword(password, salt);
    console.log("Hashed password:", hashedPassword);
    
    const isValid = verifyPassword(password, salt, hashedPassword);
    console.log("Password verification:", isValid ? "Successful" : "Failed");
    
    const wrongResult = verifyPassword("wrongPassword", salt, hashedPassword);
    console.log("Wrong password test:", wrongResult ? "Failed (should be rejected)" : "Successful (correctly rejected)");
    
    return { salt, hashedPassword, isValid };
};