//const path = require('path');
 
module.exports = {
    get: (req, res) => {
        res.sendFile(path.join(__dirname, '../pages/user.html'));
    },
    post: (req, res) => {
        res.sendFile(path.join(__dirname, '../pages/user.html'));
    }
};
 
const path = require('path');
const mysql = require('mysql2');

// Create database connection
//const db = mysql.createConnection({
//    host: 'db',
//    user: 'root',
//    password: 'root',
//    database: 'secure_webshop'
//});
//
//module.exports = {
//    get: (req, res) => {
//        res.sendFile(path.join(__dirname, '../pages/user.html'));
//    },
//
//    post: (req, res) => {
//        const { Username, Password } = req.body;
//
//        if (!Username || !Password) {
//            return res.status(400).json({ error: 'Username and password are required' });
//        }
//
//        // Query the database to check user credentials
//        db.query(
//            'SELECT * FROM Users WHERE Username = ? AND Password = ?',
//            [Username, Password],
//            (error, results) => {
//                if (error) {
//                    console.error('Database error:', error);
//                    return res.status(500).json({ error: 'Internal server error' });
//                }
//
//                if (results.length > 0) {
//                    // User found - successful login
//                    const user = results[0];
//                    if (user.isAdmin) {
//                        res.sendFile(path.join(__dirname, '../pages/admin.html'));
//                    } else {
//                        res.sendFile(path.join(__dirname, '../pages/user.html'));
//                    }
//                } else {
//                    // No user found - invalid credentials
//                    res.status(401).json({ error: 'Invalid username or password' });
//                }
//            }
//        );
//    }
//};