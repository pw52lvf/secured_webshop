const mysql = require('mysql2');
const bcrypt = require('bcrypt');

const db = mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'secure_webshop'
});

exports.login = async (req, res) => {
    try {
        const { username, password } = req.body;

        // Check if user exists
        db.query(
            'SELECT * FROM Users WHERE Username = ?',
            [username],
            async (error, results) => {
                if (error) {
                    console.error('Database error:', error);
                    return res.status(500).json({ error: 'Internal server error' });
                }

                if (results.length === 0) {
                    return res.status(401).json({ error: 'Invalid credentials' });
                }

                // Compare password
                const match = await bcrypt.compare(password, results[0].Password);
                
                if (!match) {
                    return res.status(401).json({ error: 'Invalid credentials' });
                }

                // Set session
                req.session.userId = results[0].id;
                req.session.isAdmin = results[0].isAdmin;

                // Redirect based on user role
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