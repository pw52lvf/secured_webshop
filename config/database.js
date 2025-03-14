const mysql = require('mysql2');

const pool = mysql.createPool({
    host: 'db',
    user: 'root',
    password: 'your_password',
    database: 'secure_webshop',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

const promisePool = pool.promise();

module.exports = promisePool;