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