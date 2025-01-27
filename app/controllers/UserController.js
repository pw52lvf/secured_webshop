const path = require('path');
 
module.exports = {
    get: (req, res) => {
        res.sendFile(path.join(__dirname, '../pages/user.html'));
    },
    post: (req, res) => {
        res.sendFile(path.join(__dirname, '../pages/user.html'));
    }
};
 