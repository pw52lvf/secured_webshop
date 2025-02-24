const jwt = require('jsonwebtoken');
 
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) {
        return res.status(403).send({ error: 'No token provided' });
    }
 
    jwt.verify(token, 'your_secret_key', (err, decoded) => {
        if (err) {
            return res.status(500).send({ error: 'Failed to authenticate token' });
        }
        req.userId = decoded.id;
        next();
    });
};
 
module.exports = verifyToken;