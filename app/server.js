const express = require("express");
const path = require('path');

const app = express();
const userRoute = require('./routes/User');
app.use('/user', userRoute);



// Démarrage du serveur
app.listen(8080, () => {
    console.log('Server running on port 8080');
});

app.use(express.static(path.join(__dirname, 'pages')));
 
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'pages', 'index.html'));
});