// server.js
const express = require("express");
const path = require('path');
const mysql = require('mysql2');
const fs = require('fs');
const https = require('https');

const sslOptions = {
  key: fs.readFileSync("./privkey.key"),
  cert: fs.readFileSync("./certificate.crt")
};

const app = express();
const userRoute = require('./routes/User');
app.use('/user', userRoute);



// Démarrage du serveur
//app.listen(443, () => {
//    console.log('Server running on port 443');
//});
https.createServer(sslOptions, app).listen(443, () =>{
  console.log("Server running on port 443");
});

app.use(express.static(path.join(__dirname, 'pages')));
 
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'pages', 'index.html'));
});