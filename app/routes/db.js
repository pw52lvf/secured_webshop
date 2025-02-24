const mysql = require("mysql2");
 
const connection = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "root",
    database: "db",
    port: 6033,
});
 
connection.connect((err) => {
    if (err) throw err;
    console.log("Connected to MySQL Database!");
});
 
module.exports = connection;