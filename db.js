const mysql = require('mysql2/promise');
require('dotenv').config({ path: '.env.local' });


const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    database: 'bgezewfvzq0jjws5duno',
    password: process.env.DB_PASS || '',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
})

module.exports = pool