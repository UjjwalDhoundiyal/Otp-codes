//src/config/db.ts
import mysql from 'mysql2/promise';

// Configured with a connection pool for production-grade request handling
export const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'voltstartev',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});
