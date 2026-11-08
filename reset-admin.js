require('dotenv').config();
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');

async function resetAdmin() {
  console.log('Connecting to database...');
  
  const connection = await mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
  });

  // Generate clean bcrypt hash
  const newHash = await bcrypt.hash('admin123', 10);
  console.log('New hash generated successfully.');

  // Check if admin exists
  const [rows] = await connection.execute('SELECT * FROM users WHERE email = ?', ['admin@school.edu']);

  if (rows.length === 0) {
    // Insert fresh admin user
    await connection.execute(
      `INSERT INTO users (full_name, email, password_hash, role) 
       VALUES (?, ?, ?, 'admin')`,
      ['System Administrator', 'admin@school.edu', newHash]
    );
    console.log('SUCCESS: Admin user created!');
  } else {
    // Update existing admin password
    await connection.execute(
      'UPDATE users SET password_hash = ? WHERE email = ?',
      [newHash, 'admin@school.edu']
    );
    console.log('SUCCESS: Admin password updated!');
  }

  await connection.end();
}

resetAdmin().catch(err => {
  console.error('ERROR:', err.message);
});