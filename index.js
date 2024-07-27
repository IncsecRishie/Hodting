const express = require('express');
const bodyParser = require('body-parser');
const { exec } = require('child_process');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const app = express();
const USERS_FILE = './users.json';
const RAM_LIMIT_DIR = '/sys/fs/cgroup/memory';

app.use(bodyParser.json());
app.use(express.static('public'));

// Initialize users file if not exists
if (!fs.existsSync(USERS_FILE)) {
  fs.writeFileSync(USERS_FILE, JSON.stringify([]));
}

// Helper functions
const loadUsers = () => JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
const saveUsers = (users) => fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));

// Authentication middleware
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).send('Access denied');
  }

  const [username, password] = Buffer.from(authHeader.split(' ')[1], 'base64').toString().split(':');
  const users = loadUsers();
  const user = users.find(u => u.username === username);

  if (user && bcrypt.compareSync(password, user.password)) {
    req.user = user;
    next();
  } else {
    res.status(401).send('Access denied');
  }
};

// Admin endpoint to create users
app.post('/create-user', authenticate, (req, res) => {
  if (!req.user.isAdmin) {
    return res.status(403).send('Access denied');
  }

  const { username, password, ram } = req.body;

  if (!username || !password || !ram) {
    return res.status(400).send('Username, password, and RAM allocation are required');
  }

  exec(`sudo useradd -m -s /bin/bash ${username} && echo "${username}:${password}" | sudo chpasswd`, (err) => {
    if (err) {
      return res.status(500).send(`Error creating user: ${err.message}`);
    }

    // Create cgroup for RAM allocation
    exec(`sudo mkdir -p ${RAM_LIMIT_DIR}/${username} && sudo echo "${ram}" | sudo tee ${RAM_LIMIT_DIR}/${username}/memory.limit_in_bytes`, (err) => {
      if (err) {
        return res.status(500).send(`Error setting RAM limit: ${err.message}`);
      }

      res.send(`User ${username} created with ${ram} bytes RAM allocation.`);
    });
  });
});

// Admin endpoint to list users
app.get('/users', authenticate, (req, res) => {
  if (!req.user.isAdmin) {
    return res.status(403).send('Access denied');
  }

  exec('cut -d: -f1 /etc/passwd', (err, stdout) => {
    if (err) {
      return res.status(500).send(`Error listing users: ${err.message}`);
    }

    const users = stdout.split('\n').filter(user => user && user !== 'root');
    res.json(users);
  });
});

// Web pages for login and admin panel
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Start the web server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
