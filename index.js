const express = require("express");
const fs = require("fs");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const bodyParser = require("body-parser");
const cors = require("cors");
const path = require("path");
const app = express();

const PORT = 5000;


app.use(bodyParser.json());
app.use(cors({ origin: 'https://transcendent-cupcake-d74797.netlify.app/'}));

function ensureUsersFile() {
    if (!fs.existsSync(USERS_FILE)) {
        fs.writeFileSync(USERS_FILE, JSON.stringify([]));
    }
}
app.get('/',(req, res)=>{
  res.send('Welcome to jwt auth and file handling');
  res.end();
})

app.use(express.json());

const SECRET_KEY = 'your_secret_key';
const USERS_FILE = '/tmp/users.json'; // Use /tmp for writing

// Middleware for JWT Authentication
function authenticateToken(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// Helper to ensure users.json exists
function ensureUsersFile() {
    if (!fs.existsSync(USERS_FILE)) {
        fs.writeFileSync(USERS_FILE, JSON.stringify([]));
    }
}

// Registration Route
app.post('/register', (req, res) => {
    ensureUsersFile();
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).send('Missing fields');

    const users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    if (users.find(user => user.username === username)) {
        return res.status(400).send('User already exists');
    }

    bcrypt.hash(password, 10, (err, hash) => {
        users.push({ username, password: hash });
        fs.writeFileSync(USERS_FILE, JSON.stringify(users));
        res.status(201).send('User registered');
    });
});

// Login Route
app.post('/login', (req, res) => {
    ensureUsersFile();
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).send('Missing fields');

    const users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    const user = users.find(user => user.username === username);
    if (!user) return res.status(400).send('Invalid credentials');

    bcrypt.compare(password, user.password, (err, result) => {
        if (!result) return res.status(400).send('Invalid credentials');
        const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });
        res.json({ token });
    });
});

// Protected Route to Save Data
app.post('/save', authenticateToken, (req, res) => {
    const { data } = req.body;
    if (!data) return res.status(400).send('No data provided');

    const filePath = path.join('/tmp', 'data.json');
    fs.writeFileSync(filePath, JSON.stringify(data));
    res.send('Data saved');
});

// Protected Route to Read Data
app.get('/read', authenticateToken, (req, res) => {
    const filePath = path.join('/tmp', 'data.json');
    if (!fs.existsSync(filePath)) {
        return res.status(404).send('No data found');
    }
    const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    res.json(data);
});

module.exports = (req, res) => {
    app(req, res); // Pass Vercel request to Express
};


app.listen(PORT, () =>
  console.log(`Server running on http://localhost:${PORT}`)
);
