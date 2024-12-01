const express = require("express");
const fs = require("fs");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const bodyParser = require("body-parser");
const cors = require("cors");

const app = express();

const PORT = 5000;
const SECRET_KEY = "mysecretkey";

app.use(bodyParser.json());
app.use(cors());

function authenticateToken(req, res, next) {
  const token = req.headers["authorization"];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendstatus(403);
    req.user = user;
    next();
  });
}

app.get('/',(req, res)=>{
  res.send('Welcome to jwt auth and file handling');
  res.end();
})
// Registration Route
app.post("/register", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).send("Missing fields");

  fs.readFile("users.json", "utf8", (err, data) => {
    let users = err ? [] : JSON.parse(data);
    if (users.find((user) => user.username === username)) {
      return res.status(400).send("User already exists");
    }

    bcrypt.hash(password, 10, (err, hash) => {
      users.push({ username, password: hash });
      fs.writeFile("users.json", JSON.stringify(users), (err) => {
        if (err) return res.status(500).send("Error saving user");
        res.status(201).send("User registered");
      });
    });
  });
});

// Login Route
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).send("Missing fields");

  fs.readFile("users.json", "utf8", (err, data) => {
    let users = err ? [] : JSON.parse(data);
    const user = users.find((user) => user.username === username);
    if (!user) return res.status(400).send("Invalid credentials");

    bcrypt.compare(password, user.password, (err, result) => {
      if (!result) return res.status(400).send("Invalid credentials");
      const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: "1h" });
      res.json({ token });
    });
  });
});

// Protected Route to Save Data
app.post("/save", authenticateToken, (req, res) => {
  const { data } = req.body;
  if (!data) return res.status(400).send("No data provided");

  fs.writeFile("data.json", JSON.stringify(data), (err) => {
    if (err) return res.status(500).send("Error saving data");
    res.send("Data saved");
  });
});

// Protected Route to Read Data
app.get("/read", authenticateToken, (req, res) => {
  fs.readFile("users.json", "utf8", (err, data) => {
    if (err) return res.status(500).send("Error reading data");
    res.json(JSON.parse(data));
  });
});

app.listen(PORT, () =>
  console.log(`Server running on http://localhost:${PORT}`)
);
