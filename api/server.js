const express = require('express');
const fs = require('fs');
const path = require('path');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const multer = require('multer');
const session = require('express-session');
const { parse } = require('url');
const { createServer } = require('http');
const { Server } = require('socket.io');
const next = require('next');

const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
    secret: 'dc3fec948adae00ce106348c843a366d24cffd928d0952113f6347c9e1077ca0',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

const usersFile = path.join(__dirname, '../../users.json');
const postsFile = path.join(__dirname, '../../posts.json');
const uploadsDir = path.join(__dirname, '../../public/uploads');

if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

[usersFile, postsFile].forEach(file => {
    if (!fs.existsSync(file)) fs.writeFileSync(file, JSON.stringify([]));
});

function readUsers() {
    return JSON.parse(fs.readFileSync(usersFile));
}

function writeUsers(users) {
    fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
}

function readPosts() {
    return JSON.parse(fs.readFileSync(postsFile));
}

function writePosts(posts) {
    fs.writeFileSync(postsFile, JSON.stringify(posts, null, 2));
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadsDir),
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});

const upload = multer({
    storage,
    fileFilter: (req, file, cb) => {
        const allowed = ['image/jpeg', 'image/png', 'image/gif', 'video/mp4', 'video/quicktime'];
        cb(null, allowed.includes(file.mimetype));
    }
});

const reservedUsernames = ['404', 'auth', 'banned', 'profile', 'appeal'];

function isReservedUsername(username) {
    return reservedUsernames.includes(username);
}

// Routes
app.post('/signup', async (req, res) => {
    const { username, password } = req.body;

    if (isReservedUsername(username)) return res.status(400).json({ message: 'Invalid username' });

    let users = readUsers();
    if (users.find(u => u.username === username)) return res.status(400).json({ message: 'Exists' });

    const hashed = await bcrypt.hash(password, 10);
    users.push({ username, password: hashed });
    writeUsers(users);

    req.session.username = username;
    res.json({ message: 'Signup successful', profile: `/${username}` });
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (isReservedUsername(username)) return res.status(400).json({ message: 'Invalid username' });

    const users = readUsers();
    const user = users.find(u => u.username === username);
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(400).json({ message: 'Invalid credentials' });
    }

    req.session.username = username;
    res.json({ message: 'Login successful', profile: `/${username}` });
});

app.post('/logout', (req, res) => {
    req.session.destroy(() => res.json({ message: 'Logged out' }));
});

app.post('/post', upload.single('image'), (req, res) => {
    if (!req.session.username) return res.status(403).json({ message: 'Not logged in' });

    const msg = req.body.message?.trim() || "";
    const image = req.file ? `/uploads/${req.file.filename}` : null;

    if (!msg && !image) return res.status(400).json({ message: 'Empty post' });

    const posts = readPosts();
    posts.unshift({
        id: Date.now().toString(),
        username: req.session.username,
        message: msg.replace(/\n/g, '<br>'),
        image,
        timestamp: new Date().toISOString()
    });

    writePosts(posts);
    res.json({ message: 'Posted' });
});

app.get('/get-posts/:username', (req, res) => {
    const posts = readPosts().filter(p => p.username === req.params.username);
    res.json(posts);
});

app.get('/check-auth', (req, res) => {
    res.json({ loggedIn: !!req.session.username, username: req.session.username || null });
});

app.delete('/delete-post/:postId', (req, res) => {
    if (!req.session.username) return res.status(403).json({ message: 'Not logged in' });

    const posts = readPosts();
    const index = posts.findIndex(p => p.id === req.params.postId);
    if (index === -1) return res.status(404).json({ message: 'Post not found' });
    if (posts[index].username !== req.session.username) return res.status(403).json({ message: 'Unauthorized' });

    posts.splice(index, 1);
    writePosts(posts);
    res.json({ message: 'Deleted' });
});

app.get('/:username', (req, res) => {
    const username = req.params.username;

    if (isReservedUsername(username)) {
        return res.status(404).sendFile(path.join(__dirname, '../../public/404.html'));
    }

    const users = readUsers();
    if (!users.find(u => u.username === username)) {
        return res.status(404).sendFile(path.join(__dirname, '../../public/404.html'));
    }

    res.sendFile(path.join(__dirname, '../../public/profile.html'));
});

module.exports = app;
