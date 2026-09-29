const express = require('express');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const db = require('../database');
const router = express.Router();

const { validateCredentials, createSessionId, logAuthEvent } = require('../routes/authUtils')
const { createUser } = require ('../routes/roles')


router.get('/login', (req, res) => {
    res.render('login', { title: 'Login' });
});

router.post('/login', (req, res) => {
    const { username, password } = req.body;

    if (!validateCredentials(username, password)) {
        logAuthEvent('login_failed', { username });
        return res.render('login', { title: 'Login', error: 'Invalid username or password' });
    }

    db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
        if (err) throw err;
        if (user && bcrypt.compareSync(password, user.password)) {
            const sessionId = createSessionId();
            db.run("UPDATE users SET sessionId = ? WHERE username = ?", [sessionId, user.username], (err) => {
                if (err) throw err;
                res.cookie('sessionId', sessionId, { httpOnly: true });
                logAuthEvent('login_success', { username });
                res.redirect('/');
            });
        } else {
            logAuthEvent('login_failed', { username });
            res.render('login', { title: 'Login', error: 'Invalid username or password' });
        }
    });
});

router.get('/register', (req, res) => {
    res.render('register', { title: 'Register' });
});

router.post('/register', (req, res) => {
    const { username, password } = req.body;

    if (!validateCredentials(username, password)) {
        return res.render('register', { title: 'Register', error: 'Invalid username or password' });
    }

    const hashedPassword = bcrypt.hashSync(password, 10);
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, existingUser) => {
        if (err) throw err;
        if (!existingUser) {
            const user = createUser({ username });
            db.run(
                "INSERT INTO users (username, password, sessionId, role) VALUES (?, ?, ?, ?)",
                [user.username, hashedPassword, 0, user.role],
                (err) => {
                    if (err) throw err;
                }
            );
        }
        res.redirect('/auth/login');
    });
});

router.get('/logout', (req, res) => {
    res.clearCookie('sessionId');
    res.redirect('/auth/login');
});

module.exports = router;
