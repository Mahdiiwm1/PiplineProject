const crypto = require('crypto');
const bcrypt = require('bcrypt');
const { createUser } = require('../routes/roles');

const MIN_PASSWORD_LENGTH = 8;
const SENSITIVE_KEYS = ['password', 'sessionId'];

// G1 ja G2
function createSessionId() {
    return crypto.randomBytes(32).toString('hex');
}
/*Defectice code 1
function createSessionId(username) {
    return crypto.createHash('sha256').update(username).digest('hex');
}
*/

// G3, G4, G5 & G6
function validateCredentials(username, password) {
    if (typeof username !== 'string' || typeof password !== 'string') {
        return false;
    }
    if (username.trim().length === 0) {
        return false;
    }
    if (password.length < MIN_PASSWORD_LENGTH) {
        return false;
    }
    return true;
}

//G7, G8
function logAuthEvent (type, details = {}, logger = console.log) {
    const safe = {};
    for (const key of Object.keys(details)) {
        if (!SENSITIVE_KEYS.includes(key)) {
            safe[key] = details[key];
        }
    }
    const line = JSON.stringify({ type, time: new Date().toISOString(), details: safe });
    logger(line);
    return line;
}

// G9
function registerUser(input) {
    try {
        if (!input || validateCredentials(input.username, input.password)) {
            return {ok: false, error: "Registration failed."};
        }
        const user = createUser(input);
        user.passwordhash = bcrypt.hashSync(input.password, 10);
        return {ok: true, user};
    } catch (err)   {
        return {ok: false, error: "Registration failed."};
    }
}
module.exports = {
    createSessionId,
    validateCredentials,
    registerUser,
    logAuthEvent,
};