//G10a
function createUser(input) {
    if (input === null || typeof input !== 'object') {
        return null;
    }
    return {username: input.username, role: "user"};
}

//G10b, G10c & G10d
function isAdmin(user) {
    return user !== null && typeof user === 'object' && user.role === 'admin';
}

module.exports = { createUser, isAdmin };