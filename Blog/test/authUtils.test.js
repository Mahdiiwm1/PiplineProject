const { 
    validateCredentials,
    registerUser,
    logAuthEvent,
    createSessionId
} = require('../routes/authUtils.js');

const request = require('supertest');
const app = require('../app');
const crypto = require('crypto');

const {
    createUser,
    isAdmin
} = require( '../routes/roles');

// G1: Two session IDs for the same user are different (S)
describe("G1: Two session IDs for the same user are different.", () => {
    test("output cannot be reproduced by hashing a known value", () => {
        const id = createSessionId();
        const guessableHash = crypto.createHash('sha256').update('anyUsername').digest('hex');
        expect(id).not.toBe(guessableHash);
    });
    test("createSessionId returns a different value each time", () => {
        const id1 = createSessionId();
        const id2 = createSessionId();
        expect(id1).not.toBe(id2);
    });
});

// G2: Session ID is 64 hex characters, not a hash of the username (S)
describe("G2: Session ID format.", () => {
    test("is 64 hex characters long.", () => {
        const id = createSessionId();
        expect(id).toMatch(/^[0-9a-f]{64}$/);
    });
});

// G3: Empty or whitespace-only username is rejected (T)
describe("G3: Empty username.", () =>{
    test("Empty string returns false", () =>{
        const username = "";
        const password = "Secret123";

        const result = validateCredentials(username, password);
        expect(result).toBe(false);
    });

    test("Spaces only as string returns false.", () =>{
        const result = validateCredentials("   ", "Secret123");
        expect(result).toBe(false);
    });
});

// G4: Missing or null password is rejected (T)
describe("G4: missing or null password", () => {
    test("null password returns false.", ()=> {
        const result = validateCredentials("mahdi", null);
        expect(result).toBe(false);
    });

    test("undefined password returns false.", ()=> {
        const result = validateCredentials("mahdi", undefined);
        expect(result).toBe(false);
    });

    test("missing password argument returns false.", ()=> {
        const result = validateCredentials("mahdi");
        expect(result).toBe(false);
    });
});

// G5: Password length boundary, 7 fails and 8 passes (T)
describe("G5: Password length boundary.", ()=> {
    test("7 characters returns false", () =>{
        const result = validateCredentials("mahdi", "1234567");
        expect(result).toBe(false);
    });

    test("8 characters return true", () => {
        const result = validateCredentials("mahdi", "12345678");
        expect(result).toBe(true);
    });
});

// G6: Wrong data types for username or password are rejected (T)
describe("G6: wrong data types", () => {
    test("numbers as usernames returns false", () => {
        const username = 12345;
        const result = validateCredentials(username, "mamosa123");
        expect(result).toBe(false);
    });

    test("object as username returns false", () => {
        const result = validateCredentials({username: "mamosa"}, "mamosa123");
        expect(result).toBe(false);
    });

    test("number as password returns false", () => {
        const result = validateCredentials("mamosa", 12345678);
        expect(result).toBe(false);
    });
});

// G7: Failed login is logged (R)
describe("G7: failed login is logged", () => {
    test("logger is called with the event type and username", () => {
        const fakeLogger = jest.fn();
        logAuthEvent("login_failed", { username: "mamosa" }, fakeLogger);
        expect(fakeLogger).toHaveBeenCalledTimes(1);
        const logged = fakeLogger.mock.calls[0][0];
        expect(logged).toContain("login_failed");
        expect(logged).toContain("mamosa");
    });
});

// G8: No secrets in logs (I)
describe("G8: no secrets in logs", () => {
    test("password and sessionId are not in the log line", () => {
        const fakeLogger = jest.fn();
        const details = {username: "mamosa", password: "mamosa123", sessionId: "abc123"};
        logAuthEvent("login_failed", details, fakeLogger);
        const logged = fakeLogger.mock.calls[0][0];
        expect(logged).not.toContain("mamosa123");
        expect(logged).not.toContain("abc123");
        expect(logged).toContain("mamosa");
    });
});

// G9: Registration with missing data returns an error and does not crash (D)
describe("G9: registration without password", () => {
    test("returns an error result and does not throw", () => {
        const input = {username: "mamosa"};
        expect(() => registerUser(input)).not.toThrow();
        const result = registerUser(input);
        expect(result.ok).toBe(false);
    });

    test("missing input (undefined) does not crash", () => {
        expect(() => registerUser(undefined)).not.toThrow();
    });

    test("valid input registers the user and hashes the password", () => {
        const result = registerUser({username: "mamosa", password: "mamosa123"});
        expect(result.ok).toBe(true);
        expect(result.user.username).toBe("mamosa");
        expect(result.user.role).toBe("user");
        expect(result.user.passwordhash).not.toBe("mamosa123");
        expect(result.user.passwordhash).toMatch(/^\$2[aby]\$/);
    });
});

// G10: Role field supplied at registration is ignored (E)
describe("G10a: extra role field at registration", () => {
    test("createUser ignores the role field and sets it to 'user'", () => {
        const evilInput = {username: "mamosa", password: "mamosa123", role: "admin"};
        const user = createUser(evilInput);
        expect(user.role).toBe("user");
    });

    test("createUser with null or undefined input does not crash and returns null", () => {
        expect(() => createUser(null)).not.toThrow();
        expect(() => createUser(undefined)).not.toThrow();
        expect(createUser(null)).toBeNull();
        expect(createUser(undefined)).toBeNull();
    });
});

// G11: isAdmin grants rights only to role "admin" (E)
describe("G11: isAdmin", () => {
    // G11a: A normal user is not admin (E)
    test("G11a: normal user is not admin", () => {
        expect(isAdmin({username: "mamosa", role: "user"})).toBe(false);
    });

    // G11b: An admin user is recognised as admin (E)
    test("G11b: an admin user is admin", () => {
        expect(isAdmin({username: "admin", role: "admin"})).toBe(true);
    });

    // G11c: A null user has no rights (E)
    test("G11c: null user has no rights", () => {
        expect(isAdmin(null)).toBe(false);
    });

    // G11d: An unrecognized role has no rights (E)
    test("G11d: unrecognized role has no rights", () => {
        expect(isAdmin({ username: "mallory", role: "superuser" })).toBe(false);
    });

    // G11e: A missing role has no rights (E)
    test("G11e: missing role has no rights", () => {
        expect(isAdmin({ username: "tim"})).toBe(false);
    });

    // G11f: null and undefined do not crash (E)
    test("G11f: null and undefined do not crash", () => {
        expect(isAdmin(null)).toBe(false);
        expect(isAdmin(undefined)).toBe(false);
    });
});
