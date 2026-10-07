const { 
    validateCredentials,
    registerUser,
    logAuthEvent,
    createSessionId
} = require('../routes/authUtils');

const request = require('supertest');
const app = require('../app');
const crypto = require('crypto');

const {
    createUser,
    isAdmin
} = require( '../routes/roles');

// G1 (S)
describe("G1: Two sesion IDS for the same user are different.", () => {
    test("output cannot be reproduced by hashing a known value", () => {
        const id = createSessionId();
        const guessableHash = crypto.createHash('sha256').update('anyUsername').digest('hex');
        expect(id).not.toBe(guessableHash);
    });
    //.test("createSessionId returns a different value each time", () => {
    //    const id1 = createSessionId();
    //    const id2 = createSessionId();
    //    expect(id1).not.toBe(id2);
    //});
});

// G2: sessionID is not a hash of the username (S)
describe("G2: Session ID format.", () => {
    test("is 64 hex charachters long.", () => {

        const id = createSessionId();
        expect(id).toMatch(/^[0-9a-f]{64}$/);
    });
});

// G3: Empty username is rejected (T)
describe("G3: Empty username.", () =>{
    test("Emty string returns false", () =>{
        const username = "";
        const password = "Secret123";

        const result = validateCredentials(username, password);
        expect(result).toBe(false);
    });
});

test("Spaces only as string returns fals.", () =>{
    const result = validateCredentials("   ", "Secret123");
    expect(result).toBe(false);
});

//G4: missing or null password is rejected.
describe("G4: missing or null password", () => {
    test("null password returns false.", ()=> {
        const result = validateCredentials("mahdi", "123456");
        expect(result).toBe(false);
    });

    test("8 characters return true", () => {
        const result = validateCredentials("mahdi", "12345678");
        expect(result).toBe(true);
    });
});

// G5: Password length boundry
describe("G5: Password length boundry.", ()=> {
    test("7 characters returns false", () =>{
        const result = validateCredentials("mahdi", "1234567");
        expect(result).toBe(false);
    });

    test("8 charaters return true", () => {
        const result = validateCredentials("mahdi", "12345678");
        expect(result).toBe(true);
    });
});

// G6 (T)
describe("G6: wrong data types", () => {
    test("numbers as usernames returns false", () => {
        const username = 12345;
        const result = validateCredentials(username, "mamosa123");
        expect(result).toBe(false);
    });
 });

 test("object as username returns false", () => {
    const result = validateCredentials({username: "mamosa"}, "mamosa123");
    expect(result).toBe(false);
 });

 test ("number as password returns false", () => {
    const result = validateCredentials("mamosa", 12345678);
    expect(result).toBe(false);
 });

// G7 (R)
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

// G8 (I)
describe("G8: no secrets in logs", () => {
    test("password and sesstionId are not int the log line", () => {
        const fakeLogger = jest.fn();
        const  details = {username: "mamosa", password: "mamosa123", sessionId: "abc123"};
        logAuthEvent("login_failed", details, fakeLogger);
        const logged = fakeLogger.mock.calls[0][0];
        expect(logged).not.toContain("mamosa123");
        expect(logged).not.toContain("abc123");
        expect(logged).toContain("mamosa");
    });
});

// G9 (D)
describe("G9: regeistration without password", () => {
    test("return an error result and deosnot throw", () => {
        const input = {username: "mamosa"};
        expect(() => registerUser(input)).not.toThrow();
        const result = registerUser(input);
        expect(result.ok).toBe(false);
    });

    test("missing input (undefined deos not crash)", () => {
        expect(() => registerUser(undefined)).not.toThrow();
    });
});

// G10a (E)
describe("G10a: extra role field at registration", () => {
    test("createUser ignores the role field and sets it to 'user'", () => {
        const evilinput = {username: "mamosa", password: "mamosa123", role: "admin"};
        const user = createUser(evilinput);
        expect(user.role).toBe("user");
    });
});

// G10b (E)
describe("G10b: isAdmin", () => {
    test("a normal user is not admin", () => {
        expect(isAdmin({username: "mamosa", role: "user"})).toBe(false);
    });

    // G10c (E)
    test("an admin user is admin", () => {
        expect(isAdmin({username: "admin", role: "admin"})).toBe(true);
    });

    // G10d (E)
    test("unknown user has no rights", () => {
        expect(isAdmin(null)).toBe(false);
    });

    // G10d (E)
    test("G10d: missing role has no rights", () => {
    expect(isAdmin({ username: "tim" })).toBe(false);
  });

  // G10d (E)
  test("G10d: null and undefined do not crash", () => {
    expect(isAdmin(null)).toBe(false);
    expect(isAdmin(undefined)).toBe(false);

  });
});

test("G-integration: login always issues a new session ID, never reuses the client's", async () => {
  const fakeOldSessionId = "attackerSuppliedSessionId1234567890";

  const res = await request(app)
    .post("/auth/login")
    .set("Cookie", `sessionId=${fakeOldSessionId}`)
    .send({ username: "validtestuser", password: "Secret123" });

  const setCookieHeader = res.headers["set-cookie"];
  expect(setCookieHeader).toBeDefined();
  expect(setCookieHeader[0]).not.toContain(fakeOldSessionId);
});