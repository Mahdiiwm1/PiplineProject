const { 
    validateCredentials,
    registerUser,
    logAuthEvent,
} = require('../routes/authUtils');

const { createUser, isAdmin } = require('../routes/roles');

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
        expect(registerUser(undefined)).not.toThrow();
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
    test("G11d: missing role has no rights", () => {
    expect(isAdmin({ username: "tim" })).toBe(false);
  });

  // G10d (E)
  test("G11d: null and undefined do not crash", () => {
    expect(isAdmin(null)).toBe(false);
    expect(isAdmin(undefined)).toBe(false);

  });
});