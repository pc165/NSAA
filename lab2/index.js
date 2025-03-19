const express = require("express");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const https = require("https");
const fs = require("fs");
const JwtStrategy = require("passport-jwt/lib/strategy");
const { Strategy: LocalStrategy } = require("passport-local");
const passport = require("passport");
const app = express();
const jwtSecret = require("crypto").randomBytes(16);

const sqlite3 = require("sqlite3").verbose();
const db = new sqlite3.Database(":memory:");

db.serialize(() => {
  db.run(`CREATE TABLE USERS
            (
                id       UUID PRIMARY KEY,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            )
    `);

  const stmt = db.prepare(
    "INSERT INTO USERS VALUES (lower(hex(randomblob(16))),?,?)",
  );
  stmt.run("walrus", "walrus");
  stmt.finalize();

  db.each("SELECT * FROM USERS", (err, row) => {
    console.log(row);
  });
});

db.close();
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(passport.initialize());

passport.use(
  "jwtCookie",
  new JwtStrategy(
    {
      jwtFromRequest: (req) => {
        if (req && req.cookies) {
          return req.cookies.jwt;
        }
        return null;
      },
      secretOrKey: jwtSecret,
    },
    (jwtPayload, done) => {
      if (jwtPayload.sub && jwtPayload.sub === "walrus") {
        const user = {
          username: jwtPayload.sub,
          description: "one of the users that deserve to get to this server",
          role: jwtPayload.role ?? "user",
        };
        return done(null, user);
      }
      return done(null, false);
    },
  ),
);

passport.use(
  "username-password",
  new LocalStrategy(
    {
      usernameField: "username",
      passwordField: "password",
      session: false,
    },
    function (username, password, done) {
      if (username === "walrus" && password === "walrus") {
        const user = {
          username: "walrus",
          description: "the only user that deserves to get to this server",
        };
        return done(null, user);
      }
      return done(null, false);
    },
  ),
);

app.get("/login", (req, res) => {
  res.sendFile("login.html", { root: __dirname });
});

app.get("/logout", (req, res) => {
  res.cookie("jwt", null);
  res.send("logged out");
});

app.post(
  "/login",
  passport.authenticate("username-password", {
    failureRedirect: "/login",
    session: false,
  }),
  (req, res) => {
    const jwtClaims = {
      sub: req.user.username,
      iss: "localhost:3000",
      aud: "localhost:3000",
      exp: Math.floor(Date.now() / 1000) + 604800,
      role: "user",
    };

    const token = jwt.sign(jwtClaims, jwtSecret);
    res.cookie("jwt", token, { httpOnly: true, secure: true });
    res.redirect("/");
  },
);
app.use((req, res, next) => {
  req.isFirefox = /Firefox/.test(req.headers["user-agent"]);
  next();
});

app.get(
  "/",
  passport.authenticate("jwtCookie", {
    session: false,
    failureRedirect: "/login",
  }),
  (req, res) => {
    res.send(
      `Welcome to your private page, ${req.user.username}, you are ${req.isFirefox ? "" : "not "}using firefox!`,
    );
  },
);

app.use((req, res, next) => {
  res.status(500).send("Something broke!");
});

// app.listen(3000, () => {
//   console.log(`start http`);
// });

https
  .createServer(
    {
      cert: fs.readFileSync("localhost.crt"),
      key: fs.readFileSync("localhost.key"),
    },
    app,
  )
  .listen(9443, () => {
    console.log(`start https`);
  });
