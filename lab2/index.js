const express = require("express");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const https = require("https");
const fs = require("fs");
const JwtStrategy = require("passport-jwt/lib/strategy");
const { Strategy: LocalStrategy } = require("passport-local");
const passport = require("passport");
const app = express();
const crypto = require("crypto");
const jwtSecret = crypto.randomBytes(16);
const scryptMcf = require("scrypt-mcf");
const sqlite3 = require("sqlite3").verbose();
const db = new sqlite3.Database(":memory:");

const insertUser = async (username, password, description) => {
  const salt = crypto.randomBytes(16).toString("base64");
  const hashedPassword = await scryptMcf.hash(password, {
    saltBase64NoPadding: salt,
  });

  db.run(
    `INSERT INTO USERS
         VALUES (lower(hex(randomblob(16))),
                 $username,
                 $password,
                 $salt,
                 $description)`,
    {
      $username: username,
      $salt: salt,
      $password: hashedPassword,
      $description: description,
    },
  );
};

db.serialize(async () => {
  db.run(`CREATE TABLE USERS
            (
                id          UUID PRIMARY KEY,
                username    TEXT NOT NULL UNIQUE,
                password    TEXT NOT NULL,
                salt        TEXT NOT NULL,
                description TEXT
            )
    `);

  await insertUser(
    "walrus",
    "walrus",
    "one of the users that deserve to get to this server",
  );
});

app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(passport.initialize());

passport.use(
  "jwtCookie",
  new JwtStrategy(
    {
      jwtFromRequest: (req) => req?.cookies?.jwt,
      secretOrKey: jwtSecret,
    },
    (jwtPayload, done) => {
      db.get(
        `SELECT username, description
                 FROM USERS
                 WHERE id = ?`,
        [jwtPayload.sub],
        (err, row) => {
          if (err) {
            return done(err, false);
          }

          return done(null, {
            username: row.username,
            description: row.description,
            role: "user",
          });
        },
      );
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
    (username, password, done) => {
      db.get(
        `SELECT id, username, password
                 FROM USERS
                 WHERE username = ?`,
        [username],
        async (err, user) => {
          if (err) {
            return done(err);
          }

          if (!user) {
            return done(null, false, {
              message: "Incorrect username or password.",
            });
          }

          if (await scryptMcf.verify(password, user.password)) {
            return done(null, user);
          }

          return done(null, false, {
            message: "Incorrect username or password.",
          });
        },
      );
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
      sub: req.user.id,
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
      `Welcome to your private page, ${req.user.username} ${req.user.description}, you are ${req.isFirefox ? "" : "not "}using firefox!`,
    );
  },
);

app.use((req, res, next) => {
  res.status(500).send("Something broke!");
});

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
