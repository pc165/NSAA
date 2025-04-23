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
const session = require("express-session");
const { discovery } = require("openid-client");
const OpenIDConnectStrategy = require("openid-client/passport").Strategy;
const dotenv = require("dotenv");
dotenv.config();

const insertUserFromOpenId = async (username, description) => {
  const randomPassword = crypto.randomBytes(32).toString("base64");
  return insertUser(username, randomPassword, description);
};

const insertUser = async (username, password, description) => {
  const salt = crypto.randomBytes(16).toString("base64");
  const id = crypto.randomUUID().toString();

  const hashedPassword = await scryptMcf.hash(password, {
    saltBase64NoPadding: salt,
    scryptParams: { logN: 18, r: 8, p: 2 },
  });

  db.run(
    `INSERT INTO USERS
     VALUES ($id,
             $username,
             $password,
             $salt,
             $description)`,
    {
      $id: id,
      $username: username,
      $salt: salt,
      $password: hashedPassword,
      $description: description,
    },
  );
  return id;
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
  await insertUser(
    "midterm",
    "midterm",
    "one of the users that deserve to get to this server",
  );
});

passport.serializeUser((user, done) => done(null, user));

passport.deserializeUser((user, done) => done(null, user));

app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: require("crypto").randomBytes(32).toString("base64url"),
    resave: false,
    saveUninitialized: false,
  }),
);
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
          if (err || !row) {
            return done(err);
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
            return done("Incorrect username or password.");
          }

          if (await scryptMcf.verify(password, user.password)) {
            return done(null, user);
          }

          return done("Incorrect username or password.");
        },
      );
    },
  ),
);

app.get("/login", (req, res) => {
  res.sendFile("login.html", { root: __dirname });
});

app.get("/logout", (req, res) => {
  res.clearCookie("jwt");
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
      iss: "localhost:9443",
      aud: "localhost:9443",
      exp: (Date.now() + 3 * 24 * 60 * 60 * 1000) / 1000,
      role: "user",
    };

    if (req.user.username === "midterm") {
      jwtClaims["examiner"] = true;
    }

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

app.get(
  "/onlyexaminers",
  passport.authenticate("jwtCookie", {
    session: false,
    failureRedirect: "/login",
  }),
  (req, res) => {
    jwt.verify(req.cookies.jwt, jwtSecret, (err, decoded) => {
      if (err) {
        return res.status(403).send("Forbidden");
      }
      if (decoded.examiner) {
        return res.send(`hello examiner`);
      }
    });
    return res.status(403).send("Forbidden");
  },
);

app.get(
  "/oidc/cb",
  passport.authenticate("oidc", {
    failureRedirect: "/login",
    failureMessage: true,
  }),
  (req, res) => {
    const jwtClaims = {
      sub: req.user.sub,
      iss: "localhost:9443",
      aud: "localhost:9443",
      exp: (Date.now() + 3 * 24 * 60 * 60 * 1000) / 1000,
      role: "user",
    };

    const token = jwt.sign(jwtClaims, jwtSecret);
    res.cookie("jwt", token, { httpOnly: true, secure: true });
    res.redirect("/");
  },
);

app.get(
  "/oidc/login",
  passport.authenticate("oidc", { scope: "openid email" }),
);

(async () => {
  try {
    const oidcConfig = await discovery(
      new URL(process.env.OIDC_PROVIDER),
      process.env.OIDC_CLIENT_ID,
      process.env.OIDC_CLIENT_SECRET,
    );
    passport.use(
      "oidc",
      new OpenIDConnectStrategy(
        {
          config: oidcConfig,
          callbackURL: process.env.OIDC_CALLBACK_URL,
        },
        async (tokens, done) => {
          const claims = tokens?.claims();

          if (!claims) {
            return done("no tokenSet or userInfo");
          }

          db.get(
            `SELECT id, username
             FROM USERS
             WHERE username = ?`,
            [claims.email],
            async (err, user) => {
              if (err) {
                return done(err);
              }

              if (!user) {
                const sub = await insertUserFromOpenId(
                  claims.email,
                  "Registered using openId!",
                );
                return done(null, { ...claims, sub });
              }

              return done(null, { ...claims, sub: user.id });
            },
          );
        },
      ),
    );

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
  } catch (e) {
    console.log("Got error:\n", JSON.stringify(e, null, 2));
    console.log(e);
  }
})();
