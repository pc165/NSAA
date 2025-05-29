require("dotenv").config();
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
const Client = require("node-radius-client");
const OAuth2Strategy = require("passport-oauth2");
const morgan = require('morgan')
const {
  dictionaries: {
    rfc2865: { file, attributes },
  },
} = require("node-radius-utils");


app.use(morgan(':method :url :status :res[content-length] - :response-time ms'))

const githubApi = (access_token) => {
  const api = async (path) => {
    const a = await fetch(`https://api.github.com/${path}`, {
      headers: {
        Authorization: `Bearer ${access_token}`,
        "X-GitHub-Api-Version": "2022-11-28",
        Accept: "application/vnd.github+json",
      },
    });
    return await a.json();
  };

  return {
    user: () => api("user"),
    repos: () => api("user/repos"),
  };
};

const radiusClient = new Client({
  host: "172.19.62.240", // ip a | grep eth0
  dictionaries: [file],
});

const insertUserWithoutPassword = async (username, description) => {
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

app.use((req, res, next) => {
  req.isFirefox = /Firefox/.test(req.headers["user-agent"]);
  next();
});

app.use((req, res, next) => {
  if (req.cookies.jwt) {
    jwt.verify(req.cookies.jwt, jwtSecret, (err, decoded) => {
      if (err) {
        return res.status(403).send(JSON.stringify(err));
      }
      req.decodedJwt = decoded;
      return next();
    });
  } else {
    return next();
  }
});

passport.use(
  "oauth2",
  new OAuth2Strategy(
    {
      authorizationURL: "https://github.com/login/oauth/authorize",
      tokenURL: "https://github.com/login/oauth/access_token",
      clientID: process.env.OAUTH2_GITHUB_ID,
      clientSecret: process.env.OAUTH2_GITHUB_SECRET,
      callbackURL: "https://localhost:9443/oauth2/cb",
    },
    async (accessToken, refreshToken, profile, done) => {
      const github_user = await githubApi(accessToken).user();
      console.log(github_user);
      db.get(
        `SELECT id, username
         FROM USERS
         WHERE username = ?`,
        [github_user.login],
        async (err, user) => {
          if (err) {
            return done(err);
          }

          if (!user) {
            const id = await insertUserWithoutPassword(
              github_user.login,
              "Registered using oauth2!",
            );
            return done(null, { sub: id });
          }

          return done(null, { sub: user.id });
        },
      );
    },
  ),
);

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
            return done(null, { sub: user.id, username: user.username });
          }

          return done("Incorrect username or password.");
        },
      );
    },
  ),
);

passport.use(
  "username-password-radius",
  new LocalStrategy(
    {
      usernameField: "username",
      passwordField: "password",
      session: false,
    },
    async (username, password, done) => {
      await radiusClient
        .accessRequest({
          secret: process.env.RADIUS_SECRET,
          attributes: [
            [attributes.USER_NAME, username],
            [attributes.USER_PASSWORD, password],
          ],
        })
        .catch((err) => {
          console.error(err);
          return done("Incorrect username or password.");
        })
        .then(() => {
          db.get(
            `SELECT id, username
             FROM USERS
             WHERE username = ?`,
            [username],
            async (err, user) => {
              if (err) {
                return done(err);
              }

              if (!user) {
                const id = await insertUserWithoutPassword(
                  username,
                  "Registered using radius!",
                );
                return done(null, { username, sub: id });
              }

              return done(null, user);
            },
          );
        });
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
    if (req.decodedJwt.examiner) {
      return res.send(`hello examiner`);
    }
    return res.status(403).send("Forbidden");
  },
);

app.get(
  "/oauth2/login",
  passport.authenticate("oauth2", {
    scope: "user,repo",
    redirect_uri: "/oauth2/cb",
  }),
);

const setJwtCookie = (req, res) => {
  const jwtClaims = {
    sub: req.user.sub,
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
};

app.get(
  "/oauth2/cb",
  passport.authenticate("oauth2", {
    failureRedirect: "/oauth2/login",
    failureMessage: true,
  }),
  setJwtCookie,
);

app.post(
  "/login",
  passport.authenticate("username-password", {
    failureRedirect: "/login",
    session: false,
  }),
  setJwtCookie,
);

app.post(
  "/login-radius",
  passport.authenticate("username-password-radius", {
    failureRedirect: "/login-radius",
    session: false,
  }),
  setJwtCookie,
);

app.get("/login-radius", (req, res) => {
  res.sendFile("login-radius.html", { root: __dirname });
});

app.get(
  "/finalexam",
  passport.authenticate("jwtCookie", {
    session: false,
    failureRedirect: "/login",
  }),
  (req, res) => {
    const decoded = jwt.decode(req.cookies.jwt);
    return res.send(`Hello ${decoded.given_name}`);
  },
);

app.get(
  "/oidc/login",
  passport.authenticate("oidc", { scope: "openid email profile" }),
);

app.get(
  "/oidc/cb",
  passport.authenticate("oidc", {
    failureRedirect: "/oidc/login",
    failureMessage: true,
  }),
  (req, res) => {
    const jwtClaims = {
      sub: req.user.sub,
      given_name: req.user.given_name,
      iss: "localhost:9443",
      aud: "localhost:9443",
      exp: Math.floor((Date.now() + 3 * 24 * 60 * 60 * 1000) / 1000),
      oidc: true,
    };

    const token = jwt.sign(jwtClaims, jwtSecret);
    res.cookie("jwt", token, { httpOnly: true, secure: true });
    res.redirect("/");
  },
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
                const id = await insertUserWithoutPassword(
                  claims.email,
                  "Registered using openId!",
                );
                return done(null, { ...claims, sub: id });
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
