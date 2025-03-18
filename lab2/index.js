const express = require("express");
const app = express();
const port = 3000;

app.use((req, res, next) => {
  req.isFirefox = /Firefox/.test(req.headers["user-agent"]);
  next();
});

app.get("/", (req, res) => {
  const name = req.isFirefox ? "firefox user" : "world";
  res.send(`Hello ${name}!`);
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
