const child_process = require("child_process");
const express = require("express");
const app = express();

app.get("/lookup", (req, res) => {
  const domain = req.query.domain;
  child_process.exec("nslookup " + domain, (error, stdout) => {
    res.send(stdout);
  });
});
