const child_process = require("child_process");
const express = require("express");
const app = express();

app.get("/version", (req, res) => {
  const target = String(req.query.tool || "");
  if (target !== "uptime") {
    return res.status(400).send("unsupported");
  }
  child_process.execFile("/usr/bin/uptime", [], (error, stdout) => {
    res.send(stdout);
  });
});
