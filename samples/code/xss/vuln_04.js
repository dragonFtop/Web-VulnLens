const express = require("express");
const app = express();

app.get("/profile", (req, res) => {
  const bio = req.query.bio;
  document.getElementById("bio").innerHTML = bio;
  res.send("ok");
});
