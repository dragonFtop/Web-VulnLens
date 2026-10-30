const express = require("express");
const app = express();

app.get("/page", (req, res) => {
  const title = req.query.title;
  document.write("<h2>" + title + "</h2>");
  res.end();
});
