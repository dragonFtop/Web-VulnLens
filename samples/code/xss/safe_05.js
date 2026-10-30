const express = require("express");
const app = express();

app.get("/post", (req, res) => {
  const html = req.query.html;
  const clean = DOMPurify.sanitize(html);
  document.getElementById("post").innerHTML = clean;
  res.sendStatus(204);
});
