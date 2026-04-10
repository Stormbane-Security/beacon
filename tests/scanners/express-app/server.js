const express = require("express");
const app = express();

// Express sets X-Powered-By: Express by default
app.get("/", (req, res) => {
  res.send("<html><body><h1>Express App</h1></body></html>");
});

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

app.listen(3000, "0.0.0.0", () => {
  console.log("Express listening on :3000");
});
