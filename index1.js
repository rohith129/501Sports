const app = require("./app");
app.listen(3000 || process.env.PORT, () => {
  console.log("starting the server"); //for listening the port
});
