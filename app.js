const express = require("express"); //for importing the express package
const app = express();
const bodyparser = require("body-parser");
app.use(bodyparser.json());
app.use(express.urlencoded({ extended: false }));

const csrf = require("tiny-csrf");
const cookieParser = require("cookie-parser");
app.use(cookieParser("shh! some secret String"));
app.use(csrf("this_should_be_32_character_long", ["POST", "PUT", "DELETE"]));
const { User, Admin, Sports, UserJoinedSessions } = require("./models");
app.set("view engine", "ejs");
const path = require("path");
app.use(express.static(path.join(__dirname, "public")));

//for authentication
const passport = require("passport");
const connectEnsureLogin = require("connect-ensure-login");
const session = require("express-session");
const LocalStrategy = require("passport-local");
const flash = require("connect-flash"); //for sending notifications
//for hashing
const bcrypt = require("bcrypt");
const saltRounds = 10;
app.use(
  session({
    secret: "my-super-key-1234567987",
    cookie: {
      maxAge: 24 * 60 * 60 * 1000, //24 hours
      resave: false,
      saveUninitialized: true,
    },
  })
);
app.use(passport.initialize());
app.use(passport.session());
app.set("views", path.join(__dirname, "views"));
app.use(flash());
app.use(function (request, response, next) {
  response.locals.messages = request.flash();
  next();
});
const { Op } = require("sequelize");
passport.use(
  new LocalStrategy(
    {
      usernameField: "email",
      passwordField: "password",
    },
    (username, password, done) => {
      User.findOne({ where: { email: username } })
        .then(async (user) => {
          const res = await bcrypt.compare(password, user.password);
          if (res) {
            return done(null, user);
          } else {
            return done(null, false, { message: "password is invalid" });
          }
        })
        .catch((error) => {
          return error;
        });
    }
  )
);

//for serializing
passport.serializeUser((user, done) => {
  console.log("serializing user in session", user.id);
  done(null, user.id);
});
//for deserializing
passport.deserializeUser((id, done) => {
  User.findByPk(id)
    .then((user) => {
      done(null, user);
    })
    .catch((error) => {
      done(error, null);
    });
});
//for signup
app.get("/signup", (req, res) => {
  res.render("signup", { csrfToken: req.csrfToken() });
});

//for checking the signup details
app.post("/signupsubmit", async (req, res) => {
  console.log("CSRF Token:", req.csrfToken());
  console.log(req.body.fullname);
  const firstname = req.body.firstname;
  const email = req.body.email;
  const hashedPsd = await bcrypt.hash(req.body.password, saltRounds);

  try {
    if (!firstname || !email) {
      req.flash("error", "First name and email are required.");
      return res.redirect("/signup");
    }
    const user = await User.addUser({
      firstname: req.body.firstname,
      lastname: req.body.lastname,
      email: req.body.email,
      password: hashedPsd,
    });
    req.login(user, (err) => {
      if (err) {
        console.log(err);
      }
      console.log("hii");
      return res.redirect("/check");
    });
  } catch (error) {
    console.log(error);

    if (error.name === "SequelizeValidationError") {
      const errorMessages = error.errors.map((e) => e.message);
      req.flash("error", errorMessages);
      return res.redirect("/signup");
    }
    return res.status(422).json(error);
  }
});
//for login
app.get("/login", (req, res) => {
  res.render("loginpage", { csrfToken: req.csrfToken() });
});
//for checking the details of the login user
app.post(
  "/loginsubmit",
  passport.authenticate("local", {
    failureRedirect: "/login",
    failureFlash: true,
  }),
  (req, res) => {
    console.log(req.user);
    res.redirect("/check");
  }
);
app.get("/check", connectEnsureLogin.ensureLoggedIn(), (req, res) => {
  res.render("homepage1", {
    csrfToken: req.csrfToken(),
    userName: req.user.firstName,
  });
});
//for creating the session
app.post(
  "/create-session",
  connectEnsureLogin.ensureLoggedIn(),
  async (req, res) => {
    console.log("CSRF Token:", req.csrfToken());
    console.log("user name is:", req.user.id);
    try {
      const userId = req.user.id;

      const user = await User.findByPk(userId);

      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      const {
        sportsName,
        team1Players,
        team2Players,
        addPlayers,
        date,
        time,
        venue,
      } = req.body;

      const sportsSession = await Sports.create({
        SportsName: sportsName,
        team1Players: team1Players,
        team2players: team2Players,
        addPlayers: addPlayers,
        date: date,
        time: time,
        venue: venue,
        userId: userId,
        isCancelled: false,
      });
      const message1 = "successfully sport session created"; //for sending the notifications
      req.flash("error", message1);
      return res.redirect("/check");
    } catch (error) {
      console.error(error);
      return res.status(500).json({ error: "Internal Server Error" });
    }
  }
);
//for retriving the data
app.get(
  "/sportsSessions",
  connectEnsureLogin.ensureLoggedIn(),
  async (req, res) => {
    try {
      const sportsSessions = await Sports.findAll();
      //for getting the session
      const userId = req.user.id; //user id of the user
      // Iterate through each sports session and check if the user has joined
      for (const session of sportsSessions) {
        const userHasJoined = await UserJoinedSessions.findOne({
          where: {
            userId: userId,
            sessionId: session.id,
          },
        });

        // Add a property 'userHasJoined' to the session object
        session.userHasJoined = userHasJoined !== null;
      }
      // Render the EJS view with the retrieved sports sessions
      res.render("sportsSessions", {
        sportsSessions,
        userId: req.user.id,
        csrfToken: req.csrfToken(),
        userName: req.user.firstName,
      });
    } catch (error) {
      console.error("Error retrieving sports sessions:", error);
      res.status(500).send("Internal Server Error");
    }
  }
);
//for user created sessions
app.get(
  "/mySessions",
  connectEnsureLogin.ensureLoggedIn(),
  async (req, res) => {
    try {
      // Retrieve the user ID from the session
      const userId = req.user.id;

      // Query to get sports sessions for the logged-in user
      const sportsSessions = await Sports.findAll({
        where: {
          userId: userId,
          isCancelled: false,
        },
      });

      // Render the EJS view with the retrieved sports sessions
      res.render("mySessions", { sportsSessions, csrfToken: req.csrfToken() });
    } catch (error) {
      console.error("Error retrieving sports sessions:", error);
      res.status(500).send("Internal Server Error");
    }
  }
);
app.post("/cancelMath", async (req, res) => {
  const { sessionId, reason } = req.body;
  console.log(reason);
  try {
    // Find the sports session by ID
    const sportsSession = await Sports.findByPk(sessionId);

    if (!sportsSession) {
      return res.status(404).json({ error: "Sports session not found" });
    }

    // Update the sports session with cancelReason and isCancelled
    await sportsSession.update({
      cancelReason: reason,
      isCancelled: true,
    });
    req.flash("error", "Match cancelled successfully");
    return res.redirect("/mySessions");
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});
app.post("/cancelMySession", async (req, res) => {
  const { sessionId } = req.body;
  const userId = req.user.id;
  try {
    const session = await Sports.findByPk(sessionId);
    if (session && session.addPlayers >= 0) {
      // Update the addPlayers count
      await session.update({
        addPlayers: session.addPlayers + 1,
      });
      await UserJoinedSessions.destroy({
        where: {
          sessionId: sessionId,
          userId: userId,
        },
      });
      res.redirect("/joined-sports"); // Redirect to the sport sessions page
    } else {
      // Handle the case where the session is not available or no additional players are allowed
      res.status(400).send("Unable to cancel the session.");
    }
  } catch (error) {
    // Handle any errors
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
});
//for updating the players
app.post("/join-session", async (req, res) => {
  const { sessionId } = req.body;
  const userId = req.user.id;
  const userSession = await UserJoinedSessions.findOne({
    where: {
      userId: userId,
      sessionId: sessionId,
    },
  });

  try {
    // Find the session by ID
    if (!userSession) {
      const session = await Sports.findByPk(sessionId);
      await UserJoinedSessions.create({
        userId: userId,
        sessionId: sessionId,
      });
      // Check if the session is available and has additional players
      if (session && session.addPlayers > 0) {
        // Update the addPlayers count
        await session.update({
          addPlayers: session.addPlayers - 1,
        });
        res.redirect("/sportsSessions"); // Redirect to the sport sessions page
      } else {
        res.status(400).send("Unable to join the session.");
      }
    }
  } catch (error) {
    // Handle any errors
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
});
//for joined sports
app.get(
  "/joined-sports",
  connectEnsureLogin.ensureLoggedIn(),
  async (req, res) => {
    try {
      const userJoinedSessions = await UserJoinedSessions.findAll({
        where: {
          userId: req.user.id,
        },
      });

      const sportsIds = userJoinedSessions.map((session) => session.sessionId);

      const joinedSports = await Sports.findAll({
        where: {
          id: sportsIds,
        },
      });
      console.log(joinedSports);
      res.render("joined-sports", { joinedSports, csrfToken: req.csrfToken() });
    } catch (error) {
      console.error(error);
      res.status(500).send("Internal Server Error");
    }
  }
);
app.get(
  "/cancelled-sports",
  connectEnsureLogin.ensureLoggedIn(),
  async (req, res) => {
    try {
      // Retrieve the user ID from the session
      const userId = req.user.id;

      // Query to get sports sessions for the logged-in user
      const sportsSessions = await Sports.findAll({
        where: {
          userId: userId,
          isCancelled: true,
        },
      });

      // Render the EJS view with the retrieved sports sessions
      res.render("cancelled-sports", {
        sportsSessions,
        userName: req.user.firstName,
      });
    } catch (error) {
      console.error("Error retrieving sports sessions:", error);
      res.status(500).send("Internal Server Error");
    }
  }
);
//for signout
app.get("/signout", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/check");
  });
});

// Admin signup route
app.get("/admin/signup", (req, res) => {
  res.render("admin-signup", { csrfToken: req.csrfToken() });
});

app.post("/admin/signupsubmit", async (req, res) => {
  const firstname = req.body.firstname;
  const email = req.body.email;
  const hashedPsd = await bcrypt.hash(req.body.password, saltRounds);

  try {
    if (!firstname || !email) {
      req.flash("error", "First name and email are required.");
      return res.redirect("/admin/signup");
    }
    const admin = await User.create({
      firstName: req.body.firstname,
      lastname: req.body.lastname,
      email: req.body.email,
      password: hashedPsd,
      isAdmin: true,
    });
    req.login(admin, (err) => {
      if (err) {
        console.log(err);
      }
      console.log("Admin signed up");
      return res.redirect("/check");
    });
  } catch (error) {
    console.log(error);

    if (error.name === "SequelizeValidationError") {
      const errorMessages = error.errors.map((e) => e.message);
      req.flash("error", errorMessages);
      return res.redirect("/admin/signup");
    }

    return res.status(422).json(error);
  }
});

// Admin login route
app.get("/admin/login", (req, res) => {
  res.render("admin-login", { csrfToken: req.csrfToken() });
});

app.post(
  "/admin/loginsubmit",
  passport.authenticate("local", {
    failureRedirect: "/admin/login",
    failureFlash: true,
  }),
  (req, res) => {
    console.log(req.user);
    res.redirect("/adminDashboard");
  }
);

app.get("/adminDashboard", connectEnsureLogin.ensureLoggedIn(), (req, res) => {
  if (req.isAuthenticated() && req.user.isAdmin) {
    // User is an admin, proceed to the admin dashboard
    res.render("admin-dashboard", {
      sportsSessions: "",
      csrfToken: req.csrfToken(),
    });
  } else {
    // User is not an admin, redirect to a different page or show an error
    req.flash("error", "you are not a admin");
    return res.redirect("/admin/login"); // Redirect to home page for non-admin users
  }
});

// Your route handler
app.post("/sports-between-dates", async (req, res) => {
  const { startDate, endDate } = req.body;

  try {
    // Query the database for sports sessions between the given dates
    const sportsSessions = await Sports.findAll({
      where: {
        date: {
          [Op.between]: [startDate, endDate],
        },
      },
    });

    // Render the EJS template with the sports sessions
    res.render("admin-dashboard", {
      sportsSessions,
      csrfToken: req.csrfToken(),
    });
  } catch (error) {
    console.error("Error fetching sports sessions:", error);
    res.status(500).send("Internal server error");
  }
});

//for listening the port
module.exports = app;

// app.listen(3000, () => {
//   console.log("todo app is running");
// });
