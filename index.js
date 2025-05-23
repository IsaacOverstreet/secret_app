import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

// get secret from data base and render on the secret.ejs template
app.get("/secrets", async (req, res) => {
  // console.log(req.user);
  if (req.isAuthenticated()) {
    try {
      const result = await db.query(
        "SELECT secret FROM secretdb WHERE user_id = $1",
        [req.user.id]
      );
      let secrets = [];

      console.log("res", result);

      if (result.rows.length === 0) {
        res.render("secrets.ejs", {
          allSecret: "jack bauer",
        });
      } else {
        // secrets = result.rows
        result.rows.forEach((secret) => {
          secrets.push(secret.secret);
        });
        console.log("array", secrets);
        // result.rows.forEach((s)=>{
        //   secrets.push(s.secret)
        // })

        res.render("secrets.ejs", {
          allSecret: secrets,
        });
      }
      // console.log("sec",secret)
    } catch (err) {
      console.log(err);
    }
  } else {
    res.redirect("/login");
  }
});

// get submit page if already authenticated with google
app.get("/submit", async (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit.ejs");
  } else res.redirect("/login");
});

// get profile and email from google
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

// authentication for google
app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

//login authentication check for bcrypt
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

// registering and hashing password using bcrypt
app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query(
      "SELECT * FROM users WHERE user_email = $1",
      [email]
    );

    if (checkResult.rows.length > 0) {
      res.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (user_email, user_password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("success");
            res.redirect("/secrets");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

//Creating the post route for submit.
//Handling the submitted data and add it to the database
app.post("/submit", async (req, res) => {
  const secret = req.body.secret.trim();
  // console.log(req.user)
  const userId = req.user.id;
  console.log("Id", userId);
  // console.log(secret)
  try {
    // const insertID = await db.query ("INSERT INTO secretdb (secret, user_id) VALUES ($1,$2) RETURNING *",[secret,userId])
    const newSecret = await db.query(
      "INSERT INTO secretdb (secret, user_id) VALUES ($1,$2) ON CONFLICT (user_id, secret) DO NOTHING RETURNING *",
      [secret, userId]
    );
    console.log(newSecret);
    // console.log(insertID)
    // const storedID = insertID.rows[0].user_id
    // console.log('store',storedID);
    // console.log('requestEmail',req.user.user_email)
    // const result = await db.query("UPDATE secretdb SET secret= $1 WHERE user_id = $2 RETURNING *",[secret, storedID])
    // console.log(result)
    res.redirect("/secrets");
  } catch (err) {
    console.log(err);
  }
});

// passport hash: logging with bcrypt hashing password has been saved in the users db
passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query(
        "SELECT * FROM users WHERE user_email = $1 ",
        [username]
      );
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.user_password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              return cb(null, user);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      console.log(err);
    }
  })
);

//Getting authentication from google grabs the email
// Check the db if the email exist
// then creates a new user and stores it in the users db

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        // console.log(profile);
        const result = await db.query(
          "SELECT * FROM users WHERE user_email = $1",
          [profile.email]
        );
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO users (user_email, user_password) VALUES ($1, $2)",
            [profile.email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);

passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
