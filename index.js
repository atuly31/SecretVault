import express, { query } from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import env from "dotenv";
import { access } from "fs";
import { profile } from "console";
const app = express();
const port = 3000;

env.config();
app.use(
  session({
    secret: process.env.hide,
    resave: false,
    saveUninitialized: true,
  })
);
// Declare session before creating passport very important
app.use(passport.initialize());
app.use(passport.session());
app.set("view engine", "ejs");
const db = new pg.Client({
  user: "postgres",
  password: "Atulyadav31",
  database: "World",
  port: 5432,
});

const saltRound = 10;
db.connect();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/secrets", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("secrets");
  } else {
    res.render("login");
  }
});

app.get("/submit", (req, res) => {
  res.render("submit.ejs");
});
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post(
  "/login",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post("/register", async (req, res) => {
  var password = "";
  var email = "";
  email = req.body.username;
  password = req.body.password;
  try {
    const pre = await db.query("select * from person where email = ($1)", [
      email,
    ]);

    if (pre.rowCount > 0) {
      res.send("user Already Prsent");
      res.redirect("/");
    } else if (email === "" || password === "") {
      res.send("error");
    } else {
      bcrypt.hash(password, saltRound, async (err, hash) => {
        if (err) {
          console.log("Error");
        } else {
          const result = await db.query(
            "INSERT INTO person (email, password) VALUES ($1, $2)",
            [email, hash]
          );
          const user = result.rows[0];
          console.log(user);
          req.login(user, (err) => {
            res.redirect("/secrets");
          });
        }
      });
    }
  } catch (error) {
    console.log(error);
  }
});

app.post("/submit", async (req, res) => {
  const secrect = req.body.secret;
  if (req.isAuthenticated()) {
    try {
      await db.query("update person set secrects = $1 where email = $2", [
        secrect,
        req.user.email,
      ]);
      console.log("success posted a secret");
    } catch (error) {}
  } else {
    
  }
});

passport.use(
  "local",
  new Strategy(async function (username, password, cb) {
    console.log(username);
    try {
      const response = await db.query(
        "select * from person where email = ($1)",
        [username]
      );
      login_user_email = response.rows[0].username;
      // get_user(login_user_email);
      if (response.rowCount > 0) {
        const storedHashpass = response.rows[0].password;

        const user = response.rows[0];

        bcrypt.compare(password, storedHashpass, (err, output) => {
          if (err) {
            console.log("error");
            return cb(err);
          } else {
            if (output === true) {
              return cb(null, true);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        return cb(null, false);
      }
    } catch (error) {}
  })
);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.Client_ID,
      clientSecret: process.env.Client_secret,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      console.log(profile);
      try {
        const response = await db.query(
          "Select * from person where email = $1",
          [profile.email]
        );

        console.log(response.rowCount);
        if (response.rows.length !== 0) {
          return cb(null, response.rows[0], true);
        } else {
          console.log("IN saved google db");
          const new_user = await db.query(
            "insert into person (email,password) Values($1,$2)",
            [profile.email, "google"]
          );
          login_user_email = new_user.rows[0].email;
          console.log(new_user);
          return cb(null, new_user.rows[0], true);
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
