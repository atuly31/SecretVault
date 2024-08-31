import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import env from "dotenv"
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

// app.get("/secrets", (req, res) => {
//   if (req.isAuthenticated()) {
//     res.render("secrets.ejs");
//   } else {
//     res.redirect("/login");
//   }
// });

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

app.post("/register", async (req, res) => {
  var password = "";
  var email = "";
  email = req.body.username;
  password = req.body.password;
  try {
    const pre = await db.query("select * from person where email = ($1)", [
      email,
    ]);
    console.log(pre);
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
          res.redirect("/");
        }
      });
    }
  } catch (error) {
    console.log(error);
  }
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/",
  })
);

passport.use(
  new Strategy(async function (username, password, cb) {
    try {
      const response = await db.query(
        "select * from person where email = ($1)",
        [username]
      );

      const storedHashpass = response.rows[0].password;
      console.log(storedHashpass);
      console.log(password);
      const user = response.rows[0];
      console.log(user);
      if (response.rowCount > 0) {
        bcrypt.compare(password, storedHashpass, (err, output) => {
          if (err) {
            console.log("error");
            return cb(err);
          } else {
            if (output === true) {
              console.log("in true");
              return cb(null, user);
            } else {
              console.log("in false");
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (error) {}
  })
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
