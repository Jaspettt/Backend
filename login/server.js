const express = require("express");
const { pool } = require("./DBconfig");
const bcrypt = require("bcrypt");
const passport = require("passport");
const flash = require("express-flash");
const session = require("express-session");
require("dotenv").config();
const app = express();
const initializePassport = require("./passConfig");
const PORT = process.env.PORT || 8000
app.set("view engine", "ejs");
app.use(express.urlencoded({extended:false}));


initializePassport(passport);

app.use(session({
    secret: "secret",
    resave: false,
    saveUninitialized: false,
}));

app.use(passport.initialize());

app.use(passport.session());
app.use(flash())

app.get("/", (req, res) => {
    res.render("index");
});
app.get("/users/register", checkAuthenticated, (req, res) => {
     res.render("register")
});

app.get("/users/login", checkAuthenticated, (req, res) => {
    res.render("login")
});
app.get("/users/dashboard", checkNotAuthenticated, (req, res) => {
    
    res.render("dashboard", {user: req.user.name })
});
app.get("/users/logout", (req, res) => {
    req.session.destroy();
    
    res.redirect("/users/login");
});
app.post("/users/register", async (req, res) => {
    let {name, email, password, password2} = req.body;
    console.log({
        name,
        email,
        password,
        password2
    });
    let errors = [];
    if (!name || !email || !password || !password2) {
        errors.push({message: "Enter all fields please"});
    }
    if (password.length <4) {
        errors.push({message: "Password must be at least 4 characters long"});
    }
    if (password != password2) {
        errors.push({message: "Password must match"});
    }
    if(errors.length > 0) {
        res.render("register", {errors});
    } 
    else {
        let hashedPass = await bcrypt.hash(password, 7);
        pool.query(
            `SELECT * FROM users
            WHERE email = $1`, 
            [email], (err, results) => {
                if (err) {
                    throw err;
                }
                console.log(results.rows);

                if (results.rows.length > 0) {
                    errors.push({message: "Email already at use"});
                    res.render("register", {errors});
                } else {
                    pool.query (
                        `INSERT INTO users (name, email, password)
                        VALUES ($1, $2, $3)
                        RETURNING id, password`, [name, email, hashedPass], 
                        (err, results) => {
                            if (err) {
                                throw err;
                            }
                            console.log(results.rows);
                            req.flash("succ_msg", "You're now a part of community. Join us.");
                            res.redirect("/users/login");
                        }
                    );
                }
            }
        );
    }
});
app.post(
    "/users/login",
    passport.authenticate("local", {
      successRedirect: "/users/dashboard",
      failureRedirect: "/users/login",
      failureFlash: true
    })
  );
  
  function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
      return res.redirect("/users/dashboard");
    }
    next();
  }
  
  function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
      return next();
    }
    res.redirect("/users/login");
  }
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});