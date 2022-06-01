require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
// const md5 = require("md5");  //using bcrypt after this
// const encrypt = require("mongoose-encryption");  //using md5 after this
// const bcrypt = require("bcrypt");   // using passpor after this
// const saltRounds = 10;   // using passpor after this

const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

const GoogleStrategy = require('passport-google-oauth20').Strategy;

const findOrCreate = require("mongoose-findorcreate");

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.set("view engine", "ejs");
app.use(express.static("public"));

app.use(session({
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: false,
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });    //using md5 after this
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);
passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    cb(null, { id: user.id, username: user.username });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});

passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "http://localhost:3002/auth/google/secrets"
},
function(accessToken, refreshToken, profile, cb) {
  console.log(profile);
  User.findOrCreate({ googleId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));

app.get("/", function(req, res) {
  res.render("home");
});

app.get("/login", function(req, res) {
  res.render("login");
});

app.get("/register", function(req, res) {
  res.render("register");
});

app.get("/secrets", function(req, res) {
  User.find({ "secret": {$ne: null}}, function(err, foundUsers) {
    if (err) {
      console.log(err);
    } else if (foundUsers) {
      res.render("secrets", { usersWithSecrets: foundUsers })
    }
  })
});

app.get("/logout", function(req, res) {
  req.logout();
  res.redirect("/");
});

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] }));

app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/submit", function(req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.render("login");
  }
});

app.post("/submit", function(req, res) {
  const secret = req.body.secret;
  User.findById(req.user.id, function(err, foundUser) {
    if (err) {
      console.log(err);
    } else {
      foundUser.secret = secret;
      foundUser.save();
      res.redirect("/secrets");
    }
  })
})

app.post("/register", function(req, res) {

  // using passport after this 
  // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
  //   const user = new User({
  //     email: req.body.username,
  //     password: hash
  //   });
  //   user.save((err) => {
  //     if (err) {
  //       console.log(err);
  //     } else {
  //       res.render("secrets");
  //     }
  //   });
  // });

  //using passport

  User.register({ username: req.body.username }, req.body.password, function(err, user) {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("secrets");
      })
    }
  })

});

app.post("/login", function(req, res) {
  // using passport after this 
  // const username = req.body.username;
  // const password = req.body.password;
  // User.findOne({ email: username }, function(err, foundUser) {
  //   if (err) {
  //     console.log(err);
  //   } else if (foundUser) {
  //     bcrypt.compare(password, foundUser.password, function(err, result) {
  //       if (result === true) {
  //         res.render("secrets");
  //       }
  //     });
  //   }
  // })

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("secrets");
      })
    }
  })

});

app.listen(3002, function() {
  console.log("server running on port 3002");
});