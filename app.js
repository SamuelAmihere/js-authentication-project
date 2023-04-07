//---------REQUIRE MODULES------
require("dotenv").config();

const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");

const mongoose = require('mongoose');

const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

const GoogleStrategy = require("passport-google-oauth20").Strategy;

const findOrCreate = require("mongoose-findorcreate");


//----------SETTINGS------------
const port = 3000;
const homeEndPoint = "/";
const loginEndPoint = "/login";
const logoutEndPoint = "/logout";
const registerEndPoint = "/register";
const secretEndPoint = "/secrets";
const googleEndPoint = "/auth/google";
const googleRedirectEndPoint = "/auth/google/secrets"
const submitEndPoint = "/submit"
const database = "userDB";

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));

// setup sessions
app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: true,
}));
// Initialize and use passport for managing sessions
app.use(passport.initialize());
app.use(passport.session());


// MONGOOSE

mongoose.connect("mongodb://localhost:27017/"+database);

// setup mongoose schema
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

// Mongoose Plugins
// use passport-local-mongoose as plugin to hash and sort passwords
// this creates a local login strategy
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// Create object
const User = new mongoose.model("User", userSchema);

// Set Up serialze and deserialize
// Only necessary when using sessions
// serialize creates cookies and stores messages(e.g. user identification into cookies)
// deserialize allows passport to crumble the cookies and discover the messages
// inside which includes user identification so that we can authenticate them
// on our server
passport.use(User.createStrategy());

// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());


passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        id: user.id,
        username: user.username,
        picture: user.picture
      });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });


// Google OAuth20
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

// ------------------END POINTS----------------------

app.get(homeEndPoint, function(req,res){
    res.render("home");
});

app.get(googleEndPoint,
    // Authenticate on google service
    passport.authenticate("google", { scope: ["profile"] })
);

app.get(googleRedirectEndPoint, 
    // authenticate user locally and save login session
  passport.authenticate("google", { failureRedirect: loginEndPoint }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect(secretEndPoint);
  });

app.get(loginEndPoint, function(req,res){
    res.render("login");
});


app.get(registerEndPoint, function(req,res){

    res.render("register");
});

app.get(secretEndPoint, function(req, res){
    User.find({"secret": {$ne: null}}, function(err, foundUsers){
        if(err){
            console.log(err);
        }else{
            if (foundUsers){
                res.render("secrets", {usersWithSecrets: foundUsers});
            }
        }
    });
});

app.get(submitEndPoint, function(req, res){
    if (req.isAuthenticated()){
        res.render("submit");
    }else{
        res.redirect("login");
    }
});

app.get(logoutEndPoint, function(req, res){
    // deauthenticate (logout user)
    req.logout(function(err){
        if (err){
            console.log(err);
        }else{
            res.redirect(homeEndPoint);
        }
    });
});

app.post(registerEndPoint, function(req, res){
    //register comes from passport-local-mongoose
    // helps avoid creating and saving new user
   User.register({username: req.body.username}, req.body.password,function(err, user){
    if(err){
        console.log(err);
        res.redirect("register");
    }else{
        // Authenticate user using passport
        passport.authenticate("local")(req, res, function(){
            res.redirect("secrets");
        });
    }
   });
            
                                                     
});



app.post(loginEndPoint, function(req, res){

    const user = new User ({
        username: req.body.username,
        password: req.body.password
    });

    // use passport to login this user and authenticate him/er
    // we use a login() function that passport gives us
    // has to be called on the request object
    req.login(user, function(err) {
        if (err) {
            console.log(err);
        }else{
            // authenticate the user using local strategy
            passport.authenticate("local")(req, res, function(){
                res.redirect(secretEndPoint);
            })
        }
      });    
});

app.post(submitEndPoint, function(req, res){
    const submittedSecret = req.body.secret;

    User.findById(req.user.id, function(err, foundUser){
        if(err){
            console.log(err);
        }else{
            foundUser.secret = submittedSecret;
            foundUser.save(function(){
                res.redirect(secretEndPoint);
            });
        }
    });
});






//----------START SERVER

app.listen(port, function(){
    console.log("Listening on port....["+port+"].")
})