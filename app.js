require('dotenv').config();             // require dotenv // imp to declare first
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy; // OAuth stratergy
const findOrCreate = require("mongoose-findorcreate");

// const encrypt = require('mongoose-encryption');      // mongoose encrypt package
// const md5 = require("md5");
// const bcrypt = require("bcrypt");    // salting +hashing
// const saltRounds = 10; // used with bcrypt
const app = express();

// console.log(process.env.API_KEY);   // process.... is the enviornment variable

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({
  extended: true
}));

app.use(express.static("public"));

app.use(session({    // Session initialization // more options in docx 
  secret: 'keyboard cat.',
  resave: false,   // read in docs what they mean
  saveUninitialized: false, // false mean we don't store empty sessions
  // cookie: { secure: true }
}));


app.use(passport.initialize()); 
app.use(passport.session()); //the app.use sesion we made


mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser : true, useUnifiedTopology: true });
mongoose.set("useCreateIndex", true);  // used for passport-stratergy


const userSchema = new mongoose.Schema({ // Modifying schema to make it actual mongoose Schema
  email: String,
  password: String,
  googleId: String, // now you are finding that this user already exists so a new database entry won't be made
  secret: String
});

userSchema.plugin(passportLocalMongoose); // Used to salt our passwords and to save our users in Mongo
userSchema.plugin(findOrCreate); // findorcreate package usage

// var secret = "Thisisourlittlesecret."; //ENCRYPTN KEY  // Used to encrypt // goes to .env
// userSchema.plugin(encrypt, { secret: process.env.SECRET , encryptedFields: ["password"]}); // This encryption was only to demonstrate mmongoose-encryption but hashing is more superior so we use that.


const User = new mongoose.model("User", userSchema);


// Authenticating via passport-local
passport.use(User.createStrategy());
// level 6 auth           // part of OAuth
passport.serializeUser(function(user, done) { //serialize everything not only locally
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

// passport.serializeUser(User.serializeUser()); // Create Cookie
// passport.deserializeUser(User.deserializeUser());  // Destroy it

passport.use(new GoogleStrategy({  // part of OAuth
  clientID: process.env.CLIENT_ID,  // process.env is the variables from .env files
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets", // the one you specified in google
  userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
function(accessToken, refreshToken, profile, cb) { //accessToken allows us to get user's data
  console.log(profile);    // Get user's profile
  User.findOrCreate({ googleId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));


//TODO


app.get("/", function(req,res){
    res.render("home");
});

// For google AUTH
app.get("/auth/google",   // part of OAuth
  passport.authenticate('google', { scope: ["profile"] }) // Asking for user's profile //taken from documentation
);

app.get("/auth/google/secrets",     // part of OAuth
  passport.authenticate('google', { failureRedirect: "/login" }), // save thier login session
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });

//////////////////////////


app.get("/login", function(req,res){
    res.render("login");
});


app.get("/register", function(req,res){
    res.render("register");
});


app.get("/secrets", function(req,res){      // To find the secrets you typed

  User.find({"secret":{$ne:null}}, function(err,foundUser){       // WHERE secret is NOT NULL
    if(err){
      console.log(err)
    }
    else{
      if(foundUser){
        res.render("secrets", {usersWithSecrets: foundUser});
      }
      
    }
  });  
  // Code before custom submission

  // if(req.isAuthenticated()){  // if you are authenticated then you will be redirected to secrets page
  //   res.render("secrets");
  // }
  // else{
  //   res.redirect("/login");  // if you are not authenticated then you will be redirected to login page to login first only then u get access to it
  // }
});


app.get("/submit" , function(req,res){
  if(req.isAuthenticated()){  // if you are authenticated then you will be redirected to secrets page
    res.render("submit");
  }
  else{
    res.redirect("/login");
}
});


app.post("/submit" , function(req,res){ // Adding yo secret in the database
  const yourSecret = req.body.secret;
  console.log(req.user.id);     // Currently logged in user's id

  User.findById(req.user.id, function(err,foundUser){
    if(err){
      console.log(err);
    }
    else{
      if(foundUser){
        foundUser.secret = yourSecret;
        foundUser.save(function(){
          res.redirect("/secrets");    // reveal the saved secrets
        });
      }
    }
  });

});




app.get("/logout", function(req,res){   // deauthenticate user
  req.logout();
  res.redirect("/");
});


// after cookies and Session// hashing + salting included in PASSPORT
app.post("/register", function(req,res){
  User.register({username:req.body.username}, req.body.password, function(err, user){
    if(err){
      console.log(err);
      res.redirect("/register");
    }
    else{                     // If no errors then authenticate
      passport.authenticate("local")(req,res, function(){ // all code inside is the code that runs only if auth is successful
        res.redirect("/secrets");
      })
    }
  });

});




app.post("/login", function(req,res){
  const user = new User({
    username: req.body.username,
    password: req.body.password // md5 keyword to Hash the password
  }); 

  req.login(user , function(err){    // for login auth
    if(err){
      console.log(err);
      // res.redirect("login");
    }
    else{
      passport.authenticate("local")(req,res, function(){ // all code inside is the code that runs only if auth is successful
        res.redirect("/secrets");
    });
   }})
});








// OLD ONES[Before Sessions and Cookies]
// app.post("/register", function(req,res){
//   bcrypt.hash(req.body.password, saltRounds, function(err, hash) { // Store hash in your password DB.
//     const newUser = new User({
//       email: req.body.username,
//       password: hash // md5 keyword to Hash the password
//        }); 
  
//     newUser.save(function(err){             // When save command is executed the data gets encrypted
//       if(err){
//         console.log(err);
//       }
//       else{
//         res.render("secrets");
//       }
//     })
// });
  
// });


//  //////////////// Auth used here ///////////////

// app.post("/login", function(req,res){        
//   const username = req.body.username;
//   const password = req.body.password;   // register's md = login's md check

//   User.findOne({email: username}, function(err, foundUser){ // When find command is executed the data gets decrypted
//     if(err){
//       console.log(err);
//     }
//     else{
//       if(foundUser){
//         bcrypt.compare(password, foundUser.password, function(err, result) {         // comparing / Auth. bcrypted password
//           if(result===true){
//             res.render("secrets");
//           }
//           //check if result == true
//       });
//         // if(foundUser.password === password) {
//         //   res.render("secrets");
//         // }
//       }
//     }
// });
// });













app.listen(3000, function() {
  console.log("Server started on port 3000");
});
