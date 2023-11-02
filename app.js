//jshint esversion:6
require('dotenv').config();//.env diye bişey olusturduk onu bitek editorde göüryoruz
const express = require("express");//server için
const bodyParser = require("body-parser");//body ulasmak için
const ejs = require("ejs");//ejs
const mongoose = require("mongoose")//db
//const encrypt = require("mongoose-encryption")//şifrelemek için
//const md5 = require("md5")//bunu hashing için ekledik nedir bilmem
//const bcrypt = require('bcryptjs');
//const salt = bcrypt.genSaltSync(10);
const session = require('express-session')
const passport = require('passport')
const passportLocalMongoose = require('passport-local-mongoose')
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate')



const app = express();

const port = 3000

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}))

/*express session passport */
app.use(session({
    secret: "Fenerbahçe",
    resave: false,
    saveUninitialized: false
}))

app.use(passport.initialize());
app.use(passport.session());


const mongoURI = "mongodb://localhost:27017/userDB";

const connectToMongo = async () => {
    mongoose.connect(mongoURI, { useNewUrlParser: true }, await console.log("Connected to mongo `Successful`"))
}
connectToMongo();

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
})
//userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] })//encryp paketi ekledik

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema)

passport.use(User.createStrategy());
passport.serializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, {
            id: user.id,
            username: user.username,
            picture: user.picture
        });
    });
});

passport.deserializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    //scope: ["email", "profile"]
},
    function (accessToken, refreshToken, profile, cb) {
        console.log(accessToken)
        console.log("-----------------------------------------")
        console.log(profile)
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));



app.get("/", function (req, res) {
    res.render("home")
})

app.get("/auth/google", passport.authenticate("google", { scope: ["profile"] }))


app.get('/auth/google/secrets', passport.authenticate('google', { failureRedirect: '/login' }), function (req, res) {
    // Successful authentication, redirect secret.
    res.redirect('/secrets');
});


app.get("/login", function (req, res) {
    res.render("login")
})

app.get("/register", function (req, res) {
    res.render("register")
})


app.get("/secrets", function (req, res) {
    User.find({ "secret": { $ne: null } })//not equal to null secrete boş olmayanları bul
        .then((foundUsers) => {
            res.render("secrets", { usersWithSecrets: foundUsers })
        })
        .catch((err) => { console.log(err) })

})

app.get("/submit", function (req, res) {
    if (req.isAuthenticated()) {
        res.render("submit")
    } else {
        res.redirect("/login")
    }
})

app.get("/logout", function (req, res) {
    req.logout(function (err) {
        if (err) {
            console.log(err)
        }
        else {
            res.redirect("/")
        }
    })
})



/*POSTS*/
app.post("/submit", function (req, res) {
    const submittedSecret = req.body.secret;

    User.findById(req.user.id)
        .then((foundUser) => {
            foundUser.secret = submittedSecret;
            foundUser.save().then(() => {
                res.redirect("/secrets")
            })
        }
        ).catch((err) => {
            console.log(err)
        })

})

app.post("/register", function (req, res) {
    //const hashedPassword = bcrypt.hashSync(req.body.password, salt)
    /* const hash = bcrypt.hashSync(req.body.password, salt);
     const newUser = new User({
         email: req.body.username,
         password: hash
     })
     newUser.save().then(() => {
         res.render("secrets");
     }).catch((err) => {
         console.log(err);
     })*/
    console.log(req.body)
    /*Passport express session*/
    User.register({ username: req.body.username, }, req.body.password, function (err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register")
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets")
            })
        }
    }
    )

})

app.post("/login", function (req, res) {
    /* const username = req.body.username;
     const password = req.body.password;
 
     User.findOne({ email: username })
         .then((foundUser) => {
             if (foundUser) {
                 bcrypt.compareSync(password, foundUser.password) ? res.render("secrets") : res.render("failLogin")
             }
         })
         .catch((err) => {
             console.log(err)
         })
 */

    /*passport-local-mongoose*/
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    req.login(user, function (err) {
        if (err) {
            console.log(err)
        }
        else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets")
            })
        }
    })

})




app.listen(port, function () {
    console.log("server started on port 3000")
})