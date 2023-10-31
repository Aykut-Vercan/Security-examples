//jshint esversion:6
require('dotenv').config();//.env diye bişey olusturduk onu bitek editorde göüryoruz
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose")
const encrypt = require("mongoose-encryption")

const app = express();

const port = 3000

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}))
const mongoURI = "mongodb://localhost:27017/userDB";

const connectToMongo = async () => {
    mongoose.connect(mongoURI, { useNewUrlParser: true }, await console.log("Connected to mongo `Successful`")
    );
}
connectToMongo();


const userSchema = new mongoose.Schema({
    email: String,
    password: String
})


userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] })//encryp paketi ekledik

const User = new mongoose.model("User", userSchema)

app.get("/", function (req, res) {
    res.render("home")
})

app.get("/login", function (req, res) {
    res.render("login")
})

app.get("/register", function (req, res) {
    res.render("register")
})

app.post("/register", function (req, res) {
    const newUser = new User({
        email: req.body.username,
        password: req.body.password
    })
    newUser.save().then(() => {
        res.render("secrets");
    }).catch((err) => {
        console.log(err);
    })
})

app.post("/login", function (req, res) {
    const username = req.body.username;
    const password = req.body.password;

    User.findOne({ email: username })
        .then((foundUser) => {
            if (foundUser) {
                if (foundUser.password === password) {
                    res.render("secrets")
                } else {
                    res.render("failLogin")
                }
            }
        })
        .catch((err) => {
            console.log(err)
        })

})




app.listen(port, function () {
    console.log("server started on port 3000")
})