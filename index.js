const express = require("express");
const session = require("express-session");
const MongoDBSession = require("connect-mongodb-session")(session);
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const path = require("path");
require("dotenv").config()

const app = express();
const PORT = process.env.PORT || 5000;

const userModel = require("./models/User");
const mongoURI = process.env.MONGOURI;

const store = new MongoDBSession({
  uri: mongoURI,
  collection: "sessions",
});

app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: "key",
    resave: false,
    saveUninitialized: false,
    store,
  })
);
app.use(express.static("./public/"));

mongoose
  .connect(mongoURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("Database Connected");
  })
  .catch((err) => {
    console.log("Database Connection Error:", err);
  });

const isAuth = (req, res, next) => {
    if (req.session.isAuth) {
      next();
    } else {
      res.redirect("/login");
    }
};
const notAuth = (req,res,next) => {
  if (!req.session.isAuth) {
    next();
  } else {
    res.redirect("/dashboard");
  }
}
const isVerifying = (req,res,next) =>
{
  if(req.session.isVerifying)
  {
    next();
  }
  else {
    res.redirect("/")
  }
}
const nodemailer = require("nodemailer")

let transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    type: 'OAuth2',
    user: process.env.MAIL_USERNAME,
    pass: process.env.MAIL_PASSWORD,
    clientId: process.env.OAUTH_CLIENTID,
    clientSecret: process.env.OAUTH_CLIENT_SECRET,
    refreshToken: process.env.OAUTH_REFRESH_TOKEN
  }
});

function generateVerificationKey()
{
  key = Math.floor(Math.random() * 90000) + 10000;
  return key
}
function sendEmail(options)
{
  transporter.sendMail(options,(err,info)=>{
    if(err)
    {
        return console.log("Error Occured When Sending Email",err)
    }
    console.log("Email Sent",info.response)
})
}

app.get("/", notAuth, (req, res) => {
  res.redirect("/login")
});
app.get("/login", notAuth, (req, res) => {
  res.sendFile(path.resolve(__dirname, "./views/login.html"));
});
app.get("/register", (req, res) => {
  res.sendFile(path.resolve(__dirname, "./views/register.html"));
});
app.get("/dashboard", isAuth, ( req, res) => {
  res.sendFile(path.resolve(__dirname, "./views/dashboard.html"));
});
app.get("/verify",isVerifying,async (req,res)=>
{
  key = String(generateVerificationKey())
  username=req.session.loginUsername
  let user = await userModel.findOneAndUpdate({username},{lastVerKey:key})
  res.sendFile(path.resolve(__dirname, "./views/verificator.html"))
  const mailOptions = {
    from: process.env.MAIL_USERNAME,
    to: user.email,
    subject: 'Hello, Please verify your login.',
    text: "Code: "+key
  }
  sendEmail(mailOptions)
})

app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;

  let user = await userModel.findOne({ email });

  if (user) {
    return res.redirect("/register");
  }

  let user1 = await userModel.findOne({username})

  if(user1) {
    return res.redirect("/register")
  }
  const hashedPsw = await bcrypt.hash(password, 12);
  user = new userModel({
    username,
    email,
    password: hashedPsw,
  });

  await user.save();

  res.redirect("/login");
});
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  let user = await userModel.findOne({ username })
  if (!user) {
    return res.redirect("/login");
  }

  const isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch) {
    return res.redirect("/login");
  }
  req.session.loginUsername = username
  req.session.isVerifying = true
  res.redirect("/verify")
});
app.post("/logout", async (req, res) => {
  req.session.destroy((err) => {
    if (err) throw err;
    res.redirect("/");
  });
});
app.post("/verify", async (req,res)=>{
  username = req.session.loginUsername
  let user = await userModel.findOne({username})

  const {key} = req.body
  const realkey = user.lastVerKey

  if(key != realkey)
  {
    console.log("No Match")
    return res.redirect("/verify")
  }
  console.log("Match")
  req.session.isAuth=true
  req.session.isVerifying=false
  res.redirect("/dashboard")
})

app.listen(PORT, console.log("Server Started On Port:", PORT));