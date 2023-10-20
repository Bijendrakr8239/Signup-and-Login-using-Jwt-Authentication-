require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const app = express();
const User = require("./models/user");
const LoginToken = require("./models/token");
const bodyParser = require("body-parser");
app.use(bodyParser.json());
const path = require("path");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { error } = require("console");
secret_key = process.env.SECRET_KEY;
mongoose
  .connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("Database Connected");
  })
  .catch((err) => {
    console.log("Error in connecting Database", err);
  });

app.post("/signup", async function (req, res) {
  const emailExit = await User.findOne({ email: req.body.email });
  if (emailExit)
    return res.status(400).send("Email already exists try another email");
  const userdata = req.body;
  const saltRounds = 10;
  const hashedPassword = await bcrypt.hash(userdata.password, saltRounds);
  userdata.password = hashedPassword;
  const newUser = new User(userdata);
  newUser
    .save()
    .then((user) => {
      const token = jwt.sign({ user }, secret_key, { expiresIn: "1h" });
      res.status(201).json({ message: "User Created", token: token });
    })
    .catch((error) => {
      res.status(400).json(error);
    });
});

app.post("/login", (req, res) => {
  let userData = req.body;
  User.findOne({ email: req.body.email }).then((user) => {
    if (user) {
      const validPassword = bcrypt.compare(userData.password, user.password);
      if (!validPassword) {
        res.status(401).json("Invalid Password");
      } else {
        const data = user.email;
        const token = jwt.sign({ data }, secret_key, { expiresIn: "1h" });
        LoginToken.findOne({ email: userData.email })
          .then((existingToken) => {
            if (existingToken) {
              existingToken.token = token;
              return existingToken.save();
            } else {
              const userToken = new LoginToken({
                email: userData.email,
                token: token,
              });
              return userToken.save();
            }
          })
          .then(() => {
            res
              .status(200)
              .json({ message: "Login Successfull", token: token });
          })
          .catch((error) => {
            console.error(error);
            res
              .status(401)
              .json({ message: "Failed to save token to database" });
          });
      }
    } else {
      res.json({ message: "Email Not Found" });
    }
  });
});

async function verifyToken(req,res,next){
  const token = req.header('authorization');
  if(!token){
    return res.status(401).json({message:'Unauthorized'});
  }
  try{
   const decoded = jwt.verify(token,secret_key);
   const tokenInDB = await LoginToken.findOne({
    email:decoded.data,
    token:token,
   });
   if(!tokenInDB){
    return res.status(401).json({message:'Token is inValid'});
   } 
   
   req.email = tokenInDB.email;
   next();
  }
  catch(error){
    return res.status(401).json({message:'Token is invalid'});
  }
}

app.get("/protected", verifyToken,(req, res) => {
  res.json({message:'Access granted for user:'+req.email});
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`App listening on port ${port}`));
