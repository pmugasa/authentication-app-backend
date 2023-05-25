require("dotenv").config();
const express = require("express");
const app = express();
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const bcrypt = require("bcryptjs");
const LocalStrategy = require("passport-local").Strategy;

//mongoDB config
mongoose.set("strictQuery", false);
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("Connected to mongoDB");
  })
  .catch((err) => console.error(err.message));

//user schema
const userSchema = new mongoose.Schema({
  photo: String,
  name: String,
  bio: String,
  phone: String,
  email: String,
  passwordHash: String,
});
userSchema.set("toJSON", {
  transform: (document, returnedObject) => {
    returnedObject.id = returnedObject._id.toString();
    delete returnedObject._id;
    delete returnedObject.__v;
    // the passwordHash should not be revealed
    delete returnedObject.passwordHash;
  },
});
const User = mongoose.model("User", userSchema);

//local strategy setup middleware
passport.use(
  new LocalStrategy(
    { usernameField: "email" },
    async (email, password, done) => {
      try {
        const user = await User.findOne({ email: email });
        if (!user) {
          return done(null, false, { message: "Incorrect email" });
        }
        bcrypt.compare(password, user.passwordHash, (err, res) => {
          if (res) {
            // Passwords match! Log the user in
            return done(null, user);
          } else {
            // Passwords do not match
            return done(null, false, { message: "Incorrect password" });
          }
        });
      } catch (err) {
        return done(err);
      }
    }
  )
);

//sessions and serialization
passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(async function (id, done) {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});
//middleware
app.use(express.json());
app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(passport.initialize());
app.use((req, res, next) => {
  res.locals.currentUser = req.user;
  next();
});
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

//ROUTES
app.get("/", (req, res) => {
  res.json({ user: req.user });
});

//register with email & password
app.post("/api/register", async (req, res) => {
  const { email, password } = req.body;
  const saltRounds = 10;
  const passwordHash = await bcrypt.hash(password, saltRounds);

  try {
    const user = new User({
      email: email,
      passwordHash: passwordHash,
    });
    const savedUser = await user.save();
    res.status(201).json(savedUser);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

//login with email & password
app.post("/api/login", function (req, res, next) {
  passport.authenticate("local", (err, user, info) => {
    console.log(user, "user");

    if (err) {
      return next(err);
    }
    if (!user) {
      return res.status(404).json(info);
    }
    req.login(user, (err) => {
      if (err) {
        return next(err);
      }
      // Successful login, redirect to the desired location
      return res.status(200).json({ user: req.user });
    });
  })(req, res, next);
});

//loging out
app.get("/api/logout", (req, res, next) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.status(200).send("Logged out successfully");
  });
});

const PORT = 3001;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
