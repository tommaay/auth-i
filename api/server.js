const express = require("express");
const helmet = require("helmet");
const knex = require("knex");
const knexConfig = require("../knexfile");
const bcrypt = require("bcryptjs");
const session = require("express-session");

const server = express();

const db = knex(knexConfig.development);

const sessionConfig = {
  name: "ayo", // default is sid, but this will show you are using the library
  secret: "kjdfhasgyrahbbvkjsdbfiaasbfyabf",
  cookie: {
    maxAge: 1000 * 60 * 10,
    secure: false // only send the cookie over https, use true in production
  },
  httpOnly: true, // js can't touch this cookie
  resave: false, // read about this
  saveUninitialized: false // read about this
};

server.use(helmet());
server.use(express.json());
server.use(session(sessionConfig));

server.get("/", (req, res) => {
  res.send("Sanity check.");
});

server.post("/users/register", async (req, res) => {
  const userInfo = req.body;

  // hash the password
  const hash = bcrypt.hashSync(userInfo.password, 12);
  userInfo.password = hash;

  db("users")
    .insert(userInfo)
    .then(ids => res.status(201).json(ids))
    .catch(err => res.status(500).json(err));
});

server.post("/login", (req, res) => {
  const creds = req.body;

  db("users")
    .where({ username: creds.username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(creds.password, user.password)) {
        req.session.user = user;
        res.status(200).json({ message: `Welcome ${user.name}` });
      } else {
        res.status(401).json({ message: "You shall not pass." });
      }
    })
    .catch(err => res.status(500).json(err));
});

function protected(req, res, next) {
  // if the user us logged in, we call next()
  if (req.session && req.session.user) {
    console.log(req.session);
    next();
  } else {
    res.status(401).json({ message: "You shall not pass, not authenticated." });
  }
}

server.get("/users", protected, async (req, res) => {
  const users = await db("users");
  res.json(users);
});

server.get("/logout", (req, res) => {
  if (req.session) {
    req.session.destroy(err => {
      if (err) {
        res.status(500).send("You can never leave.");
      } else {
        res.status(200).send("Bye bye");
      }
    });
  } else {
    res.json({ message: "Already logged out." });
  }
});

module.exports = server;
