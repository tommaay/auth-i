const express = require("express");
const helmet = require("helmet");
const knex = require("knex");
const knexConfig = require("../knexfile");
const bcrypt = require("bcryptjs");

const server = express();

const db = knex(knexConfig.development);

server.use(helmet());
server.use(express.json());

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

server.get("/users", async (req, res) => {
  const users = await db("users");
  res.json(users);
});

server.post("/login", (req, res) => {
  const creds = req.body;

  db("users")
    .where({ username: creds.username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(creds.password, user.password)) {
        res.status(200).json({ message: `Weclome ${user.name}` });
      } else {
        res.status(401).json({ message: "Cannot login." });
      }
    })
    .catch(err => res.status(500).json(err));
});

module.exports = server;
