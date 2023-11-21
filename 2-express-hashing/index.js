const express = require("express");
const session = require("express-session");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("crypto");
const app = express();
const port = 3000;

// Middleware
app.use(express.static(__dirname + "/public"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session
app.use(
  session({
    secret: "Keep it secret", // Secret key used to sign the session ID cookie
    resave: false, // Don't save session if unmodified
    name: "uniqueSessionID", // Change the name of the session ID cookie
    saveUninitialized: false, // Don't create a session until something is stored
    cookie: {
      secure: false, // Set to true if your app is served over HTTPS
      maxAge: 3600000, // Session expiration time in milliseconds (e.g., 1 hour)
    },
  })
);

// SQLite database
const db = new sqlite3.Database("./db.sqlite");

db.serialize(function () {
  console.log("creating databases if they don't exist");
  db.run(
    "create table if not exists users (id integer primary key, username text not null, password text not null)"
  );
});

// Tilføjer user til db
const addUserToDatabase = (username, password) => {
  db.run(
    "insert into users (username, password) values (?, ?)",
    [username, password],
    function (err) {
      if (err) {
        console.error(err);
      }
    }
  );
};

// Smart måde at konvertere fra Callback til Promise
// Callback er den funktion der bliver kaldt når db.all er færdig med at hente data
// Promise er en måde at håndtere asynkrone kald på
const getUserByUsername = (username) => {
  return new Promise((resolve, reject) => {
    db.all(
      "select * from users where username=(?)",
      [username],
      (err, rows) => {
        if (err) {
          console.error(err);
          return reject(err);
        }
        return resolve(rows);
      }
    );
  });
};

// Hashing af password med md5
const md5sum = crypto.createHash("md5");
const salt = "Some salt for the hash";

// Funktion til at hashe password
const hashPassword = (password) => {
  return md5sum.update(password + salt).digest("hex");
};

// Hvis brugeren er logget ind, så sendes de til dashboard, ellers sendes de til login siden
app.get("/", (req, res) => {
  if (req.session.loggedIn) {
    return res.redirect("/dashboard");
  } else {
    return res.sendFile("login.html", { root: path.join(__dirname, "public") });
  }
});

// Et dashboard som kun brugere med 'loggedIn' = true i session kan se
app.get("/dashboard", (req, res) => {
  if (req.session.loggedIn) {
    return res.sendFile("dashboard.html", {
      root: path.join(__dirname, "public"),
    });
  } else {
    return res.redirect("/");
  }
});

// Side til at oprette bruger
app.get("/signup", (req, res) => {
  if (req.session.loggedIn) {
    return res.redirect("/dashboard");
  } else {
    return res.sendFile("signup.html", {
      root: path.join(__dirname, "public"),
    });
  }
});

// Opret bruger i databasen
app.post("/signup", async (req, res) => {
  const user = await getUserByUsername(req.body.username);
  if (user.length > 0) {
    return res.send("Username already exists");
  }

  // Opgave 1
  // Brug funktionen hashPassword til at kryptere passwords før de gemmes i databasen
  addUserToDatabase(req.body.username, req.body.password);
  res.redirect("/");
});

// Checker brugerens loginoplysninger
app.post("/authenticate", async (req, res) => {
  // Opgave 2
  // Programmer så at brugeren kan logge ind med sit brugernavn og password

  // Hint: Her skal vi tjekke om brugeren findes i databasen og om passwordet er korrekt
  // Hint: Se funktionen getUserByUsername og brug funktionen hashPassword til at anvende hashing

  // Henter vi brugeren ud fra databasen
  // const user = await getUserByUsername('test')
  // console.log({user});

  if (req.body.username == "test" && req.body.password == "password") {
    req.session.loggedIn = true;
    req.session.username = req.body.username;
    console.log(req.session);
    res.redirect("/dashboard");
  } else {
    // Sender en statuskode 401 (unauthorized) til klienten
    return res.sendStatus(401);
  }
});

// Log ud
app.get("/logout", (req, res) => {
  req.session.destroy((err) => {});
  return res.sendFile("logout.html", { root: path.join(__dirname, "public") });
});

// Start server
app.listen(port, () => {
  console.log("Server listening on port " + port);
});