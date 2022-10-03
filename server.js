const express = require("express");
const app = express();
const { pool } = require("./dbConfig");
const bcrypt = require("bcrypt");
const session = require("express-session");
const flash = require("express-flash");
const passport = require("passport");

const http = require('http');
const server = http.createServer(app);
const { Server } = require("socket.io");
const io = new Server(server);

var path = require('path');
app.use(express.static(path.join(__dirname, 'public')));


app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

var userCount = 0;
io.on('connection', (socket) => {
    userCount++;
    io.sockets.emit('userCount', { userCount: userCount });
    console.log('a user connected');
    socket.on('disconnect', () => {
        userCount--;
        io.sockets.emit('userCount', { userCount: userCount });
        console.log('user disconnected');
    });
});

const initializePassport = require("./passportConfig");

initializePassport(passport);
const PORT = process.env.PORT || 4000;

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: false }));
app.use(session({
    secret: "secret",

    resave: false,

    saveUnitialized: false
})
);
app.use(passport.initialize());
app.use(passport.session());
app.use(express.json());
app.use(flash());

app.get("/", (req, res) => {
    res.render("index");
})

app.get("/users/register", checkAuthenticated, (req, res) => {
    res.render("register");
});

app.get("/users/login", checkAuthenticated, (req, res) => {
    res.render("login");
});

app.get("/users/dashboard", checkNotAuthenticated, (req, res) => {
    res.render("dashboard", { user: req.user.first_name + req.user.last_name });
    console.log(req.user.first_name);
    console.log(req.user.last_name);
});


app.get('/users/logout', function (req, res, next) {
    req.logout(function (err) {
        if (err) { return next(err); }
        req.flash('success_msg', "You have logged out.");
        res.redirect("/users/login");
    });
})

app.post("/users/register", async (req, res) => {
    let { name, last, email, phone, password, password2 } = req.body;
    console.log({
        name,
        last,
        email,
        phone,
        password,
        password2
    });

    let errors = [];

    if (!name || !email || !password || !password2) {
        errors.push({ message: "Please enter all fields" });
    }

    if (password.length < 6) {
        errors.push({ message: "Password should be at least 6 characters" });
    }
    if (password != password2) {
        errors.push({ message: "Passwords do not match " });
    }
    if (errors.length > 0) {
        res.render("register", { errors });
    } else {
        // form validation pass
        let hashedPassword = await bcrypt.hash(password, 10);
        console.log(hashedPassword);

        pool.query(
            `SELECT * FROM users WHERE email = $1`,
            [email],
            (err, results) => {
                if (err) {
                    throw err;
                }
                console.log(results.rows);
                if (results.rows.length > 0) {
                    errors.push({ message: "Email already registered" });
                    res.render("register", { errors });
                } else {
                    pool.query(
                        `INSERT INTO users(first_name,last_name,email,phone, password) VALUES($1, $2, $3, $4, $5) RETURNING id,password`, [name, last, email, phone, hashedPassword], (err, results) => {
                            if (err) {
                                throw err;
                            }
                            console.log(results.rows);
                            req.flash("success_msg", "You are now registered.Please log in");
                            res.redirect("/users/login");
                        }
                    );
                }
            }
        );
    }
});
app.post("/users/login", passport.authenticate("local", {
    successRedirect: "/users/dashboard",
    failureRedirect: "/users/login",
    failureFlash: true
}));

function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect("/users/dashboard");
    }
    next();
}

function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect("/users/login");
}

server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});