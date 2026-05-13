require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const { MongoClient } = require('mongodb');

const app = express();

const PORT = process.env.PORT || 10000;
const expireTime = 60 * 60 * 1000;
const saltRounds = 12;

// database info
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

// mongodb connection
const mongoUrl = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}`;

const client = new MongoClient(mongoUrl);

client.connect();

const database = client.db(mongodb_database);
const userCollection = database.collection('users');

// middleware
app.use(express.urlencoded({ extended: false }));

app.use(express.static(__dirname + "/public"));

app.set("view engine", "ejs");

// encrypted mongodb session store
const mongoStore = MongoStore.create({
    mongoUrl: mongoUrl,
    collectionName: 'sessions',
    crypto: {
        secret: mongodb_session_secret
    },
    ttl: 60 * 60
});

// sessions
app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: false,
    cookie: {
        maxAge: expireTime
    }
}));

// middleware for logged in users
function requireLogin(req, res, next) {

    if (!req.session.authenticated) {
        return res.redirect("/login");
    }

    next();
}

// middleware for admins only
function requireAdmin(req, res, next) {

    if (!req.session.authenticated) {
        return res.redirect("/login");
    }

    if (req.session.user_type != "admin") {
        res.status(403);
        return res.send("You are not authorized.");
    }

    next();
}

// HOME PAGE
app.get('/', (req, res) => {

    res.render("index", {
        authenticated: req.session.authenticated,
        name: req.session.name
    });
});

// SIGNUP PAGE
app.get('/signup', (req, res) => {

    res.render("signup");
});

// HANDLE SIGNUP
app.post('/signupSubmit', async (req, res) => {

    const name = req.body.name;
    const email = req.body.email;
    const password = req.body.password;

    // validate form
    const schema = Joi.object({
        name: Joi.string().max(20).required(),
        email: Joi.string().max(50).required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({
        name,
        email,
        password
    });

    if (validationResult.error != null) {

        res.send(`
            <h3>All fields are required.</h3>
            <a href="/signup">Try again</a>
        `);

        return;
    }

    // check if email already exists
    const existingUser = await userCollection.find({
        email: email
    }).toArray();

    if (existingUser.length > 0) {

        res.send(`
            <h3>Email already exists.</h3>
            <a href="/signup">Try again</a>
        `);

        return;
    }

    // hash password
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // insert user
    await userCollection.insertOne({
        name: name,
        email: email,
        password: hashedPassword,
        user_type: "user"
    });

    // create session
    req.session.authenticated = true;
    req.session.name = name;
    req.session.email = email;
    req.session.user_type = "user";
    req.session.cookie.maxAge = expireTime;

    req.session.save(() => {
        res.redirect("/members");
    });
});

// LOGIN PAGE
app.get('/login', (req, res) => {

    res.render("login");
});

// HANDLE LOGIN
app.post('/loginSubmit', async (req, res) => {

    const email = req.body.email;
    const password = req.body.password;

    // validate form
    const schema = Joi.object({
        email: Joi.string().max(50).required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({
        email,
        password
    });

    if (validationResult.error != null) {

        res.send(`
            <h3>Invalid email/password combination.</h3>
            <a href="/login">Try again</a>
        `);

        return;
    }

    // find user
    const result = await userCollection.find({
        email: email
    }).toArray();

    if (result.length != 1) {

        res.send(`
            <h3>Invalid email/password combination.</h3>
            <a href="/login">Try again</a>
        `);

        return;
    }

    // compare hashed password
    const correctPassword = await bcrypt.compare(
        password,
        result[0].password
    );

    if (correctPassword) {

        req.session.authenticated = true;
        req.session.name = result[0].name;
        req.session.email = result[0].email;
        req.session.user_type = result[0].user_type;
        req.session.cookie.maxAge = expireTime;

        req.session.save(() => {
            res.redirect("/members");
        });

    } else {

        res.send(`
            <h3>Invalid email/password combination.</h3>
            <a href="/login">Try again</a>
        `);
    }
});

// MEMBERS PAGE
app.get('/members', requireLogin, (req, res) => {

    const images = [
        "nature1.jpg",
        "nature2.jpg",
        "nature3.jpg"
    ];

    res.render("members", {
        name: req.session.name,
        images: images
    });
});

// ADMIN PAGE
app.get('/admin', requireAdmin, async (req, res) => {

    const users = await userCollection.find({}).toArray();

    res.render("admin", {
        users: users
    });
});

// PROMOTE USER
app.get('/promote/:email', requireAdmin, async (req, res) => {

    await userCollection.updateOne(
        {
            email: req.params.email
        },
        {
            $set: {
                user_type: "admin"
            }
        }
    );

    res.redirect("/admin");
});

// DEMOTE USER
app.get('/demote/:email', requireAdmin, async (req, res) => {

    await userCollection.updateOne(
        {
            email: req.params.email
        },
        {
            $set: {
                user_type: "user"
            }
        }
    );

    res.redirect("/admin");
});

// LOGOUT
app.get('/logout', (req, res) => {

    req.session.destroy();

    res.redirect('/');
});

// 404 PAGE
app.use((req, res) => {

    res.status(404);

    res.render("404");
});

// start server
app.listen(PORT, () => {

    console.log(`Server running on http://localhost:${PORT}`);
});