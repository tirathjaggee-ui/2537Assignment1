require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('./node_modules/connect-mongo/dist/index.d.cts');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const { MongoClient } = require('mongodb');

const app = express();

const PORT = process.env.PORT || 3000;
const expireTime = 60 * 60 * 1000; // 1 hour
const saltRounds = 12;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

const mongoUrl = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}`;

const client = new MongoClient(mongoUrl);
const database = client.db(mongodb_database);
const userCollection = database.collection('users');

app.use(express.urlencoded({ extended: false }));

const mongoStore = MongoStore.create({
    mongoUrl: mongoUrl,
    crypto: {
        secret: mongodb_session_secret
    }
});

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true,
    cookie: {
        maxAge: expireTime
    }
}));

app.get('/', (req, res) => {
    if (!req.session.authenticated) {
        res.send(`
            <h1>Home</h1>
            <a href="/signup">Sign up</a><br>
            <a href="/login">Log in</a>
        `);
    } else {
        res.send(`
            <h1>Hello, ${req.session.name}</h1>
            <a href="/members">Go to Members Area</a><br>
            <a href="/logout">Logout</a>
        `);
    }
});

app.get('/signup', (req, res) => {
    res.send(`
        <h1>Create user</h1>

        <form method="post" action="/signupSubmit">
            <input name="name" type="text" placeholder="name"><br>
            <input name="email" type="text" placeholder="email"><br>
            <input name="password" type="password" placeholder="password"><br>
            <button>Submit</button>
        </form>
    `);
});

app.post('/signupSubmit', async (req, res) => {
    const name = req.body.name;
    const email = req.body.email;
    const password = req.body.password;

    const schema = Joi.object({
        name: Joi.string().max(20).required(),
        email: Joi.string().max(50).required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({ name, email, password });

    if (validationResult.error != null) {
        res.send(`
            <h3>All fields are required.</h3>
            <a href="/signup">Try again</a>
        `);
        return;
    }

    const existingUser = await userCollection.find({ email: email }).toArray();

    if (existingUser.length > 0) {
        res.send(`
            <h3>Email already exists.</h3>
            <a href="/signup">Try again</a>
        `);
        return;
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({
        name: name,
        email: email,
        password: hashedPassword
    });

    req.session.authenticated = true;
    req.session.name = name;
    req.session.email = email;
    req.session.cookie.maxAge = expireTime;

    res.redirect('/members');
});

app.get('/login', (req, res) => {
    res.send(`
        <h1>Log in</h1>

        <form method="post" action="/loginSubmit">
            <input name="email" type="text" placeholder="email"><br>
            <input name="password" type="password" placeholder="password"><br>
            <button>Submit</button>
        </form>
    `);
});

app.post('/loginSubmit', async (req, res) => {
    const email = req.body.email;
    const password = req.body.password;

    const schema = Joi.object({
        email: Joi.string().max(50).required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({ email, password });

    if (validationResult.error != null) {
        res.send(`
            <h3>Invalid email/password combination.</h3>
            <a href="/login">Try again</a>
        `);
        return;
    }

    const result = await userCollection.find({ email: email }).toArray();

    if (result.length != 1) {
        res.send(`
            <h3>Invalid email/password combination.</h3>
            <a href="/login">Try again</a>
        `);
        return;
    }

    const correctPassword = await bcrypt.compare(password, result[0].password);

    if (correctPassword) {
        req.session.authenticated = true;
        req.session.name = result[0].name;
        req.session.email = result[0].email;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/members');
    } else {
        res.send(`
            <h3>Invalid email/password combination.</h3>
            <a href="/login">Try again</a>
        `);
    }
});

app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
        return;
    }

    const images = ['nature1.jpg', 'nature2.jpg', 'nature3.jpg'];
    const randomImage = images[Math.floor(Math.random() * 3)];

    res.send(`
        <h1>Hello, ${req.session.name}</h1>
        <img src="/${randomImage}" width="300"><br>
        <a href="/logout">Sign out</a>
    `);
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.use(express.static(__dirname + "/public"));

app.use((req, res) => {
    res.status(404);
    res.send("Page not found - 404");
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});