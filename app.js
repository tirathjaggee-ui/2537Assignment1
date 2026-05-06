require('dotenv').config(); // loads variables from .env file

const express = require('express'); // web framework
const session = require('express-session'); // session handling
const MongoStore = require('connect-mongo'); // store sessions in MongoDB
const bcrypt = require('bcrypt'); // hash passwords
const Joi = require('joi'); // validate user input
const { MongoClient } = require('mongodb'); // connect to MongoDB

const app = express(); // create express app

const PORT = process.env.PORT || 10000; // server port
const expireTime = 60 * 60 * 1000; // session lasts 1 hour
const saltRounds = 12; // strength of password hashing

// get database info from .env
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

// build MongoDB connection string
const mongoUrl = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}`;

// connect to database
const client = new MongoClient(mongoUrl);
client.connect();
const database = client.db(mongodb_database);
const userCollection = database.collection('users'); // collection for users

app.use(express.urlencoded({ extended: false })); // allows reading form data

// create session store in MongoDB
const mongoStore = MongoStore.create({
    mongoUrl: mongoUrl,
    collectionName: 'sessions',
});

// configure sessions
app.use(session({
    secret: node_session_secret, // session secret key
    store: mongoStore, // store sessions in MongoDB
    saveUninitialized: false,
    resave: false,
    cookie: {
        maxAge: expireTime // session expiry time
    }
}));

// HOME PAGE
app.get('/', (req, res) => {
    if (!req.session.authenticated) {
        // user NOT logged in
        res.send(`
            <h1>Home</h1>
            <a href="/signup">Sign up</a><br>
            <a href="/login">Log in</a>
        `);
    } else {
        // user IS logged in
        res.send(`
            <h1>Hello, ${req.session.name}</h1>
            <a href="/members">Go to Members Area</a><br>
            <a href="/logout">Logout</a>
        `);
    }
});

// SIGNUP PAGE
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

// HANDLE SIGNUP
app.post('/signupSubmit', async (req, res) => {
    const name = req.body.name;
    const email = req.body.email;
    const password = req.body.password;

    // validate inputs using Joi
    const schema = Joi.object({
        name: Joi.string().max(20).required(),
        email: Joi.string().max(50).required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({ name, email, password });

    if (validationResult.error != null) {
        // if invalid input
        res.send(`
            <h3>All fields are required.</h3>
            <a href="/signup">Try again</a>
        `);
        return;
    }

    // check if user already exists
    const existingUser = await userCollection.find({ email: email }).toArray();

    if (existingUser.length > 0) {
        res.send(`
            <h3>Email already exists.</h3>
            <a href="/signup">Try again</a>
        `);
        return;
    }

    // hash password
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // insert new user into database
    await userCollection.insertOne({
        name: name,
        email: email,
        password: hashedPassword
    });

    // create session
    req.session.authenticated = true;
    req.session.name = name;
    req.session.email = email;
    req.session.cookie.maxAge = expireTime;

    req.session.save(() => {
        res.redirect('/members'); // go to members page
    });
});

// LOGIN PAGE
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

// HANDLE LOGIN
app.post('/loginSubmit', async (req, res) => {
    const email = req.body.email;
    const password = req.body.password;

    // validate input
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

    // find user in DB
    const result = await userCollection.find({ email: email }).toArray();

    if (result.length != 1) {
        res.send(`
            <h3>Invalid email/password combination.</h3>
            <a href="/login">Try again</a>
        `);
        return;
    }

    // compare password with hashed one
    const correctPassword = await bcrypt.compare(password, result[0].password);

    if (correctPassword) {
        // login success → create session
        req.session.authenticated = true;
        req.session.name = result[0].name;
        req.session.email = result[0].email;
        req.session.cookie.maxAge = expireTime;

        req.session.save(() => {
            res.redirect('/members');
        });
    } else {
        res.send(`
            <h3>Invalid email/password combination.</h3>
            <a href="/login">Try again</a>
        `);
    }
});

// MEMBERS PAGE (protected)
app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        // block access if not logged in
        res.redirect('/');
        return;
    }

    // pick random image
    const images = ['nature1.jpg', 'nature2.jpg', 'nature3.jpg'];
    const randomImage = images[Math.floor(Math.random() * 3)];

    res.send(`
        <h1>Hello, ${req.session.name}</h1>
        <img src="/${randomImage}" width="300"><br>
        <a href="/logout">Sign out</a>
    `);
});

// LOGOUT
app.get('/logout', (req, res) => {
    req.session.destroy(); // destroy session
    res.redirect('/'); // go back home
});

// serve static files from /public folder (images, css, etc)
app.use(express.static(__dirname + "/public"));

// 404 PAGE (any unknown route)
app.use((req, res) => {
    res.status(404);
    res.send("Page not found - 404");
});


// start server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});