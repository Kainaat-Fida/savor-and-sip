const express = require ("express")
const session = require("express-session")
const sqlite3 = require("sqlite3").verbose()
const bcrypt = require("bcrypt")
const path = require("path")
const bodyParser = require("body-parser")

const app = express()
app.use(express.urlencoded({ extended: true }))
app.use(express.json()); // this parses JSON bodies
const db = new sqlite3.Database("usersAccount.db")

app.set("view engine", "ejs")


app.use(bodyParser.urlencoded({ extended: false }))
app.use(express.static(path.join(__dirname, "public")));

app.use(session({
    secret: "savor_and_sip_secret_key", // change this to a strong secret
    resave: false,
    saveUninitialized: false
}));




// Database Setup
db.run(`CREATE TABLE IF NOT EXISTS usersLogin (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    password TEXT
)`);

//visit a URL get function is used
app.get("/", (req, res)=>{
    res.render("loginpage")
});

// Route to display login page (GET request)
app.get('/login', (req, res) => {
  res.render('loginpage', { error: null }); // ✅ this is what was missing
});

app.post("/signup", (req, res) => {
    const { name, email, password } = req.body;

    // Hash the password first
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            return res.render("loginpage", { error: "Password encryption failed." });
        }

        const sql = "INSERT INTO usersLogin (name, email, password) VALUES (?, ?, ?)";
        db.run(sql, [name, email, hashedPassword], function(err) {
            if (err) {
                // Show this error on the signup/login page
                return res.render("loginpage", { error: "User already exists or error occurred." });
            }
            req.session.user = { id: this.lastID, name, email };
            res.redirect("/home");
        });
    });
});

app.post("/login", (req, res) => {
    const { email, password } = req.body;

    db.get("SELECT * FROM usersLogin WHERE email = ?", [email], (err, user) => {
        if (err || !user) {
            return res.render("loginpage", { error: "Invalid email or password." });
        }

        bcrypt.compare(password, user.password, (err, result) => {
            if (result) {
                req.session.user = { id: user.id, name: user.name, email: user.email };
                res.redirect("/home");
            } else {
                res.render("loginpage", { error: "Invalid email or password." });
            }
        });
    });
});


//middleware to protect routes
function ensureLogin(req, res, next) {
    if (req.session.user) {
        next();
    } else {
        res.redirect("/");
    }
}



//middleware for protected routes
app.get("/home", ensureLogin, (req, res) => {
    res.render("homepage", { user: req.session.user });
});




//logout route
app.get("/logout", (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.log("Logout error:", err);
            return res.send("Error logging out.");
        }
        res.redirect("/");
    });
});






// Home Page
app.get("/home", (req, res) => {
    res.render("homepage"); // Or render a home.ejs page
});

// About Us
app.get("/about", (req, res) => {
    res.render("about");
});

// Tea & Coffee
app.get("/tea-coffee", (req, res) => {
    res.render("tea-coffee");
});

// Fast Food
app.get("/fastfood", (req, res) => {
    res.render("fastfood");
});

// Cart
app.get("/cart", (req, res) => {
    res.render("cart");
});

// Contact Us
app.get("/contact-us", (req, res) => {
    res.render("contact-us");
});

// checkout
app.get("/checkout", (req, res) => {
    res.render("checkout");
});

// dessert
app.get("/dessert", (req, res) => {
    res.render("dessert");
});

// soup-salad
app.get("/soup-salad", (req, res) => {
    res.render("soup-salad");
});

//-----------------------------------------
// Create orders Table in SQLite
db.run(`CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    name TEXT,
    email TEXT,
    address TEXT,
    items TEXT,
    total REAL,
    order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES usersLogin(id)
)`);

// Add a /checkout POST Route to Handle Order Saving
app.post("/checkout", ensureLogin, (req, res) => {
    const { name, email, address, cart, total } = req.body;
    const userId = req.session.user.id;

    const sql = `INSERT INTO orders (user_id, name, email, address, items, total) VALUES (?, ?, ?, ?, ?, ?)`;
    db.run(sql, [userId, name, email, address, cart, total], function(err) {
        if (err) {
            console.error("Error saving order:", err);
            return res.status(500).send("Error saving order.");
        }

        res.status(200).send("Order placed successfully");
    });
});




const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Server is running at http://localhost:${PORT}`);
});


