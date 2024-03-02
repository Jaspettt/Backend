const dayjs = require('dayjs')
const express = require("express");
const sendEmail = require('./emailSender');
const app = express();
const { pool } = require('./dbConfig');
const bcrypt = require('bcrypt');
const session = require('express-session');
const flash = require('express-flash');
const passport = require('passport');

const bodyParser = require('body-parser');
const multer = require('multer');
const fs = require('fs');

const initiazilePassport = require('./passportConfig');

initiazilePassport(passport)

const PORT = process.env.PORT || 3000;

app.set('view engine', 'ejs');
app.use(express.urlencoded({extended: false}));
app.use(express.static(__dirname + '/public'));
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
    secret: 'secret',

    resave: false,

    saveUninitialized: false,
}))

app.use(passport.initialize());
app.use(passport.session());

app.use(flash());


const uploadDir = 'public/uploads';
if (!fs.existsSync(uploadDir)){
    fs.mkdirSync(uploadDir);
}

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'public/uploads/')
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname)
    }
});
const upload = multer({ storage: storage });


let portfolioItems = [];
try {
    portfolioItems = JSON.parse(fs.readFileSync('portfolioItems.json', 'utf8'));
} catch (err) {
    console.error('Error reading portfolioItems.json:', err);
}


app.get('/admin', checkNotAuthenticated, (req, res) => {
    res.render('admin');
});

app.post('/admin/add', checkNotAuthenticated, upload.array('images', 3), (req, res) => {
    const newItem = {
        id: portfolioItems.length + 1,
        name: req.body.name,
        description: req.body.description,
        images: req.files.map(file => file.filename),
        createdAt: dayjs(new Date()).format('HH:mm:ss dddd D MMMM YYYY')
    };
    portfolioItems.push(newItem);
    fs.writeFileSync('portfolioItems.json', JSON.stringify(portfolioItems));
    res.redirect('/admin');
});


app.post('/admin/delete', checkNotAuthenticated, (req, res) => {
    const itemId = req.body.itemId;

    
    const index = portfolioItems.findIndex(item => item.id === parseInt(itemId));
    if (index === -1) {
        return res.status(404).json({ error: 'Portfolio item not found' });
    } else {
        portfolioItems.splice(index, 1);

    
    fs.writeFileSync('portfolioItems.json', JSON.stringify(portfolioItems));

    res.json({ success: true });
    res.redirect('/admin')
    }

    
    
});


app.get('/', checkNotAuthenticated, (req, res)=> {
    res.render('index', )
});
app.get("/yt", checkNotAuthenticated, (req,res)=> {
    res.render('yt')
})

app.get('/users/register', checkAuthenticated, (req, res)=> {
    res.render('register');
});

app.get('/users/login', checkAuthenticated, (req, res)=> {
    res.render('login');
});

app.get('/users/dashboard', checkNotAuthenticated, checkAdmin, (req, res)=> {
    res.render('dashboard', {user: req.user.name, portfolioItems});
});

app.get('/users/logout', (req, res)=> {
    req.logOut((err)=> {
        if (err) {
            throw err;
        }
    });
    req.flash('success_msg', 'You have logged out');
    res.redirect('/users/login');
});

app.post('/users/register', async (req, res)=> {
    let { name, email, password, password2 } = req.body;

    console.log({
        name,
        email,
        password,
        password2
    });

    let errors = [];

    if (!name || !email || !password || !password2) {
        errors.push({message: "Please enter all fields"});
    }

    if (password.length < 6) {
        errors.push({message: "Password should be at least 6 characters"});
    }

    if (password != password2) {
        errors.push({message: "Passwords do not match"});
    }

    if (errors.length > 0) {
        res.render('register', {errors});
    } else {
       
        let hashedPassword = await bcrypt.hash(password, 10);
        console.log(hashedPassword);

        pool.query(
            `SELECT * FROM users
            WHERE email = $1`,
            [email],
            (err, results) => {
                if(err) {
                    throw err;
                }

                console.log(results.rows);

                if (results.rows.length > 0) {
                    errors.push({message: 'Email already registered!'});
                    res.render('register',  {errors});
                } else {
                    pool.query(
                        `INSERT INTO users (name, email, password)
                        VALUES ($1, $2, $3)
                        RETURNING id, password`,
                        [name, email, hashedPassword],
                        (err, results) => {
                            if (err) {
                                throw err;
                            }
                            console.log(results.rows);
                            req.flash('success_msg', 'You are now registered! Please log in');
                            res.redirect('/users/login');
                            sendEmail(email, 'Thank you for registering on the portfolio viewing site!');
                        }
                    );
                }
            }
        );
    }
});

app.post('/users/login', passport.authenticate('local', {
    successRedirect: '/users/dashboard',
    failureRedirect: '/users/login',
    failureFlash: true
}));

function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect('/users/dashboard');
    }
    next();
}

function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
            return next();
    }
    res.redirect('/users/login');
}

function checkAdmin(req, res, next) {
    if (req.user.email === process.env.ADMIN_EMAIL) {
        sendEmail(process.env.ADMIN_EMAIL, 'Someone logged into the admin account.');
        return res.redirect('/admin');
    }
    next();
}

app.listen(PORT, ()=>{
    console.log(`Server running on port: ${PORT}`);
});
