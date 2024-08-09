const express = require('express')
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const cors = require('cors');
require('dotenv').config();
const User = require('./models/userModel')
const jwt = require('jsonwebtoken');
const verifyToken = require('./utils/verifyToken');
const session = require('express-session');
const passport = require('passport');
const oAuth2Strategy = require('passport-google-oauth2').Strategy;


const app = express()
const PORT = process.env.PORT || 8000 ;

app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(cors({
    origin: "*",
    method: "GET,POST,DELETE,PUT,PATCH",
    credentials:true
}))


app.use(session({
    secret: "123456",
    resave: false,
    saveUninitialized:true
}))
app.use(passport.initialize())
app.use(passport.session())

passport.use(new oAuth2Strategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback",
    scope:["profile","email"]
}, async (accessToken, refreshToken, profile, done) => {
    console.log(profile)
    try {
        let user = await User.findOne({ email: profile.emails[0].value })
        if (!user) {
            user = new User({
                name: profile.displayName,
                email: profile.emails[0].value,
                password:'NotAPassword'
            })
            await user.save()
        }
        return done(null,user)
    } catch (error) {
        return done(error,null)
    }
} ))

passport.serializeUser((user, done)=> {
    done(null,user)
})
passport.deserializeUser((user, done)=> {
    done(null,user)
})

app.get('/auth/google', passport.authenticate("google", { scope: ["profile", "email"] }));

app.get('/auth/google/callback', passport.authenticate("google", {
    successRedirect: "http://localhost:3000/dashboard",
    failureRedirect:"http://localhost:3000/login"
}))

app.get('/login/success', async (req, res) => {
    if (req?.user) {
        res.status(200).send({message:"Login successful",user:req?.user})
    }
    else {
        res.status(400).send({ message: "Not authorized" });
    }
})


app.get('/', (req,res) => {
    res.send("server is Up and running")
})

app.listen(PORT, () => {
    console.log('Server getting started on port '+ PORT)
})


const connectToDB = async () => {
    try {
        await mongoose.connect(process.env.DATABASE);
        console.log("Database Connected Successfully")
    } catch (error) {
        console.log(error)
    }
    
}

connectToDB();




const registerUser = async (req, res) => {
    const { name, email, password } = req.body;

    try {
        const user = await User.findOne({ email: email });
        if (user) {
            res.status(400).send("User is already registered")
        }
        else {
          
            const saltround = 10;
            const hashedPassword = await bcrypt.hash(password, saltround)

            const newUser = new User({
                name:name, email:email, password:hashedPassword
            })
            await newUser.save()
            res.status(200).send("User registered Successfully")
        }
    } catch (error) {
        res.status(404).send("Internal Server error",error);
    }
   
}

const loginUser = async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email: email });
        if (!user) {
            res.status(404).send("User is not registered");
        } else {
            const isMatched = await bcrypt.compare(password, user.password)
            if (!isMatched) {
                res.status(400).send("Password is Incorrect");
            }
            const token = jwt.sign({ email: email, name: user.name }, process.env.JWT_SECRET, { expiresIn: "24h" })
            res.status(200).send({ message: "Login Successfull", token: token })
        }
    } catch (error) {
        res.status(500).send("Internal Server Error")
    }
   
}

const getUserData =async (req,res) => {
    try {
        const token = req.header('Authorization')?.replace("Bearer ", '')
        if (!token) {
           return res.status(401).send("Token is required");
        }
        const decoded = jwt.verify(token, process.env.JWT_SECRET)
        const user =await User.findOne({ email: decoded.email })
        console.log(decoded.email)
        res.status(201).send({
            name: user.name,
            email: user.email,
            role:user.role,
        })
        
    } catch (error) {
        res.status(401).send("Invalid Token");
    }
}

const getAllUser = async (req, res) => {
    const users = await User.find({})
    res.status(200).send({usersData:users})
}


app.post('/api/register',registerUser)
app.get('/api/login',loginUser)
app.get('/api/user', verifyToken, getUserData);
app.get('/api/getusers', getAllUser);

