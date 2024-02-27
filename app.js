const express = require('express')
const cors = require('cors')
const bodyparser = require('body-parser');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const cookieparser = require('cookie-parser');
const User=require('./model/User')
require('dotenv').config()

const app = express()
app.use(express.json());
app.use(cookieparser());

app.use(cors({
    credentials: true,
    origin: 'http://localhost:3000'
}))
mongoose.connect(process.env.MONGOURL);

app.get('/test',(req,res)=>{
    res.json({message:"Hello World"})
})
app.post('/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const user = await User.create({ name, email, password: hashedPassword });
        res.json(user);
    } catch (e) {
        res.status(422).json({ message: 'cannot register user' });
    }

})
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const existingUser = await User.findOne({ email: email });
    //console.log(existingUser);
    if (existingUser) {
        const isMatch = await bcrypt.compare(password, existingUser.password);

        if (isMatch) {
            const token = jwt.sign({ email: existingUser.email, id: existingUser._id, name: existingUser.name }, process.env.JWTSECRET);
            res.cookie('token', token).json(existingUser);
        }
        else {
            res.status(401).json({ message: 'invalid password' });
        }
    } else {
        res.status(401).json({ message: 'invalid email' })
    }

});

app.post('/logout', (req, res) => {
    res.cookie('token', '').json(true);
})

app.get('/profile', async (req, res) => {
    const { token } = req.cookies;
    if (token) {
        jwt.verify(token, process.env.JWTSECRET, {}, (err, user) => {
            if (err) {
                res.status(401).json({ message: 'invalid token' })
            }
            res.json(user);
        });

    }
    else {

        res.json(false);
    }
});


app.listen(3001, () => {
    console.log('running on port 3001')
})
