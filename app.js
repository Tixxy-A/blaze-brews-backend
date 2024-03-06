const express = require('express')
const cors = require('cors')
const bodyparser = require('body-parser');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const cookieparser = require('cookie-parser');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
//const sendgridtransport = require('nodemailer-sendgrid-transport');
const User = require('./model/User')
require('dotenv').config()

const app = express()
app.use(express.json());
app.use(cookieparser());

app.use(cors({
    credentials: true,
    origin: 'http://localhost:3000'
}))
mongoose.connect(process.env.MONGOURL);

app.get('/test', (req, res) => {
    res.json({ message: "Hello World" })
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

app.post('/reset-password', async (req, res) => {
    const { email } = req.body;

    // Create a Nodemailer transporter
    const user = await User.findOne({ email: email });
    //console.log(user);
    if (user) {
        const token = crypto.randomBytes(20).toString('hex');
        //console.log(token);
        user.resettoken = token;
        user.tokenExpiration = Date.now() + 10 * 60 * 60;
        user.save();
        //console.log(user);
        let transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: 'ajraut7221@gmail.com', // Your email address
                pass: 'vkko qpur jiok pxvk' // Your email password (or app-specific password if using Gmail)
            }
        });

        // Define email options
        let mailOptions = {
            from: 'ajraut7221@gmail.com', // Sender address
            to: email, // List of recipients
            subject: 'Reset your Password ', // Subject line
            html:
                '<p>Please click on the following link to reset your password:</p>' +
                '<a href="http://localhost:3000/reset/' + token + '">click here</a>',
        };

        try {
            // Send email
            await transporter.sendMail(mailOptions);
            res.status(200).send('Email sent successfully');
        } catch (error) {
            console.error('Error sending email:', error);
            res.status(500).send('Error sending email');
        }
    } else {
        res.status(404).json({ message: 'user not found' });
    }

});

app.post('/new-password', async (req, res) => {
    const { token, password } = req.body;
    const user = await User.findOne({ resettoken: token });
    if (user) {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        user.password = hashedPassword;
        user.save();
        const token = jwt.sign({ email: user.email, id: user._id, name: user.name }, process.env.JWTSECRET);
        res.cookie('token', token).json(user);
    } else {
        res.status(404).json({ message: 'invalid token' });
    }
})


app.listen(3001, () => {
    console.log('running on port 3001')
})
