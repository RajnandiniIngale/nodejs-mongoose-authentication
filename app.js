const express = require('express');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');

const app = express();

mongoose.connect('mongodb://localhost:27017/user_demo')
    .then(() => console.log('MongoDB Connected'))
    .catch((err) => console.log(err));


const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    role: String
})


const User = mongoose.model('userSchema', userSchema);


app.use(express.json());


app.post('/register', async (req, res) => {

    const { username, password, role } = req.body;

    try {

        const existingUser = await User.findOne({ username });

        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' })
        }

        const hashedPassword = await bcrypt.hash(password, 10);


        const newUser = new User({
            username,
            password: hashedPassword,
            role: role || 'user'
        })

        console.log("New User:", newUser);


        await newUser.save();

        res.status(201).json({ message: "User registered successfully" })

    }
    catch (err) {

        console.error(err);

        res.status(500).json({ message: 'Internal Server Error' })
    }
})

// Authentication route

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    const user = await User.findOne({ username });

    if (!user) {
        return res.status(404).json({ message: 'User not found!' });
    }

    const isValidPassword = bcrypt.compare(password, user.password);

    if (!isValidPassword) {
        return res.status(401).json({ message: 'Invalid Password' })
    }


    const tokenPayload = {
        userId: user._id,
        username: user.username,
        role: user.role  
    };


    const token = jwt.sign(tokenPayload, 'secretKey', { expiresIn: '1h' });

    res.json({ token });
})

function authenticateToken(req, res, next) {
    console.log("Middleware accessed");  // Add this log to confirm middleware execution
    const authHeader = req.headers['authorization'];
    console.log("Auth Header:", authHeader);
    const token = authHeader && authHeader.split(' ')[1];
    console.log("Token:", token); // Log the token value

    if (!token) {
        return res.sendStatus(401);
    }

    jwt.verify(token, 'secretKey', (err, decodedToken) => {
        if (err) {
            // Send a meaningful response along with the status code
            return res.status(403).json({ message: 'Token verification failed' });
        }
        console.log('Decoded Token:', decodedToken);

        // Store 'decodedToken' in 'req.user' for access in subsequent middleware or routes

        req.user = decodedToken;
        req.user.role = decodedToken.role;

        next();
    });
}


app.get('/admin', authenticateToken, (req, res) => {
    console.log('User Role:', req.user.role);  // Log the user role
    if (req.user.role !== 'admin') {
        return res.sendStatus(403);
    }

    res.json({ message: 'Admin Route accessed!' })
})

app.get('/protected', authenticateToken, (req, res) => {
    res.json({ message: 'Protected route accessed' })
})





const PORT = 3000;

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));