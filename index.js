const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();  //creates an instance of the Express application, which can be used to define routes, middleware, and other functionalities.

app.use(express.json());

//By adding this middleware to your Express application, you can handle JSON data sent in the request body of incoming HTTP requests. 
//It's commonly used for handling data sent in POST and PUT requests when creating or updating resources on the server.


mongoose.connect('mongodb://localhost:27017/user_demo')
    .then(() => console.log('MongoDB connected'))
    .catch((err) => console.error(err))


const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    role: String
})

const User = mongoose.model('userSchema', userSchema);


app.post('/register', async (req, res) => {

    const { username, password, role } = req.body;

    const existingUser = await User.findOne({ username });

    if (existingUser) {
        res.status(409).json({ message: 'User already exists' })
    }


    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
        username,
        password: hashedPassword,
        role: role || 'user'
    })


    console.log(newUser);

    await newUser.save();

    res.status(201).json({ message: 'User registered successfully' })
});


//Authentication route


app.post('/login', async (req, res) => {

    const { username, password } = req.body;

    const user = await User.findOne({ username });

    if (!user) {
        res.status(401).json({ message: 'User not found!' })
    }

    const isValidPassword = bcrypt.compare(password, user.password);

    if (!isValidPassword) {
        res.status(401).json({ message: 'Invalid Password' })
    }

    const tokenPayload = {
        userId: user._id,
        username: user.username,
        role: user.role
    }

    const token = jwt.sign(tokenPayload, 'secretKey', { expiresIn: '1h' });

    res.json({ token })
});

//a 401 status code is usually used to signify that the 'username provided does not exist' or that 'the password provided is incorrect'.
// So, 401 can indicate both "User not found" and "Invalid Password" situations.


function authenticateToken(req, res, next) {

    const authHeader = req.headers['authorization'];

    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        res.status(401).json({ message: "No token found" });
    }

    jwt.verify(token,'secretKey',(err,decodedToken)=>{
        if(err){
            res.status(403).json({message: 'Token verification failed'})
        }

        console.log('Decoded Token: ',decodedToken);

        //store the decodedToken in req.user for access in subsequent routes or middlewares
        req.user = decodedToken;
        req.user.role = decodedToken.role;

        next();
    })
}


app.get('/admin',authenticateToken,(req,res)=> {
    if(req.user.role!= 'admin'){
        return res.status(403).json({message: "User is not allowed to access admin route"})
    }

    res.json({message: 'Admin route accessed!'}) 
})

app.get('/protected',authenticateToken,(req,res)=>{
    res.json({message: 'Protected route accessed!'})
})

const PORT = 3001;

app.listen(PORT, () => console.log(`Server listening on http://localhost:${PORT}`)); //The app.listen() method starts the Express server and makes it listen for incoming HTTP requests on the specified port.