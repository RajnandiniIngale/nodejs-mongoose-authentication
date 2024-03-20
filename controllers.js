const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { User } = require('./models');


async function registerUser(req, res) {
    // Implementation
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
}

// Login user
async function loginUser(req, res) {
    // Implementation

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
        role: user.role  // Include the user's role
    };


    const token = jwt.sign(tokenPayload, 'secretKey', { expiresIn: '1h' });

    res.json({ token });
}

// Admin route handler
function adminRoute(req, res) {
    // Implementation

    console.log('User Role:', req.user.role);  // Log the user role
    if (req.user.role !== 'admin') {
        return res.sendStatus(403);
    }

    res.json({ message: 'Admin Route accessed!' })
}

// Protected route handler
function protectedRoute(req, res) {
    // Implementation

    res.json({ message: 'Protected route accessed' })
}

module.exports = { registerUser, loginUser, adminRoute, protectedRoute };