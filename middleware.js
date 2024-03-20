const jwt = require('jsonwebtoken');

// Middleware to authenticate token
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

        req.user = decodedToken;
        req.user.role = decodedToken.role;

        next();
    });
}

module.exports = { authenticateToken };
