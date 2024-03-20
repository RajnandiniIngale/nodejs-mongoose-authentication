const express = require('express');
const router = express.Router();
const { registerUser, loginUser, adminRoute, protectedRoute } = require('./controllers');
const { authenticateToken } = require('./middleware');

// Register user
router.post('/register', registerUser);

// Login user
router.post('/login', loginUser);

// Protected route
router.get('/protected', authenticateToken, protectedRoute);

// Admin route
router.get('/admin', authenticateToken, adminRoute);

module.exports = router;
