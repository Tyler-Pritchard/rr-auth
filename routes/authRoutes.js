/**
 * Authentication Routes Module
 * Manages authentication operations such as login and logout.
 */

// Import necessary modules and utilities
const express = require('express');
const jwt = require('jsonwebtoken');
const { loginSchema } = require('../validation/schemas');
const authLimiter = require('../middleware/authLimiter');
const User = require('../models/User');
const { verifyRecaptchaToken } = require('../utils/recaptcha');
const { comparePassword } = require('../utils/bcrypt');
const logger = require('../utils/logger');

const router = express.Router(); // Create a new Express Router instance

/**
 * @route   POST /api/auth/login
 * @desc    Authenticate user and generate JWT token upon successful login.
 * @access  Public
 */
router.post('/login', authLimiter, async (req, res) => {
  // Validate incoming login request using Joi schema
  const { error } = loginSchema.validate(req.body);
  if (error) {
    logger.info('Login validation failed', { error: error.details[0].message });
    return res.status(400).json({ msg: error.details[0].message });
  }

  // Destructure incoming request body to extract email, password, and rememberMe option
  const { email, password, rememberMe } = req.body;

  try {
    // Verify reCAPTCHA token to ensure the request is from a human
    const recaptchaScore = await verifyRecaptchaToken(req.body.captchaToken);
    logger.info('CAPTCHA verification during login', { email, recaptchaScore });

    // If CAPTCHA verification fails, reject the request
    if (recaptchaScore === null || recaptchaScore < 0.5) {
      logger.info('CAPTCHA verification failed during login', { email });
      return res.status(400).json({ msg: 'CAPTCHA verification failed' });
    }

    // Check for an existing user with the provided email in the database
    let user = await User.findOne({ email }).maxTimeMS(5000); // Avoid long-running queries with maxTimeMS
    if (!user) {
      logger.info('User not found during login attempt', { email });
      return res.status(400).json({ msg: 'Incorrect email or password' });
    }

    // Log the presence of the user and the stored password hash for debugging
    logger.info('User found during login', { email, storedHash: user.password });

    // Compare the plain text password with the stored hashed password
    const isMatch = await comparePassword(password, user.password);
    logger.info('Password comparison result', { isMatch });

    // If the passwords do not match, send an error response
    if (!isMatch) {
      logger.info('Invalid password entered', { email });
      return res.status(400).json({ msg: 'Incorrect email or password' });
    }

    // Create a payload for JWT that includes the user's ID
    const payload = {
      user: {
        id: user.id
      }
    };

    // Determine JWT expiration based on 'rememberMe' flag
    const expiresIn = rememberMe ? '30d' : '1h'; // 30 days if 'rememberMe' is true, otherwise 1 hour

    // Sign the JWT token with the secret key and specified expiration time
    jwt.sign(payload, process.env.JWT_SECRET, { expiresIn }, (err, token) => {
      if (err) {
        logger.error('Error signing JWT during login', { error: err });
        throw err;
      }
      logger.info('User successfully logged in', { email, token });
      res.status(200).json({ msg: 'Login successful', token });
    });
  } catch (err) {
    logger.error('Server error during login', { error: err.message });
    res.status(500).send('Server Error');
  }
});

/**
 * @route   POST /api/auth/logout
 * @desc    Handle user logout by optionally invalidating the user's token.
 * @access  Public
 */
router.post('/logout', (req, res) => {
  try {
    logger.info('User logged out successfully');
    res.status(200).json({ msg: 'Logout successful' });
  } catch (err) {
    logger.error('Server error during logout', { error: err.message });
    res.status(500).send('Server Error');
  }
});

// Export the router module for use in the main application
module.exports = router;
