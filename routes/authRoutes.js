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

const { permissionsForRoles } = require('../config/permissions');

// Standard JWT claims identifying who issued the token and who it's meant for.
// Other services can verify these once they're updated; for now they're informational.
const JWT_ISSUER = process.env.JWT_ISSUER || 'rr-auth';
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || 'rr-api';

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
    const recaptchaScore = await verifyRecaptchaToken(req.body.captchaToken, 'login');
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
    logger.info('User found during login', { email });

    // Compare the plain text password with the stored hashed password
    const isMatch = await comparePassword(password, user.password);
    logger.info('Password comparison result', { isMatch });

    // If the passwords do not match, send an error response
    if (!isMatch) {
      logger.info('Invalid password entered', { email });
      return res.status(400).json({ msg: 'Incorrect email or password' });
    }

    // Work out what this user is allowed to do
    const roles = [...(user.roles || [])];
    const permissions = permissionsForRoles(roles);

    const payload = {
      user: { id: user.id },          // Legacy shape; rrsite and other services may still read this
      roles,                          // Job titles, for display (e.g. showing "Admin" in the UI)
      scope: permissions.join(' '),   // Space-separated permissions; what services should check
    };

    // "Remember me" only applies to users without write permissions. Anyone who can
    // change site data gets a 1-hour token, so removing their role takes effect quickly.
    const hasWritePermissions = permissions.length > 0;
    const expiresIn = rememberMe && !hasWritePermissions ? '30d' : '1h';

    // Synchronous sign: any error is thrown here and caught by the catch block below,
    // instead of crashing the process from inside a callback
    const token = jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn,
      subject: String(user.id),       // Standard "sub" claim: who the token is about
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    });

    logger.info('User successfully logged in', { email, roles, expiresIn });
    return res.status(200).json({ msg: 'Login successful', token });
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
