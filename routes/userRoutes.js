/**
 * User Routes Module
 * Handles user-related operations such as registration and user count retrieval.
 */

// Import necessary modules and utilities
const express = require('express');
const { registerSchema } = require('../validation/schemas');
const authLimiter = require('../middleware/authLimiter');
const User = require('../models/User');
const { verifyRecaptchaToken } = require('../utils/recaptcha');
const logger = require('../utils/logger');

const router = express.Router(); // Create a new Express Router instance

/**
 * @route   GET /users/count
 * @desc    Retrieves the total number of registered users in the database.
 * @access  Public
 */
router.get('/count', async (req, res) => {
  try {
    // Fetch the count of user documents with a maximum query execution time of 5000ms
    const userCount = await User.countDocuments().maxTimeMS(5000);
    logger.info('Total users count retrieved successfully', { userCount });
    res.status(200).json({ totalUsers: userCount });
  } catch (err) {
    logger.error('Error fetching user count', { error: err.message });
    res.status(500).send('Server Error');
  }
});

/**
 * @route   POST /users/register
 * @desc    Register a new user with the provided details.
 * @access  Public
 */
router.post('/register', authLimiter, async (req, res) => {
  // Validate the incoming registration data using the predefined schema
  const { error } = registerSchema.validate(req.body);
  if (error) {
    logger.info('User registration validation failed', { error: error.details[0].message });
    return res.status(400).json({ msg: error.details[0].message });
  }

  // Destructure the incoming request body to extract user details
  const { firstName, lastName, username, email, password, dateOfBirth, country, isSubscribed, captchaToken } = req.body;

  try {
    // Verify the CAPTCHA token to prevent automated requests
    const recaptchaScore = await verifyRecaptchaToken(captchaToken, 'register');
    logger.info('CAPTCHA verification result during registration', { email, recaptchaScore });

    // If CAPTCHA verification fails, reject the request
    if (recaptchaScore === null || recaptchaScore < 0.5) {
      logger.info('CAPTCHA verification failed during registration', { email });
      return res.status(400).json({ msg: 'CAPTCHA verification failed' });
    }

    // Check if a user with the provided email already exists in the database
    let user = await User.findOne({ email }).maxTimeMS(5000); // Avoid long-running queries with maxTimeMS
    if (user) {
      logger.info('User already exists during registration attempt', { email });
      return res.status(400).json({ msg: 'User already exists' });
    }

    // Create a new user document with the provided details
    user = new User({
      firstName,
      lastName,
      username,
      email,
      password, // Plain text password will be hashed in the Mongoose pre-save middleware
      dateOfBirth: new Date(dateOfBirth), // Convert string date to Date object
      country,
      isSubscribed,
      captchaToken
    });

    // Save the new user document to the database
    await user.save();
    logger.info('New user registered successfully', { email });

    // Send a success response
    res.status(201).json({ msg: 'User registered successfully' });
  } catch (error) {
    logger.error('Error during user registration', { error: error.message });
    res.status(500).send('Server Error');
  }
});

// Export the router module for use in the main application
module.exports = router;
