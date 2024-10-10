/**
 * Mock CAPTCHA Verification Module
 * This mock module simulates a Google reCAPTCHA verification response for testing purposes.
 */

// Import necessary modules
const express = require('express');
const router = express.Router();
const logger = require('../utils/logger');

/**
 * @route   POST /mock-recaptcha
 * @desc    Mock route to simulate CAPTCHA verification for development and testing.
 *          Returns a simulated high score (0.9) to mimic successful CAPTCHA verification.
 * @access  Public (Used only for development and testing purposes)
 */
router.post('/mock-recaptcha', (req, res) => {
  // Log the received CAPTCHA token for transparency during testing
  logger.info('Mock reCAPTCHA token received', { token: req.body.token });
  
  // Respond with a simulated high score for successful CAPTCHA verification
  res.json({ score: 0.9 });
});

// Export the router for use in the main application
module.exports = router;
