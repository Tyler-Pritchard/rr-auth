/**
 * Password Management Routes Module
 * Handles password-related operations such as forgot password and reset password.
 */

// Import necessary modules and utilities
const express = require('express');
const jwt = require('jsonwebtoken');
const { resetPasswordSchema, updatePasswordSchema } = require('../validation/schemas');
const authLimiter = require('../middleware/authLimiter');
const createTransporter = require('../utils/emailTransporter');
const User = require('../models/User');
const { verifyRecaptchaToken } = require('../utils/recaptcha');
const logger = require('../utils/logger');
const { hashPassword } = require('../utils/bcrypt');

const router = express.Router(); // Create a new Express Router instance


/**
 * @route   POST /api/password/forgot-password
 * @desc    Send an email with a password reset link to the provided email address.
 * @access  Public
 */
router.post('/forgot-password', authLimiter, async (req, res) => {
  // Validate incoming request using Joi schema
  const { error } = resetPasswordSchema.validate(req.body);
  if (error) {
    logger.info('Forgot Password validation failed', { error: error.details[0].message });
    return res.status(400).json({ msg: error.details[0].message });
  }

  // Extract email and CAPTCHA token from the request body
  const { email, captchaToken } = req.body;

  // Log the received email and CAPTCHA token for better debugging
  logger.info('Received email and CAPTCHA token for forgot password', { email, captchaToken });

  // Check if CAPTCHA token is defined and non-empty
  if (!captchaToken || captchaToken.trim() === "") {
    logger.error('CAPTCHA token is missing or empty', { email, captchaToken });
    return res.status(400).json({ msg: 'CAPTCHA token is missing or empty' });
  }

  try {
    // Verify reCAPTCHA token for additional security
    const recaptchaScore = await verifyRecaptchaToken(captchaToken);
    logger.info('CAPTCHA verification during forgot password', { email, recaptchaScore });

    // Reject if CAPTCHA verification fails
    if (recaptchaScore === null || recaptchaScore < 0.5) {
      logger.info('CAPTCHA verification failed for forgot password', { email });
      return res.status(400).json({ msg: 'CAPTCHA verification failed' });
    }

    // Check if a user with the provided email exists in the database
    let user = await User.findOne({ email }).maxTimeMS(5000); // Avoid long-running queries with maxTimeMS
    if (!user) {
      logger.info('No account found for the provided email during forgot password', { email });
      return res.status(400).json({ msg: 'No account with that email found' });
    }

    // Generate a password reset token valid for 1 hour
    const resetToken = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    logger.info('Password reset token generated', { email, resetToken });

    // Construct the password reset URL to be sent in the email
    const resetURL = `https://robrich.band/reset-password?token=${resetToken}`;

    // Create the email transporter instance asynchronously
    const transporter = await createTransporter();

    // Define the email content and options
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: 'Password Reset Request',
      text: `You requested a password reset. Please click the link to reset your password: ${resetURL}. This link is valid for 1 hour.`,
      html: `<p>You requested a password reset.</p><p><a href="${resetURL}">Click here</a> to reset your password. This link is valid for 1 hour.</p>`,
    };

    // Send the email using the transporter
    await transporter.sendMail(mailOptions);
    logger.info('Password reset email sent', { email });

    // Respond with a success message
    res.json({ msg: 'Password reset email sent. Please check your inbox.' });
  } catch (err) {
    logger.error('Server error during forgot password operation', { error: err.message });
    res.status(500).send('Server Error');
  }
});
  

/**
 * @route   POST /api/password/reset-password
 * @desc    Reset the user's password using a valid reset token.
 * @access  Public
 */
router.post('/reset-password', authLimiter, async (req, res) => {
  // Validate incoming request using Joi schema
  const { error } = updatePasswordSchema.validate(req.body);
  if (error) {
    logger.info('Reset Password validation failed', { error: error.details[0].message });
    return res.status(400).json({ msg: error.details[0].message });
  }

  // Extract the reset token from the request body or headers
  const token = req.body.token || req.headers['reset-token'];
  logger.info('Received reset-password request', { token });

  // If the token is missing, send an error response
  if (!token) {
    logger.info('Reset token is missing from the request');
    return res.status(400).json({ msg: 'Token missing' });
  }

  try {
    // Verify the reset token to decode the user ID
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    logger.info('JWT token successfully decoded for reset password', { decoded });

    // Retrieve the user by ID from the decoded token
    let user = await User.findById(decoded.id);
    if (!user) {
      logger.info('Invalid token, user not found');
      return res.status(400).json({ msg: 'Invalid token' });
    }

    // Extract the new password from the request body
    const { newPassword } = req.body;
    logger.info('Plain new password received for reset', { userId: user.id });

    // Hash the new password using bcrypt and update the user's password field
    user.password = await hashPassword(newPassword);
    logger.info('New password hashed successfully', { userId: user.id });

    // Save the updated user object in the database
    await user.save();

    // Respond with a success message
    res.json({ msg: 'Password reset successful' });
    logger.info('Password reset completed successfully', { userId: user.id });
  } catch (err) {
    logger.error('Server error during password reset operation', { error: err.message });
    res.status(500).send('Server Error');
  }
});

// Export the router module for use in the main application
module.exports = router;
