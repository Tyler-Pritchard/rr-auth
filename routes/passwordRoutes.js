/**
 * Password Management Routes Module
 * Handles password-related operations such as forgot password and reset password.
 */

// Import necessary modules and utilities
const express = require('express');
const { resetPasswordSchema, updatePasswordSchema } = require('../validation/schemas');
const authLimiter = require('../middleware/authLimiter');
const User = require('../models/User');
const { verifyRecaptchaToken } = require('../utils/recaptcha');
const logger = require('../utils/logger');
const crypto = require('crypto'); // Node built-in, for generating and hashing reset tokens
const passwordResetLimiter = require('../middleware/passwordResetLimiter');
const { sendEmail, buildPasswordResetEmail } = require('../utils/email');

const router = express.Router(); // Create a new Express Router instance

// Password reset settings
const RESET_TOKEN_TTL_MINUTES = 30; // How long a reset link stays valid
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://robrich.band'; // Where reset links point
const GENERIC_RESPONSE = {
  msg: 'If an account exists for that email, a password reset link has been sent.',
};

// Hash a reset token with SHA-256; only the hash is stored in the database
const hashToken = (token) => crypto.createHash('sha256').update(token).digest('hex');


/**
 * @route   POST /api/password/forgot-password
 * @desc    Send an email with a password reset link to the provided email address.
 * @access  Public
 */
router.post('/forgot-password', passwordResetLimiter, async (req, res) => {
  // Validate incoming request using Joi schema (also rejects a missing or empty captchaToken)
  const { error } = resetPasswordSchema.validate(req.body);
  if (error) {
    logger.info('Forgot Password validation failed', { error: error.details[0].message });
    return res.status(400).json({ msg: error.details[0].message });
  }

  // Extract email and CAPTCHA token from the request body
  const { email, captchaToken } = req.body;

  try {
    // Verify reCAPTCHA token for additional security
    const recaptchaScore = await verifyRecaptchaToken(captchaToken, 'forgot_password');

    // Reject if CAPTCHA verification fails
    if (recaptchaScore === null || recaptchaScore < 0.5) {
      logger.info('CAPTCHA verification failed for forgot password', { recaptchaScore });
      return res.status(400).json({ msg: 'CAPTCHA verification failed' });
    }

    // Look up the user
    const user = await User.findOne({ email }).maxTimeMS(5000); // Avoid long-running queries with maxTimeMS

    // Respond the same way whether or not the account exists, and before sending the email,
    // so neither the message nor the response time reveals which emails are registered
    res.json(GENERIC_RESPONSE);

    if (!user) {
      logger.info('Password reset requested for an email with no account');
      return;
    }

    // Generate a random reset token and store only its hash, with an expiry.
    // updateOne avoids re-validating the whole document (older users may lack newer fields).
    const resetToken = crypto.randomBytes(32).toString('hex');
    await User.updateOne(
      { _id: user._id },
      {
        $set: {
          resetPasswordTokenHash: hashToken(resetToken),
          resetPasswordExpires: new Date(Date.now() + RESET_TOKEN_TTL_MINUTES * 60 * 1000),
        },
      }
    );

    // Build and send the reset email (the raw token appears only in the emailed link)
    const resetURL = `${FRONTEND_URL}/reset-password?token=${resetToken}`;
    const message = buildPasswordResetEmail({
      firstName: user.firstName,
      resetURL,
      expiresInMinutes: RESET_TOKEN_TTL_MINUTES,
    });
    const result = await sendEmail({ to: user.email, ...message });
    logger.info('Password reset email sent', { userId: user.id, messageId: result.id });
  } catch (err) {
    logger.error('Server error during forgot password operation', { error: err.message });
    // If the generic response already went out, the client is unaffected; only log the error
    if (!res.headersSent) {
      res.status(500).json({ msg: 'Server Error' });
    }
  }
});
  

/**
 * @route   POST /api/password/reset-password
 * @desc    Reset the user's password using a valid reset token.
 * @access  Public
 */
router.post('/reset-password', authLimiter, async (req, res) => {
  // Validate incoming request using Joi schema (requires token and newPassword)
  const { error } = updatePasswordSchema.validate(req.body);
  if (error) {
    logger.info('Reset Password validation failed', { error: error.details[0].message });
    return res.status(400).json({ msg: error.details[0].message });
  }

  // Extract the reset token and new password from the request body
  const { token, newPassword } = req.body;

  try {
    // Atomically claim the token: find a user with a matching, unexpired token hash and
    // clear the token in the same operation, so the link can never be used twice
    const user = await User.findOneAndUpdate(
      {
        resetPasswordTokenHash: hashToken(token),
        resetPasswordExpires: { $gt: new Date() },
      },
      { $unset: { resetPasswordTokenHash: 1, resetPasswordExpires: 1 } },
      { new: true }
    ).maxTimeMS(5000); // Avoid long-running queries with maxTimeMS

    if (!user) {
      logger.info('Password reset attempted with an invalid or expired token');
      return res.status(400).json({ msg: 'This reset link is invalid or has expired' });
    }

    // Assign the PLAIN password; the User pre-save hook hashes it exactly once
    // and records passwordChangedAt
    user.password = newPassword;
    await user.save();

    logger.info('Password reset completed successfully', { userId: user.id });

    // Respond with a success message
    res.json({ msg: 'Password reset successful' });
  } catch (err) {
    logger.error('Server error during password reset operation', { error: err.message });
    res.status(500).json({ msg: 'Server Error' });
  }
});

// Export the router module for use in the main application
module.exports = router;
