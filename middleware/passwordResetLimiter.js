/**
 * Password Reset Request Limiter
 *
 * Applied to forgot-password only. Each request can send an email, so this is kept
 * tight to prevent flooding someone's inbox and to protect the email sending quota.
 */

const rateLimit = require('express-rate-limit');

const passwordResetLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  limit: 5,                 // 5 reset requests per IP per window
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { msg: 'Too many password reset requests. Please try again in 15 minutes.' },
});

module.exports = passwordResetLimiter;
