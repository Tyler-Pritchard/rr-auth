const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { resetPasswordSchema, updatePasswordSchema } = require('../validation/schemas');
const authLimiter = require('../middleware/authLimiter');
const transporter = require('../utils/emailTransporter');  // Reusable transporter from utils
const User = require('../models/User');
const { verifyRecaptchaToken } = require('../utils/recaptcha');
const router = express.Router();

// @route   POST /api/password/forgot-password
// @desc    Send email with password reset link
// @access  Public
router.post('/forgot-password', authLimiter, async (req, res) => {
  // Validate request data
  const { error } = resetPasswordSchema.validate(req.body);
  if (error) return res.status(400).json({ msg: error.details[0].message });

  const { email, captchaToken } = req.body;

  try {
    // Verify CAPTCHA for additional security
    const recaptchaScore = await verifyRecaptchaToken(captchaToken);
    if (recaptchaScore === null || recaptchaScore < 0.5) {
      return res.status(400).json({ msg: 'CAPTCHA verification failed' });
    }

    // Check if the user exists
    let user = await User.findOne({ email }).maxTimeMS(5000);
    if (!user) {
      return res.status(400).json({ msg: 'No account with that email found' });
    }

    // Create a password reset token
    const resetToken = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    console.log(`Password reset token for ${email}: ${resetToken}`);

    const resetURL = `https://robrich.band/reset-password?token=${resetToken}`;

    // Send the email with the reset link
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: 'Password Reset Request',
      text: `You requested a password reset. Please click the link to reset your password: ${resetURL}. This link is valid for 1 hour.`,
      html: `<p>You requested a password reset.</p><p><a href="${resetURL}">Click here</a> to reset your password. This link is valid for 1 hour.</p>`,
    };

    await transporter.sendMail(mailOptions);  // Use reusable transporter from utils

    res.json({ msg: 'Password reset email sent. Please check your inbox.' });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

// @route   POST /api/password/reset-password
// @desc    Reset password using token
// @access  Public
router.post('/reset-password', authLimiter, async (req, res) => {
  const { error } = updatePasswordSchema.validate(req.body);
  if (error) return res.status(400).json({ msg: error.details[0].message });

  const token = req.body.token || req.headers['reset-token'];  // Check both headers and body for token
  console.log('Request body:', req.body);
  console.log('Request headers:', req.headers);

  if (!token) {
    return res.status(400).json({ msg: 'Token missing' });
  }

  try {
    // Verify the JWT token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    let user = await User.findById(decoded.id);
    if (!user) {
      return res.status(400).json({ msg: 'Invalid token' });
    }

    const { newPassword } = req.body;
    console.log('Plain new password:', newPassword);

    // Hash the new password
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    console.log('Hashed new password:', user.password);

    // Save the updated user object with the new password
    await user.save();

    res.json({ msg: 'Password reset successful' });
    console.log("PASSWORD HAS BEEN RESET");
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

module.exports = router;
