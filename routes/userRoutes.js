const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { registerSchema } = require('../validation/schemas');
const authLimiter = require('../middleware/authLimiter');
const User = require('../models/User');
const { verifyRecaptchaToken } = require('../utils/recaptcha'); // Import from utils
const router = express.Router();

// @route   GET /api/users/count
// @desc    Get total number of registered users
// @access  Public
router.get('/count', async (req, res) => {
  try {
    const userCount = await User.countDocuments().maxTimeMS(5000);
    res.status(200).json({ totalUsers: userCount });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

// @route   POST /api/users/register
// @desc    Register a new user
// @access  Public
router.post('/register', authLimiter, async (req, res) => {
  const { error } = registerSchema.validate(req.body);
  if (error) return res.status(400).json({ msg: error.details[0].message });

  const { firstName, lastName, username, email, password, dateOfBirth, country, isSubscribed, captchaToken } = req.body;

  try {
    // Verify CAPTCHA
    const recaptchaScore = await verifyRecaptchaToken(captchaToken);

    if (recaptchaScore === null || recaptchaScore < 0.5) {
      return res.status(400).json({ msg: 'CAPTCHA verification failed' });
    }

    // Check if the user already exists
    let user = await User.findOne({ email }).maxTimeMS(5000);
    if (user) {
      return res.status(400).json({ msg: 'User already exists' });
    }

    // Create a new user
    user = new User({
      firstName,
      lastName,
      username,
      email,
      password,
      dateOfBirth: new Date(dateOfBirth),
      country,
      isSubscribed,
      captchaToken
    });

    // Hash the password
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(password, salt);

    // Save the new user
    await user.save();

    res.status(201).json({ msg: 'User registered successfully' });
  } catch (error) {
    console.error(error.message);
    res.status(500).send('Server error');
  }
});

module.exports = router;
