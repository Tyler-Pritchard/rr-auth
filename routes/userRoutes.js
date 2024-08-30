const express = require('express');
const axios = require('axios');
const User = require('../models/User');
const router = express.Router();

const SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY;

// @route   POST /api/users/register
// @desc    Register a new user
// @access  Public
router.post('/register', async (req, res) => {
  const { firstName, lastName, username, email, password, dateOfBirth, country, captchaToken } = req.body;

  try {
    // Verify CAPTCHA
    // const captchaResponse = await axios.post(
    //   `https://www.google.com/recaptcha/api/siteverify?secret=${SECRET_KEY}&response=${captchaToken}`
    // );

    // if (!captchaResponse.data.success) {
    //   return res.status(400).json({ msg: 'CAPTCHA verification failed' });
    // }

    // Check if the user already exists
    let user = await User.findOne({ email });
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
      dateOfBirth,
      country,
    });

    await user.save();

    res.status(201).json({ msg: 'User registered successfully' });
  } catch (error) {
    console.error(error.message);
    res.status(500).send('Server error');
  }
});

module.exports = router;
