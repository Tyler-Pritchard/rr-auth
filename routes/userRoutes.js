const express = require('express');
const { registerSchema } = require('../validation/schemas');
const authLimiter = require('../middleware/authLimiter');
const User = require('../models/User');
const { verifyRecaptchaToken } = require('../utils/recaptcha');
const { hashPassword } = require('../utils/bcrypt');
const logger = require('../utils/logger');
const router = express.Router();

// @route   GET /api/users/count
// @desc    Get total number of registered users
// @access  Public
router.get('/count', async (req, res) => {
  try {
    const userCount = await User.countDocuments().maxTimeMS(5000);
    logger.info('Total users count retrieved', { userCount }); 
    res.status(200).json({ totalUsers: userCount });
  } catch (err) {
    logger.error('Error fetching user count', { error: err.message });
    res.status(500).send('Server Error');
  }
});

router.post('/register', authLimiter, async (req, res) => {
  const { error } = registerSchema.validate(req.body);
  if (error) {
    logger.info('User registration validation failed', { error: error.details[0].message });
    return res.status(400).json({ msg: error.details[0].message });
  }

  const { firstName, lastName, username, email, password, dateOfBirth, country, isSubscribed, captchaToken } = req.body;

  try {
    // Verify CAPTCHA
    const recaptchaScore = await verifyRecaptchaToken(captchaToken);
    logger.info('CAPTCHA verification for registration', { email, recaptchaScore });

    if (recaptchaScore === null || recaptchaScore < 0.5) {
      logger.info('CAPTCHA verification failed during registration', { email });
      return res.status(400).json({ msg: 'CAPTCHA verification failed' });
    }

    // Check if the user already exists
    let user = await User.findOne({ email }).maxTimeMS(5000);
    if (user) {
      logger.info('User already exists during registration', { email });
      return res.status(400).json({ msg: 'User already exists' });
    }

    // Create a new user (save plain text password)
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

    await user.save();
    logger.info('New user registered successfully', { email });

    res.status(201).json({ msg: 'User registered successfully' });
  } catch (error) {
    logger.error('Error during user registration', { error: error.message });
    res.status(500).send('Server error');
  }
});


module.exports = router;
