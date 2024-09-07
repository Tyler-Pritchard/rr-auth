const express = require('express');
const axios = require('axios');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { registerSchema, loginSchema, resetPasswordSchema } = require('../validation/schemas');
const authLimiter = require('../middleware/authLimiter');
const Joi = require('joi');
const User = require('../models/User');
const router = express.Router();
const {RecaptchaEnterpriseServiceClient} = require('@google-cloud/recaptcha-enterprise');

const SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY;
const PROJECT_ID = 'rr-auth-1725047695006';
const recaptchaSiteKey = '6LfU8jIqAAAAAOAFm-eNXmW-uPrxqdH9xJLEfJ7R';

// Initialize reCAPTCHA client
const recaptchaClient = new RecaptchaEnterpriseServiceClient();

async function verifyRecaptchaToken(token) {

  const projectPath = recaptchaClient.projectPath(PROJECT_ID);

  // Build the assessment request.
  const request = {
    assessment: {
      event: {
        token: token,
        siteKey: recaptchaSiteKey,
      },
    },
    parent: projectPath,
  };

  const [response] = await recaptchaClient.createAssessment(request);

  // Check if the token is valid.
  if (!response.tokenProperties.valid) {
    console.log(`The CreateAssessment call failed because the token was: ${response.tokenProperties.invalidReason}`);
    return null;
  }

  // Return the risk score
  return response.riskAnalysis.score;
}

// @route   GET /api/users/count
// @desc    Get total number of registered users
// @access  Public
router.get('/count', async (req, res) => {
  try {
    const userCount = await User.countDocuments();
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
  // TEST CAPTCHA DISABLE FOR PROD
  console.log("CAPTCHA TOKEN in POST: ", captchaToken)
  try {
    // Verify CAPTCHA
    const recaptchaScore = await verifyRecaptchaToken(captchaToken);

    if (recaptchaScore === null || recaptchaScore < 0.5) {
      return res.status(400).json({ msg: 'CAPTCHA verification failed' });
    }

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
      dateOfBirth: new Date(dateOfBirth),
      country,
      isSubscribed,
      captchaToken
    });

    await user.save();

    res.status(201).json({ msg: 'User registered successfully' });
  } catch (error) {
    console.error(error.message);
    res.status(500).send('Server error');
  }
});

// @route   POST /api/users/login
// @desc    Authenticate user and get token
// @access  Public
router.post('/login', authLimiter, async (req, res) => {
  // Validate request data
  const { error } = loginSchema.validate(req.body);
  if (error) return res.status(400).json({ msg: error.details[0].message });

  const { email, password } = req.body;

  const recaptchaScore = await verifyRecaptchaToken(req.body.captchaToken);

  if (recaptchaScore === null || recaptchaScore < 0.5) {
    return res.status(400).json({ msg: 'CAPTCHA verification failed' });
  }

  try {
    // Check for the user
    let user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ msg: 'Incorrect email or password' });
    }

    // Validate password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ msg: 'Incorrect email or password' });
    }

    // Generate JWT payload
    const payload = {
      user: {
        id: user.id
      }
    };

    // Sign JWT and return it to the user
    jwt.sign(
      payload,
      process.env.JWT_SECRET,
      { expiresIn: '1h' },  // Token expires in 1 hour
      (err, token) => {
        if (err) throw err;
        res.status(200).json({ msg: 'Login successful', token });
      }
    );
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

  

// @route   POST /api/users/forgot-password
// @desc    Send email with password reset link
// @access  Public
router.post('/forgot-password', authLimiter, async (req, res) => {
  // Validate request data
  const { error } = resetPasswordSchema.validate(req.body);
  if (error) return res.status(400).json({ msg: error.details[0].message });

  const { email } = req.body;

  try {
    let user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ msg: 'No account with that email found' });
    }

    const resetToken = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '15m' });

    // Ideally send an email with this resetToken to the user
    // For now, we'll just return it in the response
    res.json({ resetToken });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});


// @route   POST /api/users/reset-password
// @desc    Reset password using token
// @access  Public
router.post('/reset-password', authLimiter, async (req, res) => {
  const { error } = registerSchema.validate(req.body);
  if (error) return res.status(400).json({ msg: error.details[0].message });
  const { token, newPassword } = req.body;

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    let user = await User.findById(decoded.id);
    if (!user) {
      return res.status(400).json({ msg: 'Invalid token' });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    res.json({ msg: 'Password reset successful' });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});
  
  

module.exports = router; // Export only the router by default
module.exports.verifyRecaptchaToken = verifyRecaptchaToken; // Export function for testing
