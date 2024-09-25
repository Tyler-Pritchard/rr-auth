const express = require('express');
const jwt = require('jsonwebtoken');
const { loginSchema } = require('../validation/schemas');
const authLimiter = require('../middleware/authLimiter');
const User = require('../models/User');
const { verifyRecaptchaToken } = require('../utils/recaptcha');
const { comparePassword } = require('../utils/bcrypt');
const logger = require('../utils/logger'); 
const router = express.Router();


// @route   POST /api/auth/login
// @desc    Authenticate user and get token
// @access  Public
router.post('/login', authLimiter, async (req, res) => {
    // Validate request data using Joi
    const { error } = loginSchema.validate(req.body);
        if (error) { 
            logger.info('Login validation failed', { error: error.details[0].message });
            return res.status(400).json({ msg: error.details[0].message }) 
        };

    const { email, password, rememberMe } = req.body;

    // Verify CAPTCHA  
    const recaptchaScore = await verifyRecaptchaToken(req.body.captchaToken);
    logger.info("LOGIN CAPTCHA Token:", { token: req.body.captchaToken, score: recaptchaScore });

    if (recaptchaScore === null || recaptchaScore < 0.5) {
        logger.info('CAPTCHA verification failed', { email });
        return res.status(400).json({ msg: 'CAPTCHA verification failed' });
    }

    try {
        // Check for the user in database
        let user = await User.findOne({ email }).maxTimeMS(5000);
        if (!user) {
            logger.info('User not found during login', { email });
            return res.status(400).json({ msg: 'Incorrect email or password' });
        }

        logger.info('User found during login', { email });
        logger.info('Login password comparison', { plainPassword: password, hashedPassword: user.password });


        // Validate password
        const isMatch = await comparePassword(password, user.password);
        logger.info('Password comparison result', { isMatch });

        if (!isMatch) {
            logger.info('Invalid password entered', { email });
            return res.status(400).json({ msg: 'Incorrect email or password' });
        }

        // Generate JWT payload
        const payload = {
            user: {
                id: user.id
            }
        };

        // Determine token expiration based on 'rememberMe'
        const expiresIn = rememberMe ? '30d' : '1h';  // 30 days if 'rememberMe' is true, otherwise 1 hour

        // Sign JWT and return it to the user
        jwt.sign(
        payload,
        process.env.JWT_SECRET,
        { expiresIn },
        (err, token) => {
            if (err) { 
                logger.error('JWT signing error', { error: err });
                throw err;
            };
            logger.info('User successfully logged in', { email, token });
            res.status(200).json({ msg: 'Login successful', token });
        }
        );
    } catch (err) {
        logger.error('Server error during login', { error: err.message });
        res.status(500).send('Server Error');
    }
});

// @route   POST /api/auth/logout
// @desc    Invalidate the user's token (if necessary) and handle logout
// @access  Public
router.post('/logout', (req, res) => {
  try {
    logger.info('User logged out');
    res.status(200).json({ msg: 'Logout successful' });
  } catch (err) {
    logger.error('Server error during logout', { error: err.message });
    res.status(500).send('Server Error');
  }
});

module.exports = router;
