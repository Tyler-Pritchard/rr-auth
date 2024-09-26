const express = require('express');
const jwt = require('jsonwebtoken');
const { resetPasswordSchema, updatePasswordSchema } = require('../validation/schemas');
const authLimiter = require('../middleware/authLimiter');
const createTransporter = require('../utils/emailTransporter'); 
const User = require('../models/User');
const { verifyRecaptchaToken } = require('../utils/recaptcha');
const logger = require('../utils/logger');
const { hashPassword } = require('../utils/bcrypt'); 
const router = express.Router();


// @route   POST /api/password/forgot-password
// @desc    Send email with password reset link
// @access  Public
router.post('/forgot-password', authLimiter, async (req, res) => {
    // Validate request data
    const { error } = resetPasswordSchema.validate(req.body);
    if (error) { 
        logger.info('Forgot Password validation failed', { error: error.details[0].message });
        return res.status(400).json({ msg: error.details[0].message })
    };

    const { email, captchaToken } = req.body;

    try {
        // Verify CAPTCHA for additional security
        const recaptchaScore = await verifyRecaptchaToken(captchaToken);
        logger.info('CAPTCHA token verification score', { score: recaptchaScore, token: captchaToken });

        if (recaptchaScore === null || recaptchaScore < 0.5) {
            logger.info('CAPTCHA verification failed for forgot password', { email });
            return res.status(400).json({ msg: 'CAPTCHA verification failed' });
        }

        // Check if the user exists
        let user = await User.findOne({ email }).maxTimeMS(5000);
        if (!user) {
            logger.info('No account found for email during forgot password', { email });
            return res.status(400).json({ msg: 'No account with that email found' });
        }

        // Create a password reset token
        const resetToken = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        logger.info('Password reset token generated', { email, resetToken });

        const resetURL = `https://robrich.band/reset-password?token=${resetToken}`;

        // Get the transporter asynchronously
        const transporter = await createTransporter();

        // Send the email with the reset link
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: 'Password Reset Request',
            text: `You requested a password reset. Please click the link to reset your password: ${resetURL}. This link is valid for 1 hour.`,
            html: `<p>You requested a password reset.</p><p><a href="${resetURL}">Click here</a> to reset your password. This link is valid for 1 hour.</p>`,
        };

        await transporter.sendMail(mailOptions);
        logger.info('Password reset email sent', { email });

        res.json({ msg: 'Password reset email sent. Please check your inbox.' });
    } catch (err) {
        logger.error('Server error during forgot password', { error: err.message });
        res.status(500).send('Server Error');
    }
});


// @route   POST /api/password/reset-password
// @desc    Reset password using token
// @access  Public
router.post('/reset-password', authLimiter, async (req, res) => {
    const { error } = updatePasswordSchema.validate(req.body);
    if (error) {
        logger.info('Reset Password validation failed', { error: error.details[0].message });
        return res.status(400).json({ msg: error.details[0].message })
    };

    const token = req.body.token || req.headers['reset-token'];  // Check both headers and body for token
    logger.info('Received reset-password request', { token, body: req.body });


    if (!token) {
        logger.info('Reset token missing');
        return res.status(400).json({ msg: 'Token missing' });
    }

    try {
        // Verify the JWT token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        logger.info('JWT token decoded for reset password', { decoded });

        let user = await User.findById(decoded.id);
        if (!user) {
            logger.info('Invalid token, user not found');
            return res.status(400).json({ msg: 'Invalid token' });
        }

        const { newPassword } = req.body;
        logger.info('Plain new password received for reset', { newPassword });

        // Use bcrypt utility to hash the new password
        user.password = await hashPassword(newPassword);
        logger.info('New password hashed', { userId: user.id });

        // Save the updated user object with the new password
        await user.save();

        res.json({ msg: 'Password reset successful' });
        logger.info('Password reset successful', { userId: user.id });
    } catch (err) {
        logger.error('Server error during password reset', { error: err.message });
        res.status(500).send('Server Error');
    }
});

module.exports = router;
