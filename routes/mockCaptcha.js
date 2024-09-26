const express = require('express');
const router = express.Router();
const logger = require('../utils/logger');

// Mock reCAPTCHA verification route
router.post('/mock-recaptcha', (req, res) => {
  logger.info('Mock reCAPTCHA token received', { token: req.body.token });
  
  // Simulate a high score for testing
  res.json({ score: 0.9 });
});

module.exports = router;
