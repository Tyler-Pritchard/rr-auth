// routes/mockCaptcha.js
const express = require('express');
const router = express.Router();
const logger = require('../utils/logger'); // Import Winston logger

// Mock reCAPTCHA verification route
router.post('/mock-recaptcha', (req, res) => {
  logger.info('Mock reCAPTCHA route accessed', { body: req.body });
  
  // Simulate a high score for testing
  const mockScore = 0.9;
  logger.info('Mock reCAPTCHA score generated', { score: mockScore });

  res.json({ score: mockScore });
  
  logger.info('Mock reCAPTCHA response sent', { score: mockScore });
});

module.exports = router;
