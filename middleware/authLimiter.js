const rateLimit = require('express-rate-limit');

// Define rate limit options
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per `window` (here, per 15 minutes)
  message: 'Too many requests from this IP, please try again after 15 minutes',
  headers: true, // Send information about the rate limit status in the response headers
});

module.exports = authLimiter;
