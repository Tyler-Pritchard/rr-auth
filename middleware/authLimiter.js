/**
 * Authentication Rate Limiter Middleware
 * This middleware uses the express-rate-limit library to limit the number of requests
 * a client can make to the authentication routes within a specified time window.
 * 
 * Purpose:
 * - Protect against brute-force attacks by restricting repeated requests.
 * - Provide users with a message indicating when rate limits are exceeded.
 * 
 * Configuration:
 * - Limits each IP to 100 requests per 15-minute window.
 * - Returns a specific error message when the rate limit is exceeded.
 * - Includes rate limit information in the response headers.
 */

// Import the rate-limit middleware from express-rate-limit
const rateLimit = require('express-rate-limit');

// Define the rate limit options
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes expressed in milliseconds
  max: 100,                  // Limit each IP to 100 requests per window (per 15 minutes)
  message: 'Too many requests from this IP, please try again after 15 minutes',  // Custom error message when limit is exceeded
  headers: true,             // Include rate limit headers in the response
});

// Export the configured rate limiter for use in authentication routes
module.exports = authLimiter;
