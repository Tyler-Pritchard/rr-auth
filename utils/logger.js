/**
 * Logger Configuration Module
 * 
 * This module sets up a Winston logger for centralized logging across the application.
 * It configures the logger to log messages at different levels to the console and files.
 * 
 * Winston is a popular logging library in Node.js that supports multiple transports.
 * This module is useful for tracking and storing logs for debugging and monitoring.
 */

const { createLogger, transports, format } = require('winston');  // Import necessary Winston components

/**
 * Configure the Winston logger instance
 * 
 * The logger is configured with different transports for output:
 * 1. Console Transport: Logs to the console.
 * 2. File Transport (Error Log): Logs only error-level messages to `logs/error.log`.
 * 3. File Transport (Combined Log): Logs all messages to `logs/combined.log`.
 * 
 * The logging format includes timestamps and outputs messages in JSON format.
 */
const logger = createLogger({
  level: 'info',  // Set the default log level to 'info'
  format: format.combine(
    format.timestamp(),  // Add a timestamp to each log message
    format.json()        // Format log messages as JSON
  ),
  transports: [
    // Output logs to the console for immediate visibility during development
    new transports.Console(),

    // Write only error-level messages to a dedicated error log file
    new transports.File({ filename: 'logs/error.log', level: 'error' }),

    // Write all log messages to a combined log file for comprehensive tracking
    new transports.File({ filename: 'logs/combined.log' })
  ]
});

// Export the configured Winston logger instance for use in other modules
module.exports = logger;
