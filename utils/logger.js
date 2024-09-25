// utils/logger.js
const { createLogger, transports, format } = require('winston');

const logger = createLogger({
  level: 'info',  // Default level to log at
  format: format.combine(
    format.timestamp(),
    format.json()
  ),
  transports: [
    new transports.Console(),
    new transports.File({ filename: 'logs/error.log', level: 'error' }),  // Log errors to a file
    new transports.File({ filename: 'logs/combined.log' })  // Log all information to a file
  ]
});

module.exports = logger;
