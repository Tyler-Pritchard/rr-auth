// utils/bcrypt.js
const bcrypt = require('bcryptjs');
const logger = require('./logger');  // Import Winston logger

// Function to hash a password
async function hashPassword(password) {
  try {
    logger.info('Hashing password');  // Log when hashing starts
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    logger.info('Password successfully hashed');  // Log when hashing completes
    return hashedPassword;
  } catch (error) {
    logger.error('Error while hashing password', { error: error.message });
    throw error;  // Rethrow the error to ensure it propagates up the call chain
  }
}

// Function to compare a plain password with a hashed one
async function comparePassword(plainPassword, hashedPassword) {
  try {
    logger.info('Comparing passwords');  // Log when password comparison starts
    const isMatch = await bcrypt.compare(plainPassword, hashedPassword);
    logger.info('Password comparison completed', { isMatch });  // Log whether passwords matched
    return isMatch;
  } catch (error) {
    logger.error('Error while comparing passwords', { error: error.message });
    throw error;  // Rethrow the error to ensure it propagates up the call chain
  }
}

module.exports = {
  hashPassword,
  comparePassword,
};
