/**
 * Bcrypt Utility Module
 * This module provides utility functions to handle password hashing and comparison using the bcrypt library.
 * It includes logging for transparency and debugging during development and production.
 */

// Import required modules
const bcrypt = require('bcryptjs');
const logger = require('./logger');  // Custom Winston logger for logging activities

/**
 * @function hashPassword
 * @desc    Hashes a plain text password using bcrypt's hashing algorithm.
 * @param   {string} password - The plain text password to be hashed.
 * @returns {Promise<string>}  - Returns the hashed password.
 * @throws  Will throw an error if password hashing fails.
 */
async function hashPassword(password) {
  try {
    logger.info('Hashing password');  // Log when hashing process begins
    const salt = await bcrypt.genSalt(10);  // Generate salt with 10 rounds
    const hashedPassword = await bcrypt.hash(password, salt);  // Hash the password with the generated salt
    logger.info('Password successfully hashed');  // Log successful hashing
    return hashedPassword;
  } catch (error) {
    // Log error details and propagate the error up the chain
    logger.error('Error while hashing password', { error: error.message });
    throw error;
  }
}

/**
 * @function comparePassword
 * @desc    Compares a plain text password with a hashed password to check for a match.
 * @param   {string} plainPassword - The plain text password input by the user.
 * @param   {string} hashedPassword - The stored hashed password for comparison.
 * @returns {Promise<boolean>} - Returns true if passwords match, otherwise false.
 * @throws  Will throw an error if password comparison fails.
 */
async function comparePassword(plainPassword, hashedPassword) {
  try {
    logger.info('Comparing passwords');  // Log when password comparison starts
    const isMatch = await bcrypt.compare(plainPassword, hashedPassword);  // Compare the plain password with the hashed version
    logger.info('Password comparison completed', { isMatch });  // Log the comparison result
    return isMatch;
  } catch (error) {
    // Log error details and propagate the error up the chain
    logger.error('Error while comparing passwords', { error: error.message });
    throw error;
  }
}

// Export the utility functions for use in other modules
module.exports = {
  hashPassword,
  comparePassword,
};
