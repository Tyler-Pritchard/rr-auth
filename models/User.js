/**
 * User Model Schema Definition
 * This file defines the Mongoose schema and model for the `User` collection.
 * The schema includes various fields and constraints required for a user account.
 * It also includes pre-save middleware to handle password hashing using bcrypt.
 * 
 * Schema Fields:
 * - firstName: User's first name (String, required).
 * - lastName: User's last name (String, required).
 * - username: Unique username for the user (String, required).
 * - email: Unique email address for the user (String, required).
 * - password: Encrypted password for the user (String, required).
 * - dateOfBirth: Date of birth of the user (Date, required).
 * - country: User's country of residence (String, required).
 * - isSubscribed: Boolean indicating if the user is subscribed to newsletters (default: false).
 * - rememberMe: Boolean indicating if the user opted to stay logged in (default: false).
 * - captchaToken: String token for CAPTCHA verification during registration (conditionally required).
 * - passwordChangedAt: When the password was last changed (Date, optional).
 * - resetPasswordTokenHash: SHA-256 hash of the pending reset token; the raw token is never stored (String, optional).
 * - resetPasswordExpires: Expiry time of the pending reset token (Date, optional).
 */

const mongoose = require('mongoose');  // Import Mongoose for schema creation
const bcrypt = require('bcryptjs');    // Import bcrypt for password hashing

/**
 * Define the User Schema
 * This schema outlines the structure of the `User` collection in MongoDB.
 */
const userSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: true,
    trim: true,           // Trim whitespace
  },
  lastName: {
    type: String,
    required: true,
    trim: true,           // Trim whitespace
  },
  username: {
    type: String,
    required: true,
    unique: true,         // Ensure usernames are unique
    trim: true,           // Trim whitespace
  },
  email: {
    type: String,
    required: true,
    unique: true,         // Ensure emails are unique
    trim: true,           // Trim whitespace
  },
  password: {
    type: String,
    required: true,       // Password is required and will be hashed before saving
  },
  dateOfBirth: {
    type: Date,
    required: true,       // Date of birth is required for all users
  },
  country: {
    type: String,
    required: true,       // Country is required for each user
  },
  isSubscribed: {
    type: Boolean,
    default: false,       // Default value set to `false`
  },
  roles: {
    type: [{
      type: String,
      enum: ['admin', 'tour_manager', 'merch_manager', 'content_manager'],
    }],
    default: [],          // Regular fans have no roles
  },
  rememberMe: {
    type: Boolean,
    default: false,       // Default value set to `false`
  },
  captchaToken: {
    type: String,
    required: function () {
      // `captchaToken` is only required during registration or modification
      return this.isNew || this.isModified('captchaToken');
    },
  },
  passwordChangedAt: {
    type: Date,           // When the password was last changed; used later to reject older login tokens
  },
  resetPasswordTokenHash: {
    type: String,
    select: false,        // Never included in query results unless explicitly requested
    index: true,          // Fast lookup when a reset link is used
    sparse: true,         // Only index users who have a pending reset
  },
  resetPasswordExpires: {
    type: Date,
    select: false,        // Never included in query results unless explicitly requested
  },
});

/**
 * Pre-save Middleware
 * Hash the password before saving the user document if the password field is modified.
 * This ensures the user password is always stored securely in the database.
 */
userSchema.pre('save', async function () {
  if (!this.isModified('password')) {
    return; // Skip hashing if the password has not been modified
  }

  // Generate a salt and hash the password using bcrypt
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);

  // Record when an existing user's password changes (not on registration).
  // Subtract 1 second because JWT issue times are rounded to the second.
  if (!this.isNew) {
    this.passwordChangedAt = new Date(Date.now() - 1000);
  }
});

/**
 * Create and export the User model
 * The `User` model is based on the `userSchema` and will be used for all user-related database operations.
 */
const User = mongoose.model('User', userSchema);

module.exports = User;
