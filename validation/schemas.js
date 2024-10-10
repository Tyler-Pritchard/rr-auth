/**
 * Validation Schemas for User Authentication and Management
 * 
 * This module defines various validation schemas using the Joi library to enforce data integrity
 * and prevent malformed requests for key user actions such as registration, login, and password
 * management.
 * 
 * Joi is a popular validation library for Node.js, providing a powerful schema-based approach
 * to validate the structure and content of incoming request data. Each schema defined in this
 * module represents the expected data format and constraints for specific API routes.
 * 
 * Schemas Defined:
 * - `registerSchema`: For validating user registration fields.
 * - `loginSchema`: For validating user login fields.
 * - `resetPasswordSchema`: For validating password reset requests.
 * - `updatePasswordSchema`: For validating password updates using tokens.
 * 
 * This modular approach helps ensure that each request meets the expected structure before
 * being processed, improving security and robustness.
 */

// Import Joi for schema validation
const Joi = require('joi');  // Joi is used to define schemas and validate input data

/**
 * Schema: User Registration
 * 
 * This schema enforces the required structure for registering a new user.
 * It validates fields such as `firstName`, `lastName`, `username`, `email`, `password`, 
 * `dateOfBirth`, `country`, `isSubscribed`, and `captchaToken`.
 */
const registerSchema = Joi.object({
  firstName: Joi.string()
    .min(2)
    .max(30)
    .required()
    .messages({
      'string.base': 'First name should be a string',
      'string.empty': 'First name is required',
      'string.min': 'First name must have at least 2 characters',
      'string.max': 'First name must have at most 30 characters',
    }),

  lastName: Joi.string()
    .min(2)
    .max(30)
    .required()
    .messages({
      'string.base': 'Last name should be a string',
      'string.empty': 'Last name is required',
      'string.min': 'Last name must have at least 2 characters',
      'string.max': 'Last name must have at most 30 characters',
    }),

  username: Joi.string()
    .min(2)
    .max(30)
    .required()
    .messages({
      'string.base': 'Username should be a string',
      'string.empty': 'Username is required',
      'string.min': 'Username must have at least 2 characters',
      'string.max': 'Username must have at most 30 characters',
    }),

  email: Joi.string()
    .email()
    .required()
    .messages({
      'string.email': 'Must be a valid email address',
      'string.empty': 'Email is required',
    }),

  password: Joi.string()
    .min(6)
    .required()
    .messages({
      'string.min': 'Password must be at least 6 characters long',
      'string.empty': 'Password is required',
    }),

  dateOfBirth: Joi.date()
    .required()
    .messages({
      'date.base': 'Date of birth should be a valid date',
      'any.required': 'Date of birth is required',
    }),

  country: Joi.string()
    .min(2)
    .required()
    .messages({
      'string.base': 'Country should be a string',
      'string.empty': 'Country is required',
      'string.min': 'Country name must have at least 2 characters',
    }),

  isSubscribed: Joi.boolean()
    .optional()
    .messages({
      'boolean.base': 'Subscription status should be a boolean value',
    }),

  captchaToken: Joi.string()
    .required()
    .messages({
      'string.base': 'CAPTCHA token should be a string',
      'any.required': 'CAPTCHA token is required',
    }),
});

/**
 * Schema: User Login
 * 
 * This schema enforces the required structure for a user login request.
 * It validates fields such as `email`, `password`, `rememberMe`, and `captchaToken`.
 */
const loginSchema = Joi.object({
  email: Joi.string()
    .email()
    .required()
    .messages({
      'string.email': 'Must be a valid email address',
      'string.empty': 'Email is required',
    }),

  password: Joi.string()
    .min(6)
    .required()
    .messages({
      'string.min': 'Password must be at least 6 characters long',
      'string.empty': 'Password is required',
    }),

  rememberMe: Joi.boolean()
    .optional()
    .messages({
      'boolean.base': 'Remember Me should be a boolean value',
    }),

  captchaToken: Joi.string()
    .required()
    .messages({
      'string.base': 'CAPTCHA token should be a string',
      'any.required': 'CAPTCHA token is required',
    }),
});

/**
 * Schema: Password Reset Request
 * 
 * This schema validates the structure for requesting a password reset link.
 * It only requires a valid `email` field.
 */
const resetPasswordSchema = Joi.object({
  email: Joi.string()
    .email()
    .required()
    .messages({
      'string.email': 'Must be a valid email address',
      'string.empty': 'Email is required',
    }),
});

/**
 * Schema: Password Update Using Token
 * 
 * This schema enforces the structure for resetting a password using a token.
 * It validates fields such as `token` and `newPassword`.
 */
const updatePasswordSchema = Joi.object({
  token: Joi.string()
    .required()
    .messages({
      'string.empty': 'Reset token is required',
    }),

  newPassword: Joi.string()
    .min(6)
    .required()
    .messages({
      'string.min': 'New password must be at least 6 characters long',
      'string.empty': 'New password is required',
    }),
});

// Export all schemas for use in validation throughout the application
module.exports = {
  registerSchema,
  loginSchema,
  resetPasswordSchema,
  updatePasswordSchema,
};
