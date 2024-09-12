const Joi = require('joi');

// User registration validation schema
const registerSchema = Joi.object({
  firstName: Joi.string().min(2).max(30).required(),
  lastName: Joi.string().min(2).max(30).required(),
  username: Joi.string().min(2).max(30).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
  dateOfBirth: Joi.date().required(),
  country: Joi.string().min(2).required(),
  isSubscribed: Joi.boolean().optional(),
  captchaToken: Joi.string().required(),
});

// User login validation schema
const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
  rememberMe: Joi.boolean().optional(),
  captchaToken: Joi.string().required(),
});

// Password reset validation schema
const resetPasswordSchema = Joi.object({
  email: Joi.string().email().required(),
});

// Schema for resetting the password using token
const updatePasswordSchema = Joi.object({
  token: Joi.string().required(),
  newPassword: Joi.string().min(6).required(),
});

module.exports = {
  registerSchema,
  loginSchema,
  resetPasswordSchema,
  updatePasswordSchema
};
