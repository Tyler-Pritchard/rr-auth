/**
 * Email Transporter Configuration Module
 * 
 * This module configures and exports a Nodemailer transporter based on the environment.
 * For development, it uses Mailtrap to simulate sending emails.
 * For production, it uses Gmail with OAuth2 credentials for secure email sending.
 * 
 * The transporter is created dynamically based on the environment variables.
 */

const nodemailer = require('nodemailer');   // Import Nodemailer for email transport
const { google } = require('googleapis');   // Import Google APIs for OAuth2 client
const logger = require('./logger');         // Import logger for error and info logging

// Set up the OAuth2 client for Gmail API authentication
const OAuth2 = google.auth.OAuth2;  // Google OAuth2 client class
const oauth2Client = new OAuth2(
  process.env.CLIENT_ID,         // Client ID from environment variables
  process.env.CLIENT_SECRET,     // Client Secret from environment variables
  'https://developers.google.com/oauthplayground' // Redirect URL for OAuth2 playground
);

// Set the refresh token for the OAuth2 client
oauth2Client.setCredentials({
  refresh_token: process.env.REFRESH_TOKEN, // Refresh token to obtain new access tokens
});

// Transporter instance (reusable) to be configured based on environment
let transporter;

/**
 * Create and return a Nodemailer transporter
 * This function dynamically creates a transporter based on the current environment:
 * - In development: Uses Mailtrap to simulate email sending.
 * - In production: Uses Gmail with OAuth2 for real email sending.
 * 
 * @returns {Promise<Transporter>} Configured Nodemailer transporter object.
 * @throws {Error} If the OAuth2 token retrieval fails.
 */
async function createTransporter() {
  if (process.env.NODE_ENV === 'development') {
    // For development, configure Mailtrap as the transport service.
    return nodemailer.createTransport({
      host: 'smtp.mailtrap.io',         // Mailtrap SMTP host
      port: 2525,                       // Port for Mailtrap
      auth: {
        user: process.env.TEST_EMAIL_USER, // Mailtrap user from environment variables
        pass: process.env.TEST_EMAIL_PASS, // Mailtrap password from environment variables
      },
      jsonTransport: true,  // Simulates sending emails without actually sending them
    });
  } else {
    // For production, configure Gmail with OAuth2 authentication
    try {
      const accessToken = await oauth2Client.getAccessToken(); // Retrieve the access token using OAuth2

      // Return a Nodemailer transporter using the Gmail service and OAuth2 credentials
      return nodemailer.createTransport({
        service: 'gmail',
        auth: {
          type: 'OAuth2',
          user: process.env.EMAIL_USER,        // Gmail email address to use as the sender
          clientId: process.env.CLIENT_ID,     // OAuth2 Client ID
          clientSecret: process.env.CLIENT_SECRET, // OAuth2 Client Secret
          refreshToken: process.env.REFRESH_TOKEN, // OAuth2 Refresh Token
          accessToken: accessToken.token,      // The newly retrieved access token
        },
      });
    } catch (error) {
      // Log and throw an error if access token retrieval fails
      logger.error('Error fetching access token for Gmail OAuth2', { error: error.message });
      throw new Error('Failed to create transporter due to OAuth2 token error');
    }
  }
}

// Export the `createTransporter` function as the module's default export
module.exports = createTransporter;
