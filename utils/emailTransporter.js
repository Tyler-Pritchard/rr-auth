const nodemailer = require('nodemailer');
const { google } = require('googleapis');
const logger = require('./logger');  // Ensure logger is imported to log errors

// OAuth2 client setup
const OAuth2 = google.auth.OAuth2;
const oauth2Client = new OAuth2(
  process.env.CLIENT_ID,
  process.env.CLIENT_SECRET,
  'https://developers.google.com/oauthplayground' // Redirect URL
);

// Set refresh token for OAuth2 client
oauth2Client.setCredentials({
  refresh_token: process.env.REFRESH_TOKEN,
});

let transporter;

// Function to get access token asynchronously
async function createTransporter() {
  if (process.env.NODE_ENV === 'development') {
    // For development (e.g., using Mailtrap)
    return nodemailer.createTransport({
      host: 'smtp.mailtrap.io',
      port: 2525,
      auth: {
        user: process.env.TEST_EMAIL_USER,
        pass: process.env.TEST_EMAIL_PASS,
      },
      jsonTransport: true, // Simulates sending emails without actually sending them
    });
  } else {
    try {
      const accessToken = await oauth2Client.getAccessToken(); // Properly await the token

      return nodemailer.createTransport({
        service: 'gmail',
        auth: {
          type: 'OAuth2',
          user: process.env.EMAIL_USER,
          clientId: process.env.CLIENT_ID,
          clientSecret: process.env.CLIENT_SECRET,
          refreshToken: process.env.REFRESH_TOKEN,
          accessToken: accessToken.token, // Access the token here
        },
      });
    } catch (error) {
      logger.error('Error fetching access token for Gmail OAuth2', { error: error.message });
      throw new Error('Failed to create transporter due to OAuth2 token error');
    }
  }
}

// Export the transporter
module.exports = createTransporter;
