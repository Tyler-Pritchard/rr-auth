const nodemailer = require('nodemailer');
const { google } = require('googleapis');

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

// Create and export the Nodemailer transporter based on the environment
if (process.env.NODE_ENV === 'development') {
  transporter = nodemailer.createTransport({
    host: "smtp.mailtrap.io",
    port: 2525,
    auth: {
      user: process.env.TEST_EMAIL_USER,
      pass: process.env.TEST_EMAIL_PASS
    },
    jsonTransport: true  // Simulates sending emails without actually sending them
  });
} else {
  transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      type: 'OAuth2',
      user: process.env.EMAIL_USER,
      clientId: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      refreshToken: process.env.REFRESH_TOKEN,
      accessToken: oauth2Client.getAccessToken(),
    }
  });
}

module.exports = transporter;
