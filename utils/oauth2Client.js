/**
 * OAuth2 Client Configuration Module
 * 
 * This module sets up and configures the OAuth2 client using the Google APIs library.
 * It is primarily used for managing authorization with Google services, such as sending
 * emails through Gmail using OAuth2 tokens.
 * 
 * The OAuth2 client requires environment variables to securely store sensitive credentials.
 * The `refresh_token` is used to generate a new access token whenever required.
 * 
 * Required Environment Variables:
 * - `CLIENT_ID`: The OAuth2 client ID provided by Google.
 * - `CLIENT_SECRET`: The OAuth2 client secret associated with the client ID.
 * - `REFRESH_TOKEN`: The OAuth2 refresh token used to regenerate access tokens.
 */

const { google } = require('googleapis');  // Import the Google APIs library

// Create an OAuth2 client instance using the credentials provided in environment variables
const OAuth2 = google.auth.OAuth2;  // Destructure OAuth2 from google.auth for cleaner syntax

// Instantiate OAuth2 client with Client ID, Client Secret, and the redirect URL
const oauth2Client = new OAuth2(
  process.env.CLIENT_ID,                          // Client ID for OAuth2 authentication
  process.env.CLIENT_SECRET,                      // Client Secret for OAuth2 authentication
  'https://developers.google.com/oauthplayground' // Redirect URL for OAuth2 Playground testing
);

/**
 * Set up OAuth2 client credentials
 * 
 * The refresh token is used to request new access tokens automatically, avoiding the need for
 * manual reauthorization each time the access token expires. This is particularly useful for
 * long-running services that interact with Google APIs on a regular basis.
 */
oauth2Client.setCredentials({
  refresh_token: process.env.REFRESH_TOKEN  // Use the refresh token stored in environment variables
});

// Export the configured OAuth2 client for use in other modules
module.exports = oauth2Client;
