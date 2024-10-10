/**
 * reCAPTCHA Enterprise Verification Module
 * 
 * This module provides functionality to verify reCAPTCHA tokens using Google's reCAPTCHA Enterprise API.
 * It is used to enhance the security of user actions, such as login or registration, by validating
 * the legitimacy of the user based on their reCAPTCHA token and calculating a risk score.
 * 
 * The module relies on environment variables to securely store sensitive information like the
 * reCAPTCHA secret key and project ID.
 * 
 * Required Environment Variables:
 * - `RECAPTCHA_SECRET_KEY`: The secret key for reCAPTCHA Enterprise API.
 * - `PROJECT_ID`: The Google Cloud Project ID where reCAPTCHA Enterprise is set up.
 * 
 * Note: This module uses Google's reCAPTCHA Enterprise client library to communicate with the API.
 */

// Import Google reCAPTCHA Enterprise client library
const { RecaptchaEnterpriseServiceClient } = require('@google-cloud/recaptcha-enterprise');

// Retrieve environment variables and constants for reCAPTCHA configuration
const SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY;  // Secret key for reCAPTCHA Enterprise
const PROJECT_ID = 'rr-auth-1725047695006';           // Google Cloud Project ID for reCAPTCHA Enterprise
const recaptchaSiteKey = '6LfU8jIqAAAAAOAFm-eNXmW-uPrxqdH9xJLEfJ7R';  // Site key associated with the reCAPTCHA

// Import the custom logger for tracking events and errors
const logger = require('./logger');  // Logger utility for structured logging

// Create a new instance of the RecaptchaEnterpriseServiceClient
const recaptchaClient = new RecaptchaEnterpriseServiceClient();

/**
 * Verify reCAPTCHA Token
 * 
 * This asynchronous function accepts a reCAPTCHA token and sends a request to the reCAPTCHA Enterprise
 * API to verify the validity of the token. If successful, it returns the risk score indicating the
 * probability of the interaction being legitimate. A higher score suggests that the request is more
 * likely to be from a human user.
 * 
 * @param {string} token - The reCAPTCHA token to be verified.
 * @returns {number | null} - Returns the risk score (0.0 to 1.0) if valid, otherwise returns `null`.
 */
async function verifyRecaptchaToken(token) {
  // Construct the project path using the client and Project ID
  const projectPath = recaptchaClient.projectPath(PROJECT_ID);

  // Create an assessment request object with the required fields
  const request = {
    assessment: {
      event: {
        token: token,                 // The reCAPTCHA token provided by the client
        siteKey: recaptchaSiteKey,     // The site key associated with the current project
      },
    },
    parent: projectPath,               // Project path used for creating the assessment
  };

  try {
    // Send the assessment request to reCAPTCHA Enterprise and await the response
    const [response] = await recaptchaClient.createAssessment(request);

    // Log token properties and risk score for transparency and debugging
    logger.info('reCAPTCHA response received', {
      tokenProperties: response.tokenProperties,  // Token properties provide validation details
      riskScore: response.riskAnalysis ? response.riskAnalysis.score : 'No score',
    });

    // Check if the token is valid; if not, log the reason and return `null`
    if (!response.tokenProperties || !response.tokenProperties.valid) {
      logger.warn(`reCAPTCHA verification failed: ${response.tokenProperties.invalidReason}`);
      return null;
    }

    // Return the calculated risk score (if present); otherwise, default to 0
    return response.riskAnalysis.score || 0;
  } catch (error) {
    // Handle and log errors during the verification process
    logger.error('Error during reCAPTCHA verification', { error: error.message });
    return null;  // Return `null` on error for consistency
  }
}

// Export the `verifyRecaptchaToken` function for use in other parts of the application
module.exports = { verifyRecaptchaToken };
