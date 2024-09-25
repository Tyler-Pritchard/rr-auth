const { RecaptchaEnterpriseServiceClient } = require('@google-cloud/recaptcha-enterprise');
const SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY;
const PROJECT_ID = 'rr-auth-1725047695006';
const recaptchaSiteKey = '6LfU8jIqAAAAAOAFm-eNXmW-uPrxqdH9xJLEfJ7R';
const logger = require('./logger'); 

const recaptchaClient = new RecaptchaEnterpriseServiceClient();

async function verifyRecaptchaToken(token) {
  const projectPath = recaptchaClient.projectPath(PROJECT_ID);
  const request = {
    assessment: {
      event: {
        token: token,
        siteKey: recaptchaSiteKey,
      },
    },
    parent: projectPath,
  };

  try {
    const [response] = await recaptchaClient.createAssessment(request);

    // Log the tokenProperties and risk score for debugging
    logger.info('reCAPTCHA response received', {
      tokenProperties: response.tokenProperties,
      riskScore: response.riskAnalysis ? response.riskAnalysis.score : 'No score',
    });

    if (!response.tokenProperties || !response.tokenProperties.valid) {
      logger.warn(`reCAPTCHA verification failed: ${response.tokenProperties.invalidReason}`);
      return null;
    }

    // Return the risk score (if available), otherwise default to 0
    return response.riskAnalysis.score || 0;
  } catch (error) {
    logger.error('Error during reCAPTCHA verification', { error: error.message });
    return null;
  }
}

module.exports = { verifyRecaptchaToken };
