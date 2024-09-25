const { RecaptchaEnterpriseServiceClient } = require('@google-cloud/recaptcha-enterprise');

const SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY;
const PROJECT_ID = 'rr-auth-1725047695006';
const recaptchaSiteKey = '6LfU8jIqAAAAAOAFm-eNXmW-uPrxqdH9xJLEfJ7R';

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
    if (!response.tokenProperties || !response.tokenProperties.valid) {
      console.log(`The CreateAssessment call failed: ${response.tokenProperties.invalidReason}`);
      return null;
    }
    return response.riskAnalysis.score || 0;
  } catch (error) {
    console.error('Error during reCAPTCHA verification:', error);
    return null;
  }
}

module.exports = { verifyRecaptchaToken };
