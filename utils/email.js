/**
 * Email Module (Resend HTTPS API)
 *
 * Sends transactional email through Resend's REST API using Node's built-in fetch.
 * HTTPS is used instead of SMTP because Railway blocks outbound SMTP on non-Pro plans.
 *
 * Required environment variables (production):
 * - RESEND_API_KEY: API key with sending access for the verified domain
 * - EMAIL_FROM:     Sender, e.g. "Rob Rich <no-reply@mail.robrich.band>"
 *
 * In development, if RESEND_API_KEY is unset, emails are printed to the console
 * instead of sent, so the reset flow can be tested locally without a provider.
 */

const logger = require('./logger');

const RESEND_URL = 'https://api.resend.com/emails';

/**
 * Send an email.
 * @param {{ to: string, subject: string, text: string, html: string }} message
 * @returns {Promise<{ id: string }>} Resend message ID
 */
async function sendEmail({ to, subject, text, html }) {
  const apiKey = process.env.RESEND_API_KEY;
  const from = process.env.EMAIL_FROM;

  if (!apiKey) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('RESEND_API_KEY is not set');
    }
    // Dev fallback: print instead of sending (console only, never written to log files)
    logger.warn('RESEND_API_KEY not set; printing email to console instead of sending');
    console.log(`\n----- DEV EMAIL -----\nTo: ${to}\nSubject: ${subject}\n\n${text}\n---------------------\n`);
    return { id: 'dev-console' };
  }

  if (!from) {
    throw new Error('EMAIL_FROM is not set');
  }

  const response = await fetch(RESEND_URL, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ from, to: [to], subject, text, html }),
    signal: AbortSignal.timeout(10_000), // don't hang if Resend is slow
  });

  const body = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(`Resend API error ${response.status}: ${body.message || 'unknown error'}`);
  }

  return body;
}

/** Escape user-controlled text before inserting it into HTML. */
function escapeHtml(value = '') {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Build the password reset email content.
 * @param {{ firstName?: string, resetURL: string, expiresInMinutes: number }} params
 */
function buildPasswordResetEmail({ firstName, resetURL, expiresInMinutes }) {
  const greeting = firstName ? `Hi ${firstName},` : 'Hi,';

  const text = [
    greeting,
    '',
    'We received a request to reset the password for your Rob Rich account.',
    `Use this link to choose a new password (valid for ${expiresInMinutes} minutes):`,
    '',
    resetURL,
    '',
    "If you didn't request this, you can ignore this email. Your password won't change.",
  ].join('\n');

  const html = `
    <p>${escapeHtml(greeting)}</p>
    <p>We received a request to reset the password for your Rob Rich account.</p>
    <p><a href="${resetURL}">Reset your password</a></p>
    <p>This link is valid for ${expiresInMinutes} minutes and can only be used once.</p>
    <p>If you didn't request this, you can ignore this email. Your password won't change.</p>
  `;

  return { subject: 'Reset your Rob Rich password', text, html };
}

module.exports = { sendEmail, buildPasswordResetEmail };
