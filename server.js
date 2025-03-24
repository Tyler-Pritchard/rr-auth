/**
 * Server Configuration and Initialization File
 * 
 * This file is the entry point for the server. It initializes the Express app, sets up middlewares,
 * connects to MongoDB, and defines key application routes. Configuration settings such as Google Cloud
 * credentials and MongoDB URIs are managed through environment variables using the `dotenv` library.
 * 
 * Key Features:
 * - Secure configurations using Helmet and CORS
 * - Rate limiting and security best practices
 * - Detailed logging using Winston with Morgan integration
 * - Environment-specific setups and conditionally enabled features
 * 
 * Author: Tyler Pritchard
 * License: MIT
 */

// Import core libraries and dependencies
const express = require('express'); // Core web server framework for Node.js
const mongoose = require('mongoose'); // MongoDB ODM for database interactions
const dotenv = require('dotenv'); // Load environment variables from a `.env` file
const helmet = require('helmet'); // Security middleware to set HTTP headers
const rateLimit = require('express-rate-limit'); // Middleware to limit repeated requests
const fs = require('fs'); // Node.js file system module
const path = require('path'); // Utility module for working with file paths
const cors = require('cors'); // Middleware for handling Cross-Origin Resource Sharing
const morgan = require('morgan'); // HTTP request logger
const logger = require('./utils/logger'); // Custom logger using Winston

// Import custom route files
const userRoutes = require('./routes/userRoutes');
const authRoutes = require('./routes/authRoutes');
const passwordRoutes = require('./routes/passwordRoutes');
const mockCaptchaRoutes = require('./routes/mockCaptcha');

// Load environment variables from the `.env` file
dotenv.config();

// Initialize the Express app
const app = express();

/**
 * Google Cloud Credentials Setup
 * 
 * If using Google Cloud APIs other than Gmail (e.g., for Storage, Vision), 
 * set up the credentials. For Gmail, only OAuth2 credentials (CLIENT_ID, 
 * CLIENT_SECRET, REFRESH_TOKEN) are needed.
 */
if (process.env.USE_GCLOUD_SERVICE_ACCOUNT === 'true') {
  if (process.env.GOOGLE_APPLICATION_CREDENTIALS_BASE64) {
    const base64Credentials = process.env.GOOGLE_APPLICATION_CREDENTIALS_BASE64;
    const jsonCredentials = Buffer.from(base64Credentials, 'base64').toString('utf8');

    // Write the decoded JSON credentials to a temporary file
    const tempFilePath = path.join(__dirname, 'gcloud-credentials.json');
    fs.writeFileSync(tempFilePath, jsonCredentials);
    logger.info("Google Cloud credentials decoded and saved to file");

    // Set the environment variable to the path of the temporary file
    process.env.GOOGLE_APPLICATION_CREDENTIALS = tempFilePath;
  } else {
    logger.error("ERROR: The GOOGLE_APPLICATION_CREDENTIALS_BASE64 environment variable is not set.");
    process.exit(1);
  }
}

/**
 * CORS Configuration
 * 
 * Define allowed origins based on the environment. Production URLs are restricted,
 * while localhost is used for development and testing.
 */
const allowedOrigins = process.env.NODE_ENV === 'production' ? [
  'https://rrsite-git-main-tylers-projects-06089682.vercel.app',
  'https://rrsite-gephaoaft-tylers-projects-06089682.vercel.app',
  'https://robrich.band',
  'https://www.robrich.band', 
  'https://rrsite.vercel.app',
  'https://rr-auth-production.up.railway.app',
  'https://rr-store-production.up.railway.app', // Add the store service
  'https://cdn.knightlab.com',
  'https://vercel.live',
  'http://localhost:8080',
  'http://localhost:3000'
] : [
  'http://localhost:3000',
  'http://localhost:8080',
  'http://localhost:5000'
];

/**
 * Middleware: Setup CORS with Dynamic Origin Handling
 * 
 * CORS settings are applied to handle cross-origin requests, allowing only specified
 * domains to interact with the server.
 */
// Define allowed HTTP methods and headers explicitly
const allowedMethods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'];
const allowedHeaders = ['Content-Type', 'Authorization'];

app.use(cors({
  origin: function (origin, callback) {
    console.log('NODE_ENV is:', process.env.NODE_ENV);
    logger.info(`Incoming Origin: ${origin || 'undefined'}`);
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      logger.error(`CORS Error: Origin not allowed - ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: allowedMethods,
  allowedHeaders: allowedHeaders,
}));

// app.options('*', (req, res) => {
//   res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
//   res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
//   res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
//   res.header('Access-Control-Allow-Credentials', 'true');
//   res.sendStatus(204); // Respond with no content for OPTIONS
// });
app.options('*', cors()); // Handle preflight requests

/**
 * Middleware: Preflight Request Handler
 * 
 * Custom handler for OPTIONS preflight requests, dynamically setting CORS headers.
 */
app.use((req, res, next) => {
  const origin = req.headers.origin || '*';
  if (allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
  }

  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Credentials', 'true');

  if (req.method === 'OPTIONS') {
    return res.sendStatus(200); // Short-circuit OPTIONS requests
  }
  next();
});

// Trust the first proxy (important for deployment behind load balancers)
app.set('trust proxy', 1);

// Enable Express to parse JSON payloads
app.use(express.json());

/**
 * Middleware: Helmet Security Headers
 * 
 * Use Helmet to set various HTTP headers for securing the application.
 */
// Basic Helmet setup without contentSecurityPolicy
app.use(
  helmet({
    // Disable built-in contentSecurityPolicy to add custom CSP headers manually
    contentSecurityPolicy: false,
  })
);

// Custom CSP middleware to set headers directly
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://www.google.com https://www.gstatic.com https://vercel.live https://vercel.live/_next-live/feedback/; " +
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
    "font-src 'self' https://fonts.gstatic.com; " +
    "frame-src 'self' https://www.google.com https://www.gstatic.com https://cdn.knightlab.com https://vercel.live; " +
    "connect-src 'self' https://rr-store-production.up.railway.app https://rr-auth-production.up.railway.app https://www.robrich.band http://localhost:8080 http://localhost:3000 https://vercel.live https://www.google.com https://www.gstatic.com; " +
    "img-src 'self' data:;"
  );  
  next();
});

/**
 * Rate Limiting Configuration
 * 
 * Limit each IP to 100 requests per 15-minute window to prevent abuse.
 */
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});
app.use(limiter);

// Morgan HTTP request logging integrated with Winston
app.use(morgan('combined', { stream: { write: (message) => logger.info(message.trim()) } }));

/**
 * Global Error Handling for Uncaught Exceptions and Unhandled Rejections
 */
process.on('uncaughtException', (err) => {
  logger.error('Uncaught Exception:', { error: err.message, stack: err.stack });
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', { promise, reason: reason.message || reason, stack: reason.stack || 'No stack trace' });
  process.exit(1);
});

/**
 * Database Connection
 * 
 * Only connect to MongoDB if not in a test environment. Log the connection status.
 */
if (process.env.NODE_ENV !== 'test') {
  mongoose.connect(process.env.MONGO_URI)
    .then(() => logger.info('MongoDB connected'))
    .catch(err => logger.error('MongoDB connection error', { error: err.message }));
}

app.use((req, res, next) => {
  const isFromGateway = req.headers['x-forwarded-for'] ? 'via API Gateway' : 'direct';
  logger.info(`Request ${isFromGateway}: ${req.method} ${req.originalUrl}`);
  next();
});

// Use custom-defined routes
app.use('/api/users', userRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/password', passwordRoutes);
app.use('/api/mock-recaptcha', mockCaptchaRoutes);

// Start the server and listen on the specified port
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => logger.info(`Server running on port ${PORT}`));

// Global healthcheck route to align with other services
app.get('/health', (req, res) => {
  logger.info('Global healthcheck accessed');
  res.json({ status: "UP" });
});

// Export the app for testing
module.exports = app;

