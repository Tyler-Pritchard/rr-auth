const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const morgan = require('morgan');
const logger = require('./utils/logger');

// Import route files
const userRoutes = require('./routes/userRoutes');
const authRoutes = require('./routes/authRoutes');
const passwordRoutes = require('./routes/passwordRoutes');
const mockCaptchaRoutes = require('./routes/mockCaptcha');

dotenv.config();

const app = express();

// Decode Base64 string to JSON
if (process.env.GOOGLE_APPLICATION_CREDENTIALS_BASE64) {
    const base64Credentials = process.env.GOOGLE_APPLICATION_CREDENTIALS_BASE64;
    const jsonCredentials = Buffer.from(base64Credentials, 'base64').toString('utf8');

    // Write JSON to a temporary file
    const tempFilePath = path.join(__dirname, 'gcloud-credentials.json');
    fs.writeFileSync(tempFilePath, jsonCredentials);
    logger.info("Google Cloud credentials decoded and saved to file");

    // Set the environment variable to the path of the temporary file
    process.env.GOOGLE_APPLICATION_CREDENTIALS = tempFilePath;

  } else {
    logger.error("ERROR: The GOOGLE_APPLICATION_CREDENTIALS_BASE64 environment variable is not set.");
    process.exit(1);
}

// Enable CORS for requests from specified origins
const allowedOrigins = process.env.NODE_ENV === 'production' ? [
  'https://rrsite-git-main-tylers-projects-06089682.vercel.app',
  'https://rrsite-gephaoaft-tylers-projects-06089682.vercel.app',
  'https://www.robrich.band'
] : ['http://localhost:3000'];


// Create a stream for Morgan to use Winston
const stream = {
  write: (message) => logger.info(message.trim()),  // Use Winston to log Morgan's output
};

// Morgan for HTTP logging
app.use(morgan('combined')); 

// CORS middleware
app.use(cors({
  origin: function (origin, callback) {
    logger.info(`Incoming Origin: ${origin || 'undefined'}`);  // Log incoming origin for debugging CORS issues

    // Allow requests from Postman or other server-to-server tools that may not have an origin
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);  // If origin is allowed, proceed with the request
    } else {
      logger.error(`CORS Error: Origin not allowed - ${origin}`);
      callback(new Error('Not allowed by CORS'));  // Reject the request if origin is not allowed
    }
  },
  credentials: true,  // Allow credentials (cookies, etc.)
}));

// Middleware to handle preflight requests and set necessary CORS headers
app.use((req, res, next) => {
  const origin = req.headers.origin || '*';
  
  // Set dynamic Access-Control-Allow-Origin based on the environment
  if (allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
  }

  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS'); // Allowed methods
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization'); // Allowed headers
  res.header('Access-Control-Allow-Credentials', 'true'); // Allow credentials (cookies)

  // If the request is a preflight request (OPTIONS), return a 200 status
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  // Pass to next middleware or route handler
  next();
});

// Enable trust proxy
app.set('trust proxy', 1);

app.use(express.json());

app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://www.google.com", "https://www.gstatic.com"],
    },
  })
);

// Rate limiting configuration
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Error Handlers for Uncaught Exceptions and Unhandled Rejections
process.on('uncaughtException', (err) => {
  logger.error('Uncaught Exception:', { error: err.message, stack: err.stack });
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', { promise, reason: reason.message || reason, stack: reason.stack || 'No stack trace' });
  process.exit(1);
});

// Conditionally connect to MongoDB only if not in test environment
if (process.env.NODE_ENV !== 'test') {
  mongoose.connect(process.env.MONGO_URI)
  .then(() => logger.info('MongoDB connected'))
  .catch(err => logger.error('MongoDB connection error', { error: err.message }));
}

// Use route files
app.use('/api/users', userRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/password', passwordRoutes);
app.use('/api/mock-recaptcha', mockCaptchaRoutes);

// Healthcheck route
app.get('/', (req, res) => {
  logger.info('Healthcheck endpoint accessed');
  res.send('API is running...');
});

// App listening
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => logger.info(`Server running on port ${PORT}`));

// Export app for testing
module.exports = app;
