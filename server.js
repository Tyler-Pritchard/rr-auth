const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');
const cors = require('cors');

// This line ensures that preflight OPTIONS requests are handled correctly
app.options('*', cors());

// Routes
const userRoutes = require('./routes/userRoutes');

dotenv.config();

// Decode Base64 string to JSON
if (process.env.GOOGLE_APPLICATION_CREDENTIALS_BASE64) {
  const base64Credentials = process.env.GOOGLE_APPLICATION_CREDENTIALS_BASE64;
  const jsonCredentials = Buffer.from(base64Credentials, 'base64').toString('utf8');

  // Write JSON to a temporary file
  const tempFilePath = path.join(__dirname, 'gcloud-credentials.json');
  fs.writeFileSync(tempFilePath, jsonCredentials);

  // Set the environment variable to the path of the temporary file
  process.env.GOOGLE_APPLICATION_CREDENTIALS = tempFilePath;
} else {
  console.error("ERROR: The GOOGLE_APPLICATION_CREDENTIALS_BASE64 environment variable is not set.");
  process.exit(1);
}

const app = express();

// Enable CORS for requests from specified origins
// const allowedOrigins = ['http://localhost:3000'];  // dev
const allowedOrigins = [ 'https://rrsite-git-main-tylers-projects-06089682.vercel.app', 'https://rrsite-gephaoaft-tylers-projects-06089682.vercel.app', 'https://www.robrich.band'];  // prod

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (e.g., Postman, server-to-server requests) or allowed origins
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true, // Allow credentials if needed
}));

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

app.use('/api/users', userRoutes);

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log(err));

// Define routes
app.get('/', (req, res) => {
  res.send('API is running...');
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
