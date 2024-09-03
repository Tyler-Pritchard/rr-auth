const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');  // Add this line to import the cors module

// Routes
const userRoutes = require('./routes/userRoutes');

dotenv.config();

// check for google credentials in .env
if (!process.env.GOOGLE_APPLICATION_CREDENTIALS) {
  console.error("ERROR: The GOOGLE_APPLICATION_CREDENTIALS environment variable is not set.");
  process.exit(1);
}


const app = express();

// Enable trust proxy
app.set('trust proxy', 1);

// Enable CORS for requests from http://localhost:3000
app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true, // Include this option if your frontend needs to send cookies or other credentials
}));

app.use(express.json());
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://www.google.com", "https://www.gstatic.com"],
      // other directives...
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
