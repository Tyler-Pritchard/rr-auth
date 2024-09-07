const request = require('supertest');
const app = require('../server');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const User = require('../models/User');

describe('GET /api/users/count', () => {
    let mongoServer;
  
    // Set up in-memory MongoDB server for testing
    beforeAll(async () => {
      mongoServer = await MongoMemoryServer.create();
      const uri = mongoServer.getUri();
      await mongoose.connect(uri, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
      });
    });
  
    afterAll(async () => {
      await mongoose.disconnect();
      await mongoServer.stop();
    });
  
    beforeEach(async () => {
      // Clear the users collection before each test
      await User.deleteMany({});
    });
  
    it('should return the total number of registered users', async () => {
      // Insert mock users into the database
      await User.create([
        { firstName: 'John', lastName: 'Doe', username: 'johndoe', email: 'john@example.com', password: 'password123', dateOfBirth: '1990-01-01', country: 'US' },
        { firstName: 'Jane', lastName: 'Smith', username: 'janesmith', email: 'jane@example.com', password: 'password456', dateOfBirth: '1991-02-02', country: 'US' }
      ]);
  
      const response = await request(app).get('/api/users/count');
      expect(response.statusCode).toBe(200);
      expect(response.body.totalUsers).toBe(2); // Expect 2 users in the database
    });
  
    it('should return 0 users if there are no users in the database', async () => {
      const response = await request(app).get('/api/users/count');
      expect(response.statusCode).toBe(200);
      expect(response.body.totalUsers).toBe(0); // Expect 0 users in the database
    });
});

// Spy on the verifyRecaptchaToken function and mock its implementation
jest.spyOn(require('../routes/userRoutes'), 'verifyRecaptchaToken').mockResolvedValue(0.9); // Mock valid CAPTCHA response

describe('User Registration Route', () => {
  let mongoServer;

  // Set up in-memory MongoDB server for testing
  beforeAll(async () => {
    mongoServer = await MongoMemoryServer.create();
    const uri = mongoServer.getUri();
    await mongoose.connect(uri, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
  });

  afterAll(async () => {
    await mongoose.disconnect();
    await mongoServer.stop();
  });

  it('should return 201 status on successful registration', async () => {
    const response = await request(app)
      .post('/api/users/register')
      .send({
        firstName: 'John',
        lastName: 'Doe',
        username: 'johndoe',
        email: 'john@example.com',
        password: 'password123',
        dateOfBirth: '1990-01-01',
        country: 'US',
        captchaToken: 'valid-captcha-token',
      });
    expect(response.statusCode).toBe(201);
    expect(response.body.msg).toBe('User registered successfully');
  });
});
