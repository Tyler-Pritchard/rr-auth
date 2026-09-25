# RR-Auth

RR-Auth is a user authentication and authorization microservice for the Rob Rich website. This service handles user registration, login, password reset, CAPTCHA verification, and token-based authentication using JWT. It leverages Node.js, Express, and MongoDB, ensuring data security with bcrypt for password hashing, rate limiting for brute-force attack protection, and Google reCAPTCHA for bot prevention.

## Table of Contents
- [RR-Auth](#rr-auth)
  - [Table of Contents](#table-of-contents)
  - [Features](#features)
  - [Technologies Used](#technologies-used)
  - [Installation](#installation)
    - [Prerequisites](#prerequisites)
    - [Steps](#steps)
  - [Configuration](#configuration)
    - [Environment Variables](#environment-variables)
  - [API Endpoints](#api-endpoints)
    - [User Registration](#user-registration)
    - [User Login](#user-login)
    - [Forgot Password](#forgot-password)
    - [Reset Password](#reset-password)
    - [User Count](#user-count)
  - [Security](#security)
  - [Testing](#testing)
    - [Test Features](#test-features)
  - [Running with Docker](#running-with-docker)
    - [Docker Setup](#docker-setup)
    - [Building and Running the Container](#building-and-running-the-container)
    - [Stopping and Removing Containers](#stopping-and-removing-containers)
  - [🧩 Kubernetes Deployment](#-kubernetes-deployment)
    - [Kubernetes Prerequisites](#kubernetes-prerequisites)
    - [Kubernetes Setup Steps](#kubernetes-setup-steps)
    - [Health Check Endpoints](#health-check-endpoints)
  - [📊 Observability with Prometheus \& Grafana](#-observability-with-prometheus--grafana)
    - [Prometheus Integration](#prometheus-integration)
    - [Grafana Dashboards](#grafana-dashboards)
  - [Contributing](#contributing)
  - [License](#license)
  - [Contact](#contact)

## Features
- User Registration: Securely register new users with email and password.
- CAPTCHA Verification: Validate users using Google reCAPTCHA.
- Login & JWT Authentication: Authenticate users and generate JWT tokens.
- Password Reset: Single-use, 30-minute reset links. Tokens are random, stored only as SHA-256 hashes, and invalidated on use.
- Rate Limiting: Global limit plus stricter limits on login, registration, and password reset requests.
- Email Service: Transactional email via the Resend HTTPS API.
- MongoDB: Store user data securely in MongoDB.
- JWT Token Expiration: Supports 'remember me' functionality for longer token expiration.

## Technologies Used
- **Node.js 24**: JavaScript runtime (LTS).
- **Express**: Minimalist web framework for Node.js.
- **MongoDB**: NoSQL database for storing user data.
- **Mongoose**: ODM for MongoDB, providing a schema-based solution.
- **bcryptjs**: Library for hashing passwords.
- **JWT**: Standard for securely transmitting information between parties as a JSON object.
- **Google reCAPTCHA**: Service to protect your website from spam and abuse.
- **Resend**: Transactional email API for password reset emails (HTTPS, no SMTP).
- **Helmet**: Security middleware for HTTP headers.
- **Express Rate Limit**: Protection from brute-force attacks.
- **Winston**: Logging for application events.

## Installation

### Prerequisites
- [Node.js 24](https://nodejs.org/) (an `.nvmrc` is included; run `nvm use`).
- [MongoDB](https://www.mongodb.com/) Atlas account for cloud-based MongoDB, or a locally running MongoDB instance.
- [Google reCAPTCHA](https://www.google.com/recaptcha/) account.
- A [Resend](https://resend.com/) account with a verified sending domain (optional for local development; see below).

### Steps
1. Clone the repository:
```
git clone https://github.com/tyler-pritchard/rr-auth.git
cd rr-auth
```
2. Install dependencies:
```
npm install
```
3. Create a `.env` file in the root directory and add your environment variables (see [Configuration](#configuration)).
4. Start the server:
```
npm run dev
```

The server will start on `http://localhost:5000`.

## Configuration

### Environment Variables
In your `.env` file, include the following variables:
```
NODE_ENV=development
PORT=5000
MONGO_URI=mongodb+srv://your_mongo_uri
JWT_SECRET=your_jwt_secret_key
RECAPTCHA_SECRET_KEY=your_recaptcha_secret_key
GOOGLE_APPLICATION_CREDENTIALS_BASE64=base64_encoded_service_account_json
FRONTEND_URL=http://localhost:3000
RESEND_API_KEY=your_resend_api_key
EMAIL_FROM="Your Name <no-reply@mail.yourdomain.com>"
```
In development, if `RESEND_API_KEY` is not set, reset emails are printed to the console instead of sent, so the full reset flow can be tested without an email provider.

## API Endpoints

### User Registration
- Endpoint: `/api/users/register`
- Method: `POST`
- Body Parameters:
```
{
  "firstName": "John",
  "lastName": "Doe",
  "username": "johndoe",
  "email": "john.doe@example.com",
  "password": "securepassword123",
  "dateOfBirth": "1990-01-01",
  "country": "USA",
  "captchaToken": "your_recaptcha_token"
}
```

### User Login
- Endpoint: `/api/auth/login`
- Method: `POST`
- Body Parameters:
```
{
  "email": "john.doe@example.com",
  "password": "securepassword123",
  "captchaToken": "your_recaptcha_token",
  "rememberMe": true
}
```

### Forgot Password
- Endpoint: `/api/password/forgot-password`
- Method: `POST`
- Body Parameters:
```
{
  "email": "john.doe@example.com",
  "captchaToken": "your_recaptcha_token"
}
```
- Response: Always returns the same success message whether or not the account exists, to prevent account enumeration. Limited to 5 requests per 15 minutes per IP.

### Reset Password
- Endpoint: `/api/password/reset-password`
- Method: `POST`
- Body Parameters:
```
{
  "token": "reset_token_from_email",
  "newPassword": "newsecurepassword123"
}
```
- Response: `400` with "This reset link is invalid or has expired" if the token is unknown, expired, or already used.

### User Count
- Endpoint: `/api/users/count`
- Method: `GET`
- Description: Returns the total number of registered users.

## Security
- Password Hashing: Passwords are hashed with bcrypt in a single Mongoose pre-save hook.
- JWT Authentication: Token-based authentication with configurable expiration ("remember me").
- Secure Password Reset: Random 256-bit tokens, stored as SHA-256 hashes, single-use (claimed atomically), and expiring after 30 minutes.
- Account Enumeration Protection: Forgot-password responds identically, and before sending email, regardless of whether the account exists.
- CAPTCHA Verification: reCAPTCHA Enterprise on registration, login, and forgot-password.
- Rate Limiting: 20 requests / 15 min on auth routes, 5 / 15 min on reset requests, plus a global limit.
<!-- - Sensitive Data Handling: Reset tokens and passwords are never logged. -->

## Testing
This project uses `Jest` for testing. To run the tests:
```
npm test
```

### Test Features
- In-memory MongoDB (mongodb-memory-server) for isolated testing.
- Route tests for user registration and user count (being expanded to cover login and password reset).

## Running with Docker

### Docker Setup
Ensure you have [Docker](https://www.docker.com/) installed on your system.

### Building and Running the Container
To build and run the service using Docker:
```
docker-compose up --build -d
```
This will:
- Build the Docker image for `rr-auth`.
- Start the container in detached mode (`-d`).

To verify the service is running:
```
docker ps
```
To check the health status of `rr-auth`:
```
curl http://localhost:5000/api/auth/health
```

### Stopping and Removing Containers
To stop and remove the container:
```
docker-compose down
```
To restart the container:
```
docker-compose up -d
```

## 🧩 Kubernetes Deployment

RR-Auth is fully containerized and deployed via Kubernetes, integrated into a production-grade microservices architecture. The deployment includes secure environment variable management, observability with Prometheus metrics, and resilient pod orchestration.

### Kubernetes Prerequisites
- `minikube` or Kubernetes cluster
- `kubectl` CLI
- `helm` CLI (for observability stack)

### Kubernetes Setup Steps
1. Start Minikube:
```bash
minikube start
minikube addons enable ingress
minikube addons enable metrics-server
```
2. Build and load Docker image locally (if not pulling from Docker Hub):
```bash
eval $(minikube docker-env)
docker build -t tylerpritchard/rr-auth:latest ./rr-auth
```
3. Apply Kubernetes manifests:
```bash
kubectl apply -f rr-auth/rr-auth-deployment.yaml
kubectl apply -f rr-auth/rr-auth-service.yaml
kubectl apply -f rr-auth/rr-auth-config.yaml
kubectl apply -f rr-auth/rr-auth-secret.yaml
kubectl apply -f rr-auth/rr-auth-ingress.yaml
```

4. Verify Deployment:
```bash
kubectl get pods -l app=rr-auth
kubectl get svc -l app=rr-auth
```

### Health Check Endpoints
RR-Auth exposes Kubernetes-ready endpoints:
- `/health` for service health (via the rr-gateway, this is exposed as `/api/auth/health`)

---

## 📊 Observability with Prometheus & Grafana

RR-Auth is instrumented for observability via Prometheus metrics scraping and Grafana dashboards.

### Prometheus Integration
Kubernetes `Deployment` annotations:
```yaml
  annotations:
    prometheus.io/scrape: "true"
    prometheus.io/port: "5000"
    prometheus.io/path: "/api/auth/health"
```

### Grafana Dashboards
1. Install Prometheus & Grafana using Helm:
```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update
helm install prometheus prometheus-community/prometheus --namespace monitoring --create-namespace
helm install grafana prometheus-community/grafana --namespace monitoring
```
2. Port Forward Access:
```bash
kubectl port-forward -n monitoring svc/prometheus-server 9090:80
kubectl port-forward -n monitoring svc/grafana 3000:80
```

Default Grafana credentials:
```
Username: admin
Password: (retrieve with)
kubectl get secret --namespace monitoring grafana -o jsonpath="{.data.admin-password}" | base64 --decode ; echo
```

3. Add Prometheus as a data source in Grafana and configure dashboards using standard Node.js metrics templates.


## Contributing
Contributions are welcome! Please follow the standard Git workflow:
1. Fork the repository.
2. Create a new branch for your feature.
3. Submit a pull request for review.

## License
This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.

## Contact
For any questions or support, please reach out:

[GitHub](https://www.github.com/tyler-pritchard)
[LinkedIn](https://www.linkedin.com/in/tyler-pritchard)
