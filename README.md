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
- Password Reset: Allow users to reset passwords using email tokens.
- Rate Limiting: Protect API routes with rate limiting to prevent abuse.
- Email Service: Send password reset links via email.
- MongoDB: Store user data securely in MongoDB.
- JWT Token Expiration: Supports 'remember me' functionality for longer token expiration.

## Technologies Used
- **Node.js**: JavaScript runtime for building scalable network applications.
- **Express**: Minimalist web framework for Node.js.
- **MongoDB**: NoSQL database for storing user data.
- **Mongoose**: ODM for MongoDB, providing a schema-based solution.
- **bcryptjs**: Library for hashing passwords.
- **JWT**: Standard for securely transmitting information between parties as a JSON object.
- **Google reCAPTCHA**: Service to protect your website from spam and abuse.
- **Nodemailer**: Email handling for sending password reset links.
- **Helmet**: Security middleware for HTTP headers.
- **Express Rate Limit**: Protection from brute-force attacks.
- **Winston**: Logging for application events.

## Installation

### Prerequisites
- [Node.js](https://nodejs.org/) installed on your local machine.
- [MongoDB](https://www.mongodb.com/) Atlas account for cloud-based MongoDB, or a locally running MongoDB instance.
- [Google reCAPTCHA](https://www.google.com/recaptcha/) account.
- Set up an SMTP email service (e.g., Gmail) for sending password reset emails.

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
npx nodemon server.js
```
The server will start on `http://localhost:5000`.

## Configuration

### Environment Variables
In your `.env` file, include the following variables:
```
MONGO_URI=mongodb+srv://your_mongo_uri
RECAPTCHA_SECRET_KEY=your_recaptcha_secret_key
RECAPTCHA_SITE_KEY=your_recaptcha_site_key
JWT_SECRET=your_jwt_secret_key
PORT=5000
EMAIL_USER=your_email_address
EMAIL_PASSWORD=your_email_password
```

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

### User Count
- Endpoint: `/api/users/count`
- Method: `GET`
- Description: Returns the total number of registered users.

## Security
- Password Hashing: Passwords are hashed using bcrypt before being stored.
- JWT Authentication: Token-based authentication is implemented with configurable expiration.
- CAPTCHA Verification: Google reCAPTCHA is used to prevent bot attacks on registration and login routes.
- Rate Limiting: Requests to sensitive endpoints are rate-limited to prevent abuse.

## Testing
This project uses `Jest` for testing. To run the tests:
```
npm test
```

### Test Features
- In-memory MongoDB for isolated testing.
- Unit tests for registration, login, and user count routes.

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
- `/health` for general health
- `/api/auth/health` for service-specific status

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
