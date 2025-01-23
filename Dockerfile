# Use an official Node.js LTS image
FROM node:20-alpine AS base

# Set working directory
WORKDIR /app

# Create a non-root user before installing dependencies
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Copy package.json and package-lock.json first (leverage Docker cache)
COPY package.json package-lock.json* ./

# Install dependencies
RUN npm ci --omit=dev

# Copy the rest of the app's files
COPY . .

# Set permissions on node_modules for the non-root user
RUN chown -R appuser:appgroup /app/node_modules

# Switch to the non-root user
USER appuser

# Expose port 5000
EXPOSE 5000

# Start the application
CMD ["npm", "start"]
