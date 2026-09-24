# Use an official Node.js LTS image
FROM node:24-alpine AS base

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

# Create a writable logs directory for Winston (app runs as non-root)
RUN mkdir -p /app/logs && chown -R appuser:appgroup /app/logs

# Switch to the non-root user
USER appuser

# Expose port 5000
EXPOSE 5000

# Start the application
CMD ["npm", "start"]
