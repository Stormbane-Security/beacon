FROM node:20-alpine

# Install web3.js for contract deployment
WORKDIR /app
RUN npm init -y && npm install web3@4

COPY deploy.js /app/deploy.js

# The deploy script runs after ganache is ready
CMD ["node", "deploy.js"]
