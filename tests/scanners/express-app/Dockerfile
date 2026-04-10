FROM node:20-alpine
WORKDIR /app
RUN npm init -y && npm install express@4
COPY server.js /app/server.js
EXPOSE 3000
CMD ["node", "server.js"]
