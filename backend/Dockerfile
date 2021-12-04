FROM node:17.2.0-alpine
ENV NODE_ENV=production

# Create app directory
WORKDIR /app

# Install app dependencies
COPY ["package.json", "package-lock.json*", "./"]

RUN npm install --production

# Bundle app source
COPY . .

EXPOSE 8080
CMD ["node", "server.js"]