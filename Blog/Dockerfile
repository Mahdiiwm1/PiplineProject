# First stage to Test
FROM node:20-alpine as test
WORKDIR /usr/src/app
COPY ["package.json", "package-lock.json*", "npm-shrinkwrap.json*", "./"]
RUN apk add python3 py3-pip build-base
RUN npm install
COPY . . 
RUN npm test

# Second stage for Production
FROM node:20-alpine
ENV NODE_ENV=production
WORKDIR /usr/src/app
COPY ["package.json", "package-lock.json*", "npm-shrinkwrap.json*", "./"]
RUN apk add python3 py3-pip build-base
RUN npm install --omit=dev && mv node_modules ../
COPY . .
EXPOSE 3000
RUN chown -R node /usr/src/app
USER node
CMD ["npm", "start"]
