FROM node:20-alpine
WORKDIR /app
COPY apps/web/package.json /app/package.json
RUN npm install
COPY apps/web /app
EXPOSE 5173
CMD ["npm", "run", "dev"]
