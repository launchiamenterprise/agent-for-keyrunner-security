FROM node:20-alpine
WORKDIR /app
COPY dist/agent.js ./
CMD ["node", "agent.js"]
