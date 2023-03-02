FROM node:18-alpine

RUN npm install -g npm@latest && npm i -g @nestjs/cli

WORKDIR /backend

COPY . .


# api_serverコンテナの入り方
# docker exec -it backend sh