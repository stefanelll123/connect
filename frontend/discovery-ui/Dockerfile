FROM node:20-alpine AS builder
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .

ARG VITE_API_BASE_URL=http://localhost:8201/api/v1
ARG VITE_OIDC_AUTHORITY=http://localhost:8001/realms/discovery
ARG VITE_OIDC_CLIENT_ID=discovery-ui

ENV VITE_API_BASE_URL=$VITE_API_BASE_URL
ENV VITE_OIDC_AUTHORITY=$VITE_OIDC_AUTHORITY
ENV VITE_OIDC_CLIENT_ID=$VITE_OIDC_CLIENT_ID

RUN npx vite build

# ---- serve stage ----
FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
