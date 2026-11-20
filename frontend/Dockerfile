FROM node:22-alpine AS build
WORKDIR /src
COPY package.json package-lock.json ./
COPY admin/package.json admin/
COPY dashboard/package.json dashboard/
COPY shared/package.json shared/
RUN npm ci
COPY . .
RUN npm run build

# nginx z pakietów Alpine zamiast obrazu nginxinc: obraz nginxinc przypina wersję pakietu
# nginx, więc `apk upgrade` nie dociąga poprawek bezpieczeństwa wydanych po jego zbudowaniu.
# Minimalna wersja poniżej sprawia, że build się nie uda, zanim poprawka trafi do Alpine.
FROM alpine:3.24
RUN apk upgrade --no-cache \
    && apk add --no-cache 'nginx>=1.30.7-r0' \
    && rm -f /etc/nginx/http.d/default.conf
COPY nginx.conf /etc/nginx/nginx.conf
COPY site.conf /etc/nginx/sentinel/site.conf
# Dwie aplikacje pod jednym nginx: konsola operacyjna i dashboard menedżera.
COPY --from=build /src/admin/dist /usr/share/nginx/html/admin
COPY --from=build /src/dashboard/dist /usr/share/nginx/html/dashboard
USER nginx
EXPOSE 8080
CMD ["nginx", "-e", "stderr", "-g", "daemon off;"]
