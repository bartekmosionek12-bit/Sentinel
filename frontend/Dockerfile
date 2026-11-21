FROM node:22-alpine AS build
WORKDIR /src
COPY package.json package-lock.json ./
COPY admin/package.json admin/
COPY shared/package.json shared/
RUN --mount=type=secret,id=proxy_ca,required=false \
    if [ -f /run/secrets/proxy_ca ]; then \
      cp /run/secrets/proxy_ca /tmp/proxy-ca.crt; \
      NODE_EXTRA_CA_CERTS=/tmp/proxy-ca.crt npm ci; \
      rm /tmp/proxy-ca.crt; \
    else \
      npm ci; \
    fi
COPY . .
RUN npm run build

# Aktualny obraz mainline nginx; brak zależności od repozytorium APK podczas buildu.
FROM nginx:mainline-alpine
RUN rm -f /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/nginx.conf
COPY site.conf /etc/nginx/sentinel/site.conf
# Jedna aplikacja: konsola zespołu IT (/admin/).
COPY --from=build /src/admin/dist /usr/share/nginx/html/admin
COPY --from=build /src/dashboard/dist /usr/share/nginx/html/dashboard
RUN chmod a+r /etc/nginx/nginx.conf /etc/nginx/sentinel/site.conf \
    && chmod -R a+rX /usr/share/nginx/html
USER nginx
EXPOSE 8080
CMD ["nginx", "-e", "stderr", "-g", "daemon off;"]
