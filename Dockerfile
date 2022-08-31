FROM php:8.1-cli-alpine AS examples
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
WORKDIR /srv/app
COPY . .
WORKDIR /srv/app/examples
RUN composer install
ENV PORT=8000
ENV HOST=http://localhost:$PORT
CMD php -S 0.0.0.0:$PORT -t .
