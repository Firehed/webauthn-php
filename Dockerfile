FROM php:8.1-cli-alpine
WORKDIR /srv/app
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
COPY composer.json .
RUN composer install
COPY . .
ENV PORT=8000
ENV HOST=http://localhost:$PORT
CMD php -S 0.0.0.0:$PORT -t examples
