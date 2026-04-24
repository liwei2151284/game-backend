FROM php:8.2-apache

WORKDIR /var/www/html

RUN apt-get update && apt-get install -y \
    git unzip curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

COPY composer.json composer.lock* ./

ARG JFROG_COMPOSER_REPO
ARG JFROG_USERNAME
ARG JFROG_PASSWORD

RUN composer config -g repo.packagist composer ${JFROG_COMPOSER_REPO} \
    && composer config -g http-basic.${JFROG_COMPOSER_REPO#https://} ${JFROG_USERNAME} ${JFROG_PASSWORD} \
    && composer install --no-dev --prefer-dist --no-interaction --optimize-autoloader

COPY . .
 
EXPOSE 80
